// Glue between the GUI preview pane and the ported website viewers:
// picks the viewer for a file, builds the toolbar, and keeps viewer settings.
import { parsePmg, pmgParts } from "./pmg";
import { createModelViewer, type ModelViewer } from "./modelViewer";
import { cachedTexture } from "./dds";
import { parseGm, gmToGeometry, renderGm } from "./navmesh";
import { parseEffectXml, renderEffect } from "./effect";
import { attachItemPanel } from "./itemPanel";
import type { AssetEntry, AssetHost } from "./worldData";

export interface Preview3dSettings {
    autoRotate: boolean;
    highQuality: boolean;
    loadTextures: boolean;
    accurateDds: boolean;
    wireframe: boolean;
}

const SETTINGS_KEY = "preview3d-settings";
const DEFAULTS: Preview3dSettings = { autoRotate: true, highQuality: true, loadTextures: true, accurateDds: false, wireframe: false };

export function loadSettings(): Preview3dSettings {
    try {
        return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}") };
    } catch {
        return { ...DEFAULTS };
    }
}

function saveSettings(s: Preview3dSettings) {
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(s)); } catch { /* storage unavailable */ }
}

export interface Mounted3d {
    summary: string;
    resize(): void;
    dispose(): void;
}

/** Locale lookup supplied by the app: key plus `{0}`-style positional args. */
type Translate = (key: string, args?: string[]) => string;

/** Picks the singular key for a count of 1, the plural key otherwise. */
function countLabel(t: Translate, n: number, one: string, other: string): string {
    return t(n === 1 ? one : other, [n.toLocaleString()]);
}

export interface ModelHost {
    container: HTMLElement;
    t: Translate;
    /** Element the toolbar is placed in (absolutely positioned over the viewport). */
    overlay: HTMLElement;
    name: string;
    bytes: Uint8Array;
    accent: number;
    background: number;
    /** Returns the DDS bytes for a texture name, or null when it isn't found. */
    textureBytes(name: string): Promise<Uint8Array | null>;
    /** Cache key scope for textures (e.g. the archive path). */
    textureScope: string;
    save(defaultName: string, data: Uint8Array | string): Promise<void>;
    status(text: string): void;
    /** Open archives, for the itemdb lookup/search box (omitted for loose files). */
    assets?: AssetHost;
    /** Archive entry the model came from. */
    entry?: AssetEntry;
}

function button(label: string, title: string, onClick: () => void): HTMLButtonElement {
    const b = document.createElement("button");
    b.className = "tab-btn";
    b.textContent = label;
    b.title = title;
    b.style.cssText = "flex:0;padding:2px 8px;font-size:0.75em;white-space:nowrap;pointer-events:auto";
    b.addEventListener("click", onClick);
    return b;
}

function toggle(label: string, title: string, on: boolean, onChange: (v: boolean) => void): HTMLButtonElement {
    const b = button(label, title, () => {
        on = !on;
        b.classList.toggle("active", on);
        onChange(on);
    });
    b.classList.toggle("active", on);
    return b;
}

export function mountPmg(host: ModelHost): Mounted3d {
    const file = parsePmg(host.bytes);
    const parts = pmgParts(file);
    const t = host.t;
    if (!parts.length) throw new Error(t("p3d_err_no_submeshes"));
    const verts = parts.reduce((n, p) => n + p.vertexCount, 0);
    const faces = parts.reduce((n, p) => n + p.faceCount, 0);
    const summary = `v${file.version.join(".")} · ${countLabel(t, parts.length, "p3d_material_one", "p3d_material_other")} · ${t("p3d_verts_faces", [verts.toLocaleString(), faces.toLocaleString()])}`;
    const settings = loadSettings();
    const textured = parts.filter(p => p.textureName && !/^_+$/.test(p.textureName)).length;

    let viewer: ModelViewer;
    const build = () => {
        viewer = createModelViewer(host.container, parts, {
            accent: host.accent,
            background: host.background,
            autoRotate: settings.autoRotate,
            antialias: settings.highQuality,
            pixelRatio: settings.highQuality ? 2 : 1,
            loadTextures: settings.loadTextures,
            accurateDds: settings.accurateDds,
            resolveTexture: name => cachedTexture(`${host.textureScope}|${name.toLowerCase()}`, settings.accurateDds, () => host.textureBytes(name)),
            onTextureProgress: (loaded, failed, total) => host.status(
                loaded + failed < total
                    ? `${summary} · ${t("p3d_textures_progress", [String(loaded), String(total)])}…`
                    : `${summary} · ${t("p3d_textures_progress", [String(loaded), String(total)])}${failed ? ` ${t("p3d_textures_not_found", [String(failed)])}` : ""}`),
        });
        if (settings.wireframe) viewer.setWireframe(true);
        host.status(settings.loadTextures && textured ? `${summary} · ${t("p3d_loading_textures")}` : summary);
    };
    build();
    const rebuild = () => { viewer.dispose(); build(); };
    const update = (patch: Partial<Preview3dSettings>) => { Object.assign(settings, patch); saveSettings(settings); };

    const base = host.name.replace(/\.pmg$/i, "");
    const exporting = (kind: string, run: () => Promise<void>) => {
        run().catch(err => host.status(`${summary} · ${t("p3d_export_failed", [kind, String(err)])}`));
    };
    const bar = document.createElement("div");
    // Top-right over the viewport; #pmg-info sits bottom-left so the two never overlap (styles.css).
    bar.className = "p3d-toolbar";
    bar.append(
        toggle(t("p3d_btn_rotate"), t("p3d_tip_rotate"), settings.autoRotate, v => { update({ autoRotate: v }); viewer.setAutoRotate(v); }),
        toggle(t("p3d_btn_wire"), t("p3d_tip_wire"), settings.wireframe, v => { update({ wireframe: v }); viewer.setWireframe(v); }),
        toggle(t("p3d_btn_textures"), t("p3d_tip_textures"), settings.loadTextures, v => { update({ loadTextures: v }); rebuild(); }),
        toggle(t("p3d_btn_accurate_dds"), t("p3d_tip_accurate_dds"), settings.accurateDds, v => { update({ accurateDds: v }); rebuild(); }),
        toggle(t("p3d_btn_hq"), t("p3d_tip_hq"), settings.highQuality, v => { update({ highQuality: v }); rebuild(); }),
        button(t("p3d_btn_reset"), t("p3d_tip_reset"), () => viewer.reset()),
        button("GLB", t("p3d_tip_glb"), () => exporting("GLB", async () => host.save(`${base}.glb`, new Uint8Array(await viewer.exportGlb())))),
        button("OBJ", t("p3d_tip_obj"), () => exporting("OBJ", async () => host.save(`${base}.obj`, viewer.exportObj()))),
        button("PNG", t("p3d_tip_png"), () => exporting("PNG", async () => host.save(`${base}_render.png`, await viewer.exportPng()))),
    );
    host.overlay.appendChild(bar);
    const items = host.assets
        ? attachItemPanel({ parent: host.overlay, host: host.assets, t, model: host.name, near: host.entry, floating: true })
        : null;

    return {
        summary,
        resize: () => viewer.resize(),
        dispose: () => { viewer.dispose(); bar.remove(); items?.dispose(); },
    };
}

export function mountGm(host: { container: HTMLElement; bytes: Uint8Array; t: Translate }): Mounted3d {
    const t = host.t;
    const geo = gmToGeometry(parseGm(host.bytes));
    if (!geo.faceCount) throw new Error(t("p3d_err_no_navmesh"));
    const v = renderGm(geo, host.container);
    return { summary: `${t("p3d_navmesh")} · ${t("p3d_verts_faces", [geo.vertexCount.toLocaleString(), geo.faceCount.toLocaleString()])}`, ...v };
}

export function mountEffect(host: { container: HTMLElement; xml: string; t: Translate }): Mounted3d {
    const t = host.t;
    const eff = parseEffectXml(host.xml);
    const count = eff.effectGroups.reduce((n, g) => n + g.effects.length, 0);
    if (!count) throw new Error(t("p3d_err_no_effects"));
    const v = renderEffect(eff, host.container);
    const groups = countLabel(t, eff.effectGroups.length, "p3d_group_one", "p3d_group_other");
    const effects = countLabel(t, count, "p3d_effect_one", "p3d_effect_other");
    return { summary: `${t("p3d_effect")} · ${groups} · ${effects}`, ...v };
}
