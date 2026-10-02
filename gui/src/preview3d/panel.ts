// Glue between the GUI preview pane and the ported website viewers:
// picks the viewer for a file, builds the toolbar, and keeps viewer settings.
import { parsePmg, pmgParts } from "./pmg";
import { createModelViewer, type ModelViewer } from "./modelViewer";
import { cachedTexture } from "./dds";
import { parseGm, gmToGeometry, renderGm } from "./navmesh";
import { parseEffectXml, renderEffect } from "./effect";

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

export interface ModelHost {
    container: HTMLElement;
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
    if (!parts.length) throw new Error("no renderable submeshes");
    const verts = parts.reduce((n, p) => n + p.vertexCount, 0);
    const faces = parts.reduce((n, p) => n + p.faceCount, 0);
    const summary = `v${file.version.join(".")} · ${parts.length} material${parts.length === 1 ? "" : "s"} · ${verts.toLocaleString()} verts · ${faces.toLocaleString()} faces`;
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
                    ? `${summary} · textures ${loaded}/${total}…`
                    : `${summary} · textures ${loaded}/${total}${failed ? ` (${failed} not found)` : ""}`),
        });
        if (settings.wireframe) viewer.setWireframe(true);
        host.status(settings.loadTextures && textured ? `${summary} · loading textures…` : summary);
    };
    build();
    const rebuild = () => { viewer.dispose(); build(); };
    const update = (patch: Partial<Preview3dSettings>) => { Object.assign(settings, patch); saveSettings(settings); };

    const base = host.name.replace(/\.pmg$/i, "");
    const exporting = (kind: string, run: () => Promise<void>) => {
        run().catch(err => host.status(`${summary} · ${kind} export failed: ${err}`));
    };
    const bar = document.createElement("div");
    bar.style.cssText = "position:absolute;top:4px;right:6px;display:flex;flex-wrap:wrap;gap:4px;justify-content:flex-end;max-width:70%;pointer-events:none";
    bar.append(
        toggle("Rotate", "Auto-rotate the model", settings.autoRotate, v => { update({ autoRotate: v }); viewer.setAutoRotate(v); }),
        toggle("Wire", "Wireframe", settings.wireframe, v => { update({ wireframe: v }); viewer.setWireframe(v); }),
        toggle("Textures", "Load DDS textures from the loaded archives", settings.loadTextures, v => { update({ loadTextures: v }); rebuild(); }),
        toggle("Accurate DDS", "Rounded DXT decoding plus alpha cut-outs", settings.accurateDds, v => { update({ accurateDds: v }); rebuild(); }),
        toggle("HQ", "Antialiasing and full pixel ratio", settings.highQuality, v => { update({ highQuality: v }); rebuild(); }),
        button("Reset", "Reset the camera (or double-click the view)", () => viewer.reset()),
        button("GLB", "Export the textured model as glTF binary", () => exporting("GLB", async () => host.save(`${base}.glb`, new Uint8Array(await viewer.exportGlb())))),
        button("OBJ", "Export geometry as Wavefront OBJ", () => exporting("OBJ", async () => host.save(`${base}.obj`, viewer.exportObj()))),
        button("PNG", "Save the current view as an image", () => exporting("PNG", async () => host.save(`${base}_render.png`, await viewer.exportPng()))),
    );
    host.overlay.appendChild(bar);

    return {
        summary,
        resize: () => viewer.resize(),
        dispose: () => { viewer.dispose(); bar.remove(); },
    };
}

export function mountGm(host: { container: HTMLElement; bytes: Uint8Array }): Mounted3d {
    const geo = gmToGeometry(parseGm(host.bytes));
    if (!geo.faceCount) throw new Error("no navmesh triangles");
    const v = renderGm(geo, host.container);
    return { summary: `NavMesh · ${geo.vertexCount.toLocaleString()} verts · ${geo.faceCount.toLocaleString()} faces`, ...v };
}

export function mountEffect(host: { container: HTMLElement; xml: string }): Mounted3d {
    const eff = parseEffectXml(host.xml);
    const count = eff.effectGroups.reduce((n, g) => n + g.effects.length, 0);
    if (!count) throw new Error("no effects in file");
    const v = renderEffect(eff, host.container);
    return { summary: `Effect · ${eff.effectGroups.length} group${eff.effectGroups.length === 1 ? "" : "s"} · ${count} effect${count === 1 ? "" : "s"}`, ...v };
}
