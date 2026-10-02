// Region preview for .rgn/.area entries: loads the region from the open archives,
// shows the 2D map by default and switches to the 3D world view on demand.
import { createMapView, type MapLayer, type MapView } from "./mapView";
import type { WorldView } from "./worldView";
import { cachedTexture } from "./dds";
import {
    ensurePropDb, findEntry, loadRegion, lookupProps, propModelNames,
    type AssetEntry, type AssetHost, type MapProp, type PropClass, type Translate,
} from "./worldData";
import type { Mounted3d } from "./panel";

export interface RegionHost {
    container: HTMLElement;
    overlay: HTMLElement;
    t: Translate;
    assets: AssetHost;
    entry: AssetEntry;
    accent: number;
    background: number;
    status(text: string): void;
    /** Still the current preview? (false once the user selected something else) */
    current(): boolean;
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

export async function mountRegion(host: RegionHost): Promise<Mounted3d | null> {
    const { t, assets } = host;
    host.status(t("wv_loading"));
    const data = await loadRegion(assets, host.entry);
    if (!host.current()) return null;

    // Prop class names need a plaintext propdb.xml; encoded ones are skipped quietly.
    const propDb = await ensurePropDb(assets);
    const classIds = [...new Set(data.areas.flatMap(a => a.props.map(p => p.class_id)))];
    const classes: Map<number, PropClass> = propDb?.classes ? await lookupProps(classIds) : new Map();
    if (!host.current()) return null;

    const props = data.areas.reduce((n, a) => n + a.props.length, 0);
    const events = data.areas.reduce((n, a) => n + a.events.length, 0);
    const title = data.region?.name || data.areas[0]?.name || host.entry.name;
    const parts = [t("wv_summary", [title, String(data.areas.length), props.toLocaleString(), events.toLocaleString()])];
    if (!data.region) parts.push(t("wv_no_region"));
    if (data.dropped_props) parts.push(t("wv_dropped", [data.dropped_props.toLocaleString()]));
    if (data.errors.length) {
        parts.push(t("wv_errors", [String(data.errors.length)]));
        data.errors.slice(0, 10).forEach(e => assets.log(`[Map] ${e}`, "warn"));
    }
    if (!classes.size && props) parts.push(t("wv_no_propdb"));
    const summary = parts.join(" · ");

    const layers: Record<MapLayer, boolean> = { props: true, events: true, terrain: true };
    const accentCss = `#${host.accent.toString(16).padStart(6, "0")}`;
    let map: MapView | undefined;
    let world: WorldView | undefined;
    let mode: "map" | "world" = "map";
    let disposed = false;
    let modelsText = "";
    const showStatus = () => host.status(`${summary}${modelsText} · ${t(mode === "map" ? "wv_hint_map" : "wv_hint_world")}`);

    const showMap = () => {
        world?.dispose(); world = undefined;
        map = createMapView({ container: host.container, data, t, accent: accentCss, propClass: id => classes.get(id) });
        (Object.keys(layers) as MapLayer[]).forEach(l => map!.setLayer(l, layers[l]));
        mode = "map";
        showStatus();
    };

    const modelKey = (p: MapProp): string | null => {
        const cls = classes.get(p.class_id);
        if (cls?.class_name) return cls.class_name.toLowerCase();
        // Without a propdb, a prop name that is itself a model/set name may still resolve.
        return p.name && /^[\w.-]+$/.test(p.name) ? p.name.toLowerCase() : null;
    };
    const loadModel = async (key: string) => {
        const { parsePmg, pmgParts } = await import("./pmg");
        for (const name of await propModelNames(assets, key, host.entry)) {
            const e = findEntry(assets.entries(), `${name.toLowerCase().replace(/\.pmg$/, "")}.pmg`);
            if (!e) continue;
            try { return pmgParts(parsePmg(await assets.bytes(e))); } catch { /* try the next name */ }
        }
        return null;
    };

    const showWorld = async () => {
        const { createWorldView } = await import("./worldView");
        if (disposed) return;
        map?.dispose(); map = undefined;
        world = createWorldView({
            container: host.container,
            data,
            accent: host.accent,
            background: host.background,
            modelKey,
            loadModel,
            texture: name => cachedTexture(`${host.entry.source_archive}|${name.toLowerCase()}`, false, () => assets.textureBytes(name, host.entry)),
            onModels: (placed) => { modelsText = placed ? ` · ${t("wv_models", [String(placed)])}` : ""; if (mode === "world") showStatus(); },
        });
        (Object.keys(layers) as MapLayer[]).forEach(l => world!.setLayer(l, layers[l]));
        mode = "world";
        showStatus();
    };

    const bar = document.createElement("div");
    bar.className = "p3d-toolbar";
    const layerBtn = (layer: MapLayer, label: string, tip: string) => {
        const b = button(t(label), t(tip), () => {
            layers[layer] = !layers[layer];
            b.classList.toggle("active", layers[layer]);
            map?.setLayer(layer, layers[layer]);
            world?.setLayer(layer, layers[layer]);
        });
        b.classList.add("active");
        return b;
    };
    const mapBtn = button(t("wv_btn_map"), t("wv_tip_map"), () => { if (mode !== "map") { showMap(); mapBtn.classList.add("active"); worldBtn.classList.remove("active"); } });
    const worldBtn = button(t("wv_btn_world"), t("wv_tip_world"), () => {
        if (mode !== "world") { showWorld(); worldBtn.classList.add("active"); mapBtn.classList.remove("active"); }
    });
    mapBtn.classList.add("active");
    bar.append(
        mapBtn, worldBtn,
        layerBtn("terrain", "wv_btn_terrain", "wv_tip_terrain"),
        layerBtn("props", "wv_btn_props", "wv_tip_props"),
        layerBtn("events", "wv_btn_events", "wv_tip_events"),
        button(t("p3d_btn_reset"), t("p3d_tip_reset"), () => { map?.reset(); world?.reset(); }),
    );
    host.overlay.appendChild(bar);
    showMap();

    return {
        summary,
        resize: () => { map?.resize(); world?.resize(); },
        dispose: () => {
            disposed = true;
            map?.dispose();
            world?.dispose();
            bar.remove();
        },
    };
}
