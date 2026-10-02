// Shared types and archive helpers for the item lookup, region map and world previews.
// The app supplies an AssetHost (its loaded entry list plus byte access); the heavy
// parsing runs in Rust (gui/src-tauri/src/world_preview.rs).
import { invoke } from "../platform/invoke";

/** The subset of the app's AggregateEntry these previews need. */
export interface AssetEntry {
    name: string;
    source_archive: string;
    salt_used: string;
    entries_salt_used: string;
    iv0: number;
    h_off: number;
    mode: string;
}

export interface AssetHost {
    entries(): AssetEntry[];
    bytes(e: AssetEntry): Promise<Uint8Array>;
    /** Shows an entry in the preview pane (as if it was clicked in the list). */
    openEntry(e: AssetEntry): void;
    /** DDS bytes for a texture name, searching near `near` first. */
    textureBytes(name: string, near?: AssetEntry): Promise<Uint8Array | null>;
    log(msg: string, level?: "info" | "warn" | "error" | "success"): void;
    /** UI language code (en, tw, ja, ko). */
    language(): string;
}

export type Translate = (key: string, args?: string[]) => string;

// ── Rust result types (snake_case as serialized) ──

export interface ItemMesh { kind: string; name: string }
export interface ItemEntry { id: number; name: string; internal: string; category: string; meshes: ItemMesh[]; inv_image: string }
export interface PropClass { id: number; class_name: string; class_path: string; string_id: string; name: string }

export interface RegionInfo {
    version: number; id: number; group_id: number; name: string; cell_size: number;
    bottom_left: [number, number, number]; top_right: [number, number, number];
    scene: string; area_names: string[];
}
export type ShapeQuad = [number, number, number, number, number, number, number, number];
export interface MapProp {
    class_id: number; entity_id: string; name: string; pos: [number, number, number];
    scale: number; rotation: number;
    bottom_left: [number, number, number]; top_right: [number, number, number];
    title: string; state: string; shapes: ShapeQuad[];
}
export interface MapEvent { entity_id: string; name: string; pos: [number, number, number]; event_type: number; shapes: ShapeQuad[] }
export interface AreaTerrain {
    cols: number; rows: number; origin: [number, number]; step: [number, number];
    heights: number[]; min: number; max: number;
    planes_x: number; planes_y: number; hidden: number[];
}
export interface AreaInfo {
    version: number; id: number; region_id: number; server_name: string; name: string;
    bottom_left: [number, number, number]; top_right: [number, number, number];
    props: MapProp[]; events: MapEvent[]; terrain: AreaTerrain | null;
}
export interface RegionMap { region: RegionInfo | null; areas: AreaInfo[]; errors: string[]; dropped_props: number }

// ── entry helpers ──

const clean = (k: string) => (!k || k === "N/A" || k === "Search/Default" || k === "UNENCRYPTED") ? null : k;

export function toRef(e: AssetEntry) {
    return {
        archivePath: e.source_archive,
        entryName: e.name,
        key: clean(e.salt_used),
        entriesKey: clean(e.entries_salt_used),
        iv0: e.iv0,
        hOff: e.h_off,
        mode: e.mode,
    };
}

export const baseName = (p: string) => (p.split(/[\\/¥₩]/).pop() || p).toLowerCase();
export const folderOf = (p: string) => p.toLowerCase().replace(/[\\/¥₩][^\\/¥₩]*$/, "").replace(/[¥₩]/g, "\\").replace(/\//g, "\\");

interface EntryIndex { byBase: Map<string, AssetEntry[]> }
const indexCache = new WeakMap<AssetEntry[], EntryIndex>();

function entryIndex(entries: AssetEntry[]): EntryIndex {
    let idx = indexCache.get(entries);
    if (idx) return idx;
    const byBase = new Map<string, AssetEntry[]>();
    for (const e of entries) {
        const b = baseName(e.name);
        const list = byBase.get(b);
        if (list) list.push(e); else byBase.set(b, [e]);
    }
    idx = { byBase };
    indexCache.set(entries, idx);
    return idx;
}

/** Entry with this file name, preferring `near`'s folder, then its archive, then the newest. */
export function findEntry(entries: AssetEntry[], fileName: string, near?: AssetEntry): AssetEntry | null {
    const hits = entryIndex(entries).byBase.get(fileName.toLowerCase());
    if (!hits?.length) return null;
    if (near) {
        const dir = folderOf(near.name);
        const sameDir = hits.filter(e => folderOf(e.name) === dir);
        if (sameDir.length) return sameDir[sameDir.length - 1];
        const sameArchive = hits.filter(e => e.source_archive === near.source_archive);
        if (sameArchive.length) return sameArchive[sameArchive.length - 1];
    }
    return hits[hits.length - 1];
}

/** Last copy of every distinct entry name matching `re` (archives load oldest first). */
function newestMatching(entries: AssetEntry[], re: RegExp): AssetEntry[] {
    const byName = new Map<string, AssetEntry>();
    for (const e of entries) if (re.test(e.name)) byName.set(e.name.toLowerCase().replace(/\//g, "\\"), e);
    return [...byName.values()];
}

const LANG_SUFFIX: Record<string, string[]> = {
    en: ["english", "usa", "en"],
    tw: ["taiwan", "chinese", "tw", "zh"],
    ja: ["japanese", "japan", "jp", "ja"],
    ko: ["korean", "korea", "kr", "ko"],
};

/** One localization file per stem (`itemdb`, `itemdb_x`, ...), preferring the UI language, then English. */
function pickLocals(files: AssetEntry[], lang: string): AssetEntry[] {
    const prefs = [...(LANG_SUFFIX[lang] ?? []), ...LANG_SUFFIX.en];
    const byStem = new Map<string, AssetEntry[]>();
    for (const f of files) {
        const stem = baseName(f.name).split(".")[0];
        const list = byStem.get(stem);
        if (list) list.push(f); else byStem.set(stem, [f]);
    }
    const out: AssetEntry[] = [];
    for (const list of byStem.values()) {
        const rank = (f: AssetEntry) => {
            const parts = baseName(f.name).split(".");
            const suffix = parts.length > 2 ? parts[1] : "";
            const i = prefs.indexOf(suffix);
            return i < 0 ? prefs.length : i;
        };
        out.push(list.reduce((a, b) => (rank(b) < rank(a) ? b : a)));
    }
    return out;
}

function sourcesFor(entries: AssetEntry[], db: string, lang: string) {
    const xml = newestMatching(entries, new RegExp(`(^|[\\\\/])db[\\\\/]${db}[^\\\\/]*\\.xml$`, "i"));
    const locals = pickLocals(newestMatching(entries, new RegExp(`(^|[\\\\/])local[\\\\/]xml[\\\\/]${db}[^\\\\/]*\\.txt$`, "i")), lang);
    const key = [...xml, ...locals].map(e => `${e.source_archive}|${e.name}`).join("\n");
    return { xml, locals, key };
}

export interface ItemDbStatus { items: number; with_models: number; files: number; errors: string[] }
const itemDbLoads = new WeakMap<AssetEntry[], Promise<ItemDbStatus | null>>();

/** Loads (once per entry list) the item index from the open archives; null when no itemdb is open. */
export function ensureItemDb(host: AssetHost): Promise<ItemDbStatus | null> {
    const entries = host.entries();
    let p = itemDbLoads.get(entries);
    if (p) return p;
    const s = sourcesFor(entries, "itemdb", host.language());
    p = s.xml.length
        ? invoke<ItemDbStatus>("itemdb_load", { sources: s.xml.map(toRef), locals: s.locals.map(toRef), cacheKey: s.key })
            .catch(err => { host.log(`[itemdb] ${err}`, "warn"); return null; })
        : Promise.resolve(null);
    itemDbLoads.set(entries, p);
    return p;
}

export const itemsForModel = (model: string) => invoke<ItemEntry[]>("itemdb_for_model", { model });
export const searchItems = (query: string, limit = 40) => invoke<ItemEntry[]>("itemdb_search", { query, limit });

export interface PropDbStatus { classes: number; skipped: number }
const propDbLoads = new WeakMap<AssetEntry[], Promise<PropDbStatus | null>>();

/** Loads plaintext propdb.xml files (encoded ones are skipped quietly). */
export function ensurePropDb(host: AssetHost): Promise<PropDbStatus | null> {
    const entries = host.entries();
    let p = propDbLoads.get(entries);
    if (p) return p;
    const s = sourcesFor(entries, "propdb", host.language());
    p = s.xml.length
        ? invoke<PropDbStatus>("propdb_load", { sources: s.xml.map(toRef), locals: s.locals.map(toRef), cacheKey: s.key }).catch(() => null)
        : Promise.resolve(null);
    propDbLoads.set(entries, p);
    return p;
}

export async function lookupProps(ids: number[]): Promise<Map<number, PropClass>> {
    const list = ids.length ? await invoke<PropClass[]>("propdb_lookup", { ids }).catch(() => [] as PropClass[]) : [];
    return new Map(list.map(p => [p.id, p]));
}

/** Loads a region for a previewed .rgn or .area entry from the same folder. */
export function loadRegion(host: AssetHost, entry: AssetEntry): Promise<RegionMap> {
    const entries = host.entries();
    const dir = folderOf(entry.name);
    const inDir = (ext: string) => newestMatching(entries, new RegExp(`\\.${ext}$`, "i")).filter(e => folderOf(e.name) === dir);
    const isRgn = /\.rgn$/i.test(entry.name);
    const rgns = isRgn ? [entry] : inDir("rgn");
    return invoke<RegionMap>("region_load", {
        rgnCandidates: rgns.map(toRef),
        areaEntries: inDir("area").map(toRef),
        focusArea: isRgn ? null : baseName(entry.name),
    });
}

/** Model file names a prop class can resolve to: its .set file's models, else the class name itself. */
export async function propModelNames(host: AssetHost, className: string, near?: AssetEntry): Promise<string[]> {
    const set = findEntry(host.entries(), `${className}.set`, near);
    if (set) {
        const names = await invoke<string[]>("set_model_names", { entry: toRef(set) }).catch(() => [] as string[]);
        if (names.length) return names;
    }
    return [className];
}
