// Item lookup UI: which items use the previewed model, plus a search box that opens
// an item's model(s) from the open archives.
import { ensureItemDb, itemsForModel, searchItems, findEntry, type AssetHost, type AssetEntry, type ItemEntry, type Translate } from "./worldData";

export interface ItemPanelOptions {
    /** Element the panel is appended to. */
    parent: HTMLElement;
    host: AssetHost;
    t: Translate;
    /** The previewed model's file name, to list the items that use it. */
    model?: string;
    /** Entry the model came from (resolves sibling meshes first). */
    near?: AssetEntry;
    /** Floating box over the 3D viewport (true) or an inline bar (false). */
    floating: boolean;
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function attachItemPanel(opts: ItemPanelOptions): { dispose(): void } {
    const { host, t } = opts;
    const box = document.createElement("div");
    box.className = "p3d-items";
    box.style.cssText = opts.floating
        ? "position:absolute;top:34px;left:6px;max-width:min(360px,60%);max-height:70%;overflow:auto;z-index:3;pointer-events:auto;font-size:0.75em;background:color-mix(in srgb,var(--bg-surface,#0d0d1a) 85%,transparent);border:1px solid var(--border-glass,rgba(255,255,255,0.15));border-radius:6px;padding:4px 6px"
        : "white-space:normal;font-family:inherit;font-size:0.8em;padding:6px 8px;border-bottom:1px solid var(--border-glass,rgba(255,255,255,0.15));position:sticky;top:0;z-index:2;background:var(--bg-surface,#0d0d1a)";

    const usedBy = document.createElement("div");
    const toggle = document.createElement("button");
    toggle.className = "tab-btn";
    toggle.style.cssText = "padding:1px 6px;font-size:0.95em;margin:2px 0";
    toggle.textContent = t("item_find");
    toggle.title = t("item_find_tip");
    const searchWrap = document.createElement("div");
    searchWrap.style.display = opts.floating ? "none" : "block";
    const input = document.createElement("input");
    input.type = "search";
    input.placeholder = t("item_search_placeholder");
    input.style.cssText = "width:100%;box-sizing:border-box;font-size:1em;margin:3px 0";
    const results = document.createElement("div");
    searchWrap.append(input, results);
    box.append(usedBy, toggle, searchWrap);
    if (opts.floating) opts.parent.appendChild(box); else opts.parent.prepend(box);
    toggle.addEventListener("click", () => {
        const show = searchWrap.style.display === "none";
        searchWrap.style.display = show ? "block" : "none";
        if (show) input.focus();
    });
    if (!opts.floating) toggle.style.display = "none";

    let disposed = false;
    const setStatus = (el: HTMLElement, text: string) => { el.innerHTML = `<span style="opacity:0.7">${esc(text)}</span>`; };

    const openMesh = (name: string) => {
        const e = findEntry(host.entries(), `${name.toLowerCase().replace(/\.pmg$/, "")}.pmg`, opts.near);
        if (e) host.openEntry(e);
        else host.log(t("item_mesh_missing", [name]), "warn");
    };

    const itemHtml = (it: ItemEntry, withMeshes: boolean) => {
        const head = `<b>${esc(it.name || it.internal || "?")}</b> <span style="opacity:0.7">#${it.id}</span>`
            + (it.internal && it.internal !== it.name ? ` <span style="opacity:0.6">(${esc(it.internal)})</span>` : "")
            + (it.category ? `<div style="opacity:0.6;word-break:break-all">${esc(it.category)}</div>` : "");
        if (!withMeshes) return head;
        const meshes = it.meshes.length
            ? it.meshes.map(m => `<button class="tab-btn" data-mesh="${esc(m.name)}" title="${esc(m.name)}" style="padding:0 5px;margin:1px;font-size:0.95em">${esc(t(`item_mesh_${m.kind}`) === `item_mesh_${m.kind}` ? m.kind : t(`item_mesh_${m.kind}`))}</button>`).join("")
            : `<span style="opacity:0.6">${esc(t("item_no_model"))}</span>`;
        return `${head}<div>${meshes}</div>`;
    };

    const bindMeshButtons = (root: HTMLElement) => {
        root.querySelectorAll<HTMLButtonElement>("button[data-mesh]").forEach(b => {
            b.addEventListener("click", () => openMesh(b.dataset.mesh || ""));
        });
    };

    // Items using the current model.
    const ready = ensureItemDb(host);
    if (opts.model) {
        setStatus(usedBy, t("item_loading"));
        ready.then(async status => {
            if (disposed) return;
            if (!status) { setStatus(usedBy, t("item_no_db")); return; }
            const hits = await itemsForModel(opts.model!);
            if (disposed) return;
            if (!hits.length) { setStatus(usedBy, t("item_none_for_model")); return; }
            usedBy.innerHTML = `<div style="opacity:0.7">${esc(t("item_used_by", [String(hits.length)]))}</div>`
                + hits.slice(0, 8).map(h => `<div style="margin:2px 0">${itemHtml(h, false)}</div>`).join("");
            host.log(`[3D] ${t("item_used_by", [String(hits.length)])} ${hits.slice(0, 3).map(h => `${h.name} (#${h.id})`).join(", ")}`);
        }).catch(() => setStatus(usedBy, t("item_no_db")));
    } else {
        usedBy.style.display = "none";
    }

    // Search.
    let timer = 0;
    let seq = 0;
    const run = async () => {
        const q = input.value.trim();
        const my = ++seq;
        if (!q) { results.innerHTML = ""; return; }
        setStatus(results, t("item_loading"));
        const status = await ready;
        if (disposed || my !== seq) return;
        if (!status) { setStatus(results, t("item_no_db")); return; }
        const hits = await searchItems(q, 30);
        if (disposed || my !== seq) return;
        if (!hits.length) { setStatus(results, t("item_no_results")); return; }
        results.innerHTML = hits.map(h => `<div style="margin:3px 0;padding-top:3px;border-top:1px solid var(--border-glass,rgba(255,255,255,0.1))">${itemHtml(h, true)}</div>`).join("");
        bindMeshButtons(results);
    };
    input.addEventListener("input", () => { clearTimeout(timer); timer = window.setTimeout(run, 250); });
    input.addEventListener("keydown", e => { e.stopPropagation(); if (e.key === "Enter") { clearTimeout(timer); run(); } });
    // Keep viewport drag/zoom from firing while using the box.
    for (const ev of ["mousedown", "wheel", "touchstart"]) box.addEventListener(ev, e => e.stopPropagation(), { passive: true });

    return { dispose() { disposed = true; clearTimeout(timer); box.remove(); } };
}
