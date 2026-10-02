// Top-down 2D region map: area bounds, terrain height shading, prop and event
// positions, with pan/zoom and hover tooltips.
import type { AreaInfo, MapEvent, MapProp, PropClass, RegionMap, Translate } from "./worldData";

export type MapLayer = "props" | "events" | "terrain";

export interface MapViewOptions {
    container: HTMLElement;
    data: RegionMap;
    t: Translate;
    propClass(id: number): PropClass | undefined;
    accent: string;
}

export interface MapView {
    setLayer(layer: MapLayer, on: boolean): void;
    reset(): void;
    resize(): void;
    dispose(): void;
}

type Hit = { kind: "prop"; p: MapProp; area: AreaInfo } | { kind: "event"; e: MapEvent; area: AreaInfo };

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** Stable colour per prop class. */
export function classColor(id: number): string {
    const h = ((id * 2654435761) >>> 0) % 360;
    return `hsl(${h},70%,60%)`;
}

/** World extent of everything in the region: [minX, minY, maxX, maxY]. */
export function regionBounds(data: RegionMap): [number, number, number, number] {
    let b: [number, number, number, number] = [Infinity, Infinity, -Infinity, -Infinity];
    const add = (x: number, y: number) => {
        if (!isFinite(x) || !isFinite(y)) return;
        b = [Math.min(b[0], x), Math.min(b[1], y), Math.max(b[2], x), Math.max(b[3], y)];
    };
    for (const a of data.areas) {
        add(a.bottom_left[0], a.bottom_left[1]);
        add(a.top_right[0], a.top_right[1]);
        for (const p of a.props) add(p.pos[0], p.pos[1]);
        for (const e of a.events) add(e.pos[0], e.pos[1]);
    }
    if (!isFinite(b[0])) {
        const r = data.region;
        if (r) { add(r.bottom_left[0], r.bottom_left[1]); add(r.top_right[0], r.top_right[1]); }
    }
    if (!isFinite(b[0])) b = [0, 0, 1000, 1000];
    if (b[2] - b[0] < 1) b[2] = b[0] + 1000;
    if (b[3] - b[1] < 1) b[3] = b[1] + 1000;
    return b;
}

/** Height -> RGB ramp shared with the 3D view (lowland green to highland tan). */
export function heightColor(t: number): [number, number, number] {
    const stops: [number, number, number, number][] = [
        [0, 40, 70, 60], [0.35, 70, 120, 70], [0.7, 150, 140, 95], [1, 225, 215, 190],
    ];
    const v = Math.max(0, Math.min(1, isFinite(t) ? t : 0));
    for (let i = 1; i < stops.length; i++) {
        if (v <= stops[i][0]) {
            const [a, b] = [stops[i - 1], stops[i]];
            const f = (v - a[0]) / (b[0] - a[0] || 1);
            return [a[1] + (b[1] - a[1]) * f, a[2] + (b[2] - a[2]) * f, a[3] + (b[3] - a[3]) * f];
        }
    }
    return [225, 215, 190];
}

function terrainImage(a: AreaInfo, min: number, max: number): HTMLCanvasElement | null {
    const tr = a.terrain;
    if (!tr || tr.cols < 2 || tr.rows < 2) return null;
    const c = document.createElement("canvas");
    c.width = tr.cols; c.height = tr.rows;
    const ctx = c.getContext("2d");
    if (!ctx) return null;
    const img = ctx.createImageData(tr.cols, tr.rows);
    const range = max - min || 1;
    const seg = (tr.cols - 1) / Math.max(1, tr.planes_x);
    const h = (x: number, y: number) => tr.heights[Math.min(tr.rows - 1, Math.max(0, y)) * tr.cols + Math.min(tr.cols - 1, Math.max(0, x))];
    for (let y = 0; y < tr.rows; y++) {
        for (let x = 0; x < tr.cols; x++) {
            const v = h(x, y);
            // Simple hillshade from the north-west.
            const dx = h(x + 1, y) - h(x - 1, y), dy = h(x, y + 1) - h(x, y - 1);
            const shade = Math.max(0.55, Math.min(1.25, 1 + (-dx + dy) / (tr.step[0] * 4 || 800)));
            const [r, g, b] = heightColor((v - min) / range);
            const px = Math.min(tr.planes_x - 1, Math.floor(x / seg)), py = Math.min(tr.planes_y - 1, Math.floor(y / seg));
            const hidden = tr.hidden[py * tr.planes_x + px] === 1;
            const i = ((tr.rows - 1 - y) * tr.cols + x) * 4; // row 0 is the area's bottom edge
            img.data[i] = r * shade; img.data[i + 1] = g * shade; img.data[i + 2] = b * shade;
            img.data[i + 3] = hidden ? 0 : 255;
        }
    }
    ctx.putImageData(img, 0, 0);
    return c;
}

export function createMapView(opts: MapViewOptions): MapView {
    const { container, data, t } = opts;
    container.innerHTML = "";
    const canvas = document.createElement("canvas");
    canvas.style.cssText = "display:block;width:100%;height:100%;cursor:grab;touch-action:none";
    const tip = document.createElement("div");
    tip.style.cssText = "position:absolute;pointer-events:none;display:none;z-index:4;font-size:11px;line-height:1.35;max-width:320px;padding:4px 7px;border-radius:4px;background:rgba(10,12,24,0.92);color:#e6e6f0;border:1px solid rgba(255,255,255,0.18);white-space:normal;word-break:break-word";
    container.style.position = container.style.position || "relative";
    container.append(canvas, tip);
    const ctx = canvas.getContext("2d")!;

    const layers: Record<MapLayer, boolean> = { props: true, events: true, terrain: true };
    const bounds = regionBounds(data);
    const cx = (bounds[0] + bounds[2]) / 2, cy = (bounds[1] + bounds[3]) / 2;
    let W = 1, H = 1, dpr = 1;
    let scale = 1, panX = 0, panY = 0;
    let dirty = true;
    let disposed = false;

    let hmin = Infinity, hmax = -Infinity;
    for (const a of data.areas) if (a.terrain) { hmin = Math.min(hmin, a.terrain.min); hmax = Math.max(hmax, a.terrain.max); }
    const terrains = data.areas.map(a => ({ a, img: terrainImage(a, hmin, hmax) }));

    // Bucket grid for hover lookup.
    const GRID = 128;
    const cellW = (bounds[2] - bounds[0]) / GRID || 1, cellH = (bounds[3] - bounds[1]) / GRID || 1;
    const buckets = new Map<number, Hit[]>();
    const bucketOf = (x: number, y: number) => {
        const gx = Math.max(0, Math.min(GRID - 1, Math.floor((x - bounds[0]) / cellW)));
        const gy = Math.max(0, Math.min(GRID - 1, Math.floor((y - bounds[1]) / cellH)));
        return gy * GRID + gx;
    };
    const addHit = (x: number, y: number, h: Hit) => {
        const k = bucketOf(x, y);
        const l = buckets.get(k);
        if (l) l.push(h); else buckets.set(k, [h]);
    };
    for (const area of data.areas) {
        for (const p of area.props) addHit(p.pos[0], p.pos[1], { kind: "prop", p, area });
        for (const e of area.events) addHit(e.pos[0], e.pos[1], { kind: "event", e, area });
    }

    const sx = (x: number) => (x - cx) * scale + W / 2 + panX;
    const sy = (y: number) => -(y - cy) * scale + H / 2 + panY;
    const wx = (px: number) => (px - W / 2 - panX) / scale + cx;
    const wy = (py: number) => -(py - H / 2 - panY) / scale + cy;

    const fit = () => {
        scale = Math.min(W / (bounds[2] - bounds[0]), H / (bounds[3] - bounds[1])) * 0.92 || 1;
        panX = 0; panY = 0;
        dirty = true;
    };

    const draw = () => {
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.fillStyle = "#0b0f1c";
        ctx.fillRect(0, 0, W, H);

        if (layers.terrain) {
            ctx.imageSmoothingEnabled = true;
            for (const { a, img } of terrains) {
                if (!img || !a.terrain) continue;
                const tr = a.terrain;
                const x0 = tr.origin[0], y0 = tr.origin[1];
                const x1 = x0 + tr.step[0] * (tr.cols - 1), y1 = y0 + tr.step[1] * (tr.rows - 1);
                ctx.drawImage(img, sx(x0), sy(y1), (x1 - x0) * scale, (y1 - y0) * scale);
            }
        }

        // Area outlines and names.
        ctx.lineWidth = 1;
        ctx.strokeStyle = "rgba(255,255,255,0.28)";
        ctx.font = "11px sans-serif";
        ctx.fillStyle = "rgba(255,255,255,0.55)";
        for (const a of data.areas) {
            const x0 = sx(a.bottom_left[0]), y0 = sy(a.top_right[1]);
            const w = (a.top_right[0] - a.bottom_left[0]) * scale, h = (a.top_right[1] - a.bottom_left[1]) * scale;
            if (w > 0 && h > 0) {
                ctx.strokeRect(x0 + 0.5, y0 + 0.5, w, h);
                if (w > 80 && h > 20) ctx.fillText(a.name, x0 + 4, y0 + 13);
            }
        }

        if (layers.events) {
            ctx.strokeStyle = "rgba(255,170,60,0.85)";
            ctx.fillStyle = "rgba(255,170,60,0.12)";
            for (const a of data.areas) for (const e of a.events) {
                if (e.shapes.length) {
                    for (const s of e.shapes) {
                        ctx.beginPath();
                        ctx.moveTo(sx(s[0]), sy(s[1]));
                        for (let i = 2; i < 8; i += 2) ctx.lineTo(sx(s[i]), sy(s[i + 1]));
                        ctx.closePath();
                        ctx.fill();
                        ctx.stroke();
                    }
                } else {
                    const x = sx(e.pos[0]), y = sy(e.pos[1]);
                    ctx.beginPath(); ctx.moveTo(x, y - 4); ctx.lineTo(x + 4, y); ctx.lineTo(x, y + 4); ctx.lineTo(x - 4, y); ctx.closePath(); ctx.stroke();
                }
            }
        }

        if (layers.props) {
            const big = scale > 0.08; // zoomed in: draw bounds where known
            const byColor = new Map<string, MapProp[]>();
            for (const a of data.areas) for (const p of a.props) {
                const x = sx(p.pos[0]), y = sy(p.pos[1]);
                if (x < -20 || y < -20 || x > W + 20 || y > H + 20) continue;
                const c = classColor(p.class_id);
                const l = byColor.get(c);
                if (l) l.push(p); else byColor.set(c, [p]);
            }
            for (const [c, list] of byColor) {
                ctx.fillStyle = c;
                ctx.strokeStyle = c;
                const dots = new Path2D(), boxes = new Path2D();
                for (const p of list) {
                    const x = sx(p.pos[0]), y = sy(p.pos[1]);
                    const bw = p.top_right[0] - p.bottom_left[0], bh = p.top_right[1] - p.bottom_left[1];
                    if (big && bw > 0 && bh > 0 && bw < 1e5 && bh < 1e5) {
                        boxes.rect(sx(p.bottom_left[0]), sy(p.top_right[1]), bw * scale, bh * scale);
                    }
                    dots.moveTo(x + 2, y);
                    dots.arc(x, y, 2, 0, Math.PI * 2);
                }
                ctx.globalAlpha = 0.9;
                ctx.fill(dots);
                if (big) { ctx.globalAlpha = 0.55; ctx.stroke(boxes); }
                ctx.globalAlpha = 1;
            }
        }

        // Scale bar.
        const target = 120 / scale;
        const pow = Math.pow(10, Math.floor(Math.log10(target)));
        const len = [1, 2, 5, 10].map(m => m * pow).find(v => v >= target * 0.5) ?? pow;
        ctx.fillStyle = "rgba(255,255,255,0.7)";
        ctx.fillRect(10, H - 14, len * scale, 2);
        ctx.fillText(`${len.toLocaleString()}`, 10, H - 18);
    };

    let frame = 0;
    const tick = () => {
        frame = requestAnimationFrame(tick);
        if (dirty && W > 1) { dirty = false; draw(); }
    };

    const resize = () => {
        const r = container.getBoundingClientRect();
        const nw = Math.max(1, Math.floor(r.width)), nh = Math.max(1, Math.floor(r.height));
        const first = W === 1;
        dpr = Math.min(2, window.devicePixelRatio || 1);
        W = nw; H = nh;
        canvas.width = Math.floor(W * dpr); canvas.height = Math.floor(H * dpr);
        if (first) fit();
        dirty = true;
    };

    // ── hover ──
    const hitAt = (px: number, py: number): Hit | null => {
        const x = wx(px), y = wy(py);
        const radius = 7 / scale;
        const g0 = bucketOf(x - radius, y - radius), g1 = bucketOf(x + radius, y + radius);
        const gx0 = g0 % GRID, gy0 = Math.floor(g0 / GRID), gx1 = g1 % GRID, gy1 = Math.floor(g1 / GRID);
        let best: Hit | null = null, bestD = radius * radius;
        for (let gy = gy0; gy <= gy1; gy++) for (let gx = gx0; gx <= gx1; gx++) {
            for (const h of buckets.get(gy * GRID + gx) ?? []) {
                if (h.kind === "prop" && !layers.props) continue;
                if (h.kind === "event" && !layers.events) continue;
                const pos = h.kind === "prop" ? h.p.pos : h.e.pos;
                const d = (pos[0] - x) ** 2 + (pos[1] - y) ** 2;
                if (d <= bestD) { bestD = d; best = h; }
            }
        }
        return best;
    };
    const fmtPos = (p: [number, number, number]) => `${Math.round(p[0])}, ${Math.round(p[1])}, ${Math.round(p[2])}`;
    const row = (label: string, value: string) => value ? `<div><span style="opacity:0.65">${esc(label)}:</span> ${esc(value)}</div>` : "";
    const tipHtml = (h: Hit) => {
        if (h.kind === "prop") {
            const p = h.p, cls = opts.propClass(p.class_id);
            const clsText = cls ? `${p.class_id} · ${cls.class_name}${cls.name && cls.name !== cls.class_name ? ` (${cls.name})` : ""}` : String(p.class_id);
            return `<b>${esc(t("wv_tt_prop"))}</b> ${esc(p.title || p.name || "")}`
                + row(t("wv_tt_class"), clsText)
                + row(t("wv_tt_state"), p.state)
                + row(t("wv_tt_pos"), fmtPos(p.pos))
                + row(t("wv_tt_area"), h.area.name)
                + `<div style="opacity:0.5">0x${esc(p.entity_id)}</div>`;
        }
        const e = h.e;
        return `<b>${esc(t("wv_tt_event"))}</b> ${esc(e.name)}`
            + row(t("wv_tt_type"), String(e.event_type))
            + row(t("wv_tt_pos"), fmtPos(e.pos))
            + row(t("wv_tt_area"), h.area.name)
            + `<div style="opacity:0.5">0x${esc(e.entity_id)}</div>`;
    };

    let drag: { x: number; y: number } | null = null;
    const onDown = (e: PointerEvent) => {
        drag = { x: e.clientX, y: e.clientY };
        canvas.setPointerCapture(e.pointerId);
        canvas.style.cursor = "grabbing";
        tip.style.display = "none";
    };
    const onUp = (e: PointerEvent) => {
        drag = null;
        canvas.style.cursor = "grab";
        try { canvas.releasePointerCapture(e.pointerId); } catch { /* already released */ }
    };
    const onMove = (e: PointerEvent) => {
        if (drag) {
            panX += e.clientX - drag.x; panY += e.clientY - drag.y;
            drag = { x: e.clientX, y: e.clientY };
            dirty = true;
            return;
        }
        const r = canvas.getBoundingClientRect();
        const px = e.clientX - r.left, py = e.clientY - r.top;
        const h = hitAt(px, py);
        if (!h) { tip.style.display = "none"; return; }
        tip.innerHTML = tipHtml(h);
        tip.style.display = "block";
        const tw = tip.offsetWidth, th = tip.offsetHeight;
        tip.style.left = `${Math.min(W - tw - 4, px + 12)}px`;
        tip.style.top = `${Math.min(H - th - 4, py + 12)}px`;
    };
    const onLeave = () => { tip.style.display = "none"; };
    const onWheel = (e: WheelEvent) => {
        e.preventDefault();
        const r = canvas.getBoundingClientRect();
        const px = e.clientX - r.left, py = e.clientY - r.top;
        const before = [wx(px), wy(py)];
        scale *= e.deltaY > 0 ? 1 / 1.2 : 1.2;
        scale = Math.max(1e-5, Math.min(50, scale));
        // Keep the point under the cursor fixed.
        panX += px - sx(before[0]);
        panY += py - sy(before[1]);
        dirty = true;
    };
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointercancel", onUp);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerleave", onLeave);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("dblclick", fit);

    resize();
    tick();

    return {
        setLayer(layer, on) { layers[layer] = on; dirty = true; },
        reset: fit,
        resize,
        dispose() {
            if (disposed) return;
            disposed = true;
            cancelAnimationFrame(frame);
            canvas.remove();
            tip.remove();
        },
    };
}
