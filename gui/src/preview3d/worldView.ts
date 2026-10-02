// 3D world preview: height-mapped terrain per area, prop markers (instanced boxes),
// event outlines, and real prop models streamed in for the props nearest the camera
// target.
//
// Coordinates: Mabinogi world (x, y) is the ground plane with z as altitude; the scene
// uses three's Y-up as (x, altitude, -y), recentred and scaled by S. Prop transforms
// follow CodfishBender/MabiMapper (`UpdatePropTransforms`): yaw = -rotation - 90° in a
// left-handed Y-up space, which becomes rotation.y = rotation + 90° here with the model
// mirrored on Z. Not verified against the game client.
import * as THREE from "three";
import type { PmgPart } from "./pmg";
import type { DecodedTexture } from "./ddsDecode";
import { dataTextureFrom } from "./modelViewer";
import { heightColor, regionBounds } from "./mapView";
import type { MapLayer } from "./mapView";
import type { MapProp, RegionMap } from "./worldData";

export interface WorldViewOptions {
    container: HTMLElement;
    data: RegionMap;
    background: number;
    accent: number;
    /** Cache key for a prop's model, or null when it has none to try. */
    modelKey(p: MapProp): string | null;
    /** Mesh parts for a model key (null when it cannot be resolved). */
    loadModel(key: string, p: MapProp): Promise<PmgPart[] | null>;
    texture(name: string): Promise<DecodedTexture | null>;
    /** Called when the number of loaded prop models changes. */
    onModels?(placed: number, templates: number): void;
}

export interface WorldView {
    setLayer(layer: MapLayer, on: boolean): void;
    reset(): void;
    resize(): void;
    dispose(): void;
}

const S = 0.01;
const MAX_BOXES = 30_000;
const NEAREST = 24;
const MAX_PLACED = 64;
const MAX_IN_FLIGHT = 3;

function hashColor(id: number): THREE.Color {
    const h = (((id * 2654435761) >>> 0) % 360) / 360;
    return new THREE.Color().setHSL(h, 0.7, 0.6);
}

export function createWorldView(opts: WorldViewOptions): WorldView {
    const { container, data } = opts;
    const bounds = regionBounds(data);
    const cx = (bounds[0] + bounds[2]) / 2, cy = (bounds[1] + bounds[3]) / 2;
    const extent = Math.max(bounds[2] - bounds[0], bounds[3] - bounds[1]) * S;
    const toScene = (x: number, y: number, z: number) => new THREE.Vector3((x - cx) * S, z * S, -(y - cy) * S);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(opts.background);
    const w0 = container.clientWidth || 400, h0 = container.clientHeight || 300;
    const camera = new THREE.PerspectiveCamera(55, w0 / h0, Math.max(0.05, extent / 20000), extent * 6 + 100);
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(w0, h0);
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    const canvas = renderer.domElement;

    scene.add(new THREE.AmbientLight(0xffffff, 0.65));
    const sun = new THREE.DirectionalLight(0xffffff, 0.9);
    sun.position.set(0.4, 1, 0.3);
    scene.add(sun);

    const disposables: { dispose(): void }[] = [];
    const groups: Record<MapLayer, THREE.Group> = { terrain: new THREE.Group(), props: new THREE.Group(), events: new THREE.Group() };
    Object.values(groups).forEach(g => scene.add(g));

    // ── terrain ──
    let hmin = Infinity, hmax = -Infinity;
    for (const a of data.areas) if (a.terrain) { hmin = Math.min(hmin, a.terrain.min); hmax = Math.max(hmax, a.terrain.max); }
    const terrainMat = new THREE.MeshLambertMaterial({ vertexColors: true, side: THREE.DoubleSide });
    disposables.push(terrainMat);
    for (const a of data.areas) {
        const tr = a.terrain;
        if (!tr || tr.cols < 2 || tr.rows < 2) continue;
        const pos = new Float32Array(tr.cols * tr.rows * 3);
        const col = new Float32Array(tr.cols * tr.rows * 3);
        const range = hmax - hmin || 1;
        for (let y = 0; y < tr.rows; y++) for (let x = 0; x < tr.cols; x++) {
            const i = y * tr.cols + x, h = tr.heights[i];
            const v = toScene(tr.origin[0] + x * tr.step[0], tr.origin[1] + y * tr.step[1], h);
            pos.set([v.x, v.y, v.z], i * 3);
            const [r, g, b] = heightColor((h - hmin) / range);
            col.set([r / 255, g / 255, b / 255], i * 3);
        }
        const seg = (tr.cols - 1) / Math.max(1, tr.planes_x);
        const idx: number[] = [];
        for (let y = 0; y < tr.rows - 1; y++) for (let x = 0; x < tr.cols - 1; x++) {
            const px = Math.min(tr.planes_x - 1, Math.floor(x / seg)), py = Math.min(tr.planes_y - 1, Math.floor(y / seg));
            if (tr.hidden[py * tr.planes_x + px] === 1) continue;
            const i = y * tr.cols + x;
            idx.push(i, i + 1, i + tr.cols, i + 1, i + tr.cols + 1, i + tr.cols);
        }
        if (!idx.length) continue;
        const geo = new THREE.BufferGeometry();
        geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
        geo.setAttribute("color", new THREE.BufferAttribute(col, 3));
        geo.setIndex(idx);
        geo.computeVertexNormals();
        disposables.push(geo);
        groups.terrain.add(new THREE.Mesh(geo, terrainMat));
    }

    // ── prop markers ──
    const allProps: MapProp[] = data.areas.flatMap(a => a.props);
    const boxed = allProps.slice(0, MAX_BOXES);
    const boxGeo = new THREE.BoxGeometry(1, 1, 1);
    const boxMat = new THREE.MeshLambertMaterial({ color: 0xffffff, transparent: true, opacity: 0.75 });
    disposables.push(boxGeo, boxMat);
    const boxes = new THREE.InstancedMesh(boxGeo, boxMat, Math.max(1, boxed.length));
    boxes.count = boxed.length;
    const boxMatrices: THREE.Matrix4[] = [];
    const propScenePos: THREE.Vector3[] = [];
    {
        const m = new THREE.Matrix4(), q = new THREE.Quaternion(), sc = new THREE.Vector3();
        boxed.forEach((p, i) => {
            const [bl, tr] = [p.bottom_left, p.top_right];
            const dx = tr[0] - bl[0], dy = tr[1] - bl[1];
            let center: THREE.Vector3;
            if (dx > 0 && dy > 0 && dx < 1e5 && dy < 1e5) {
                const z0 = Math.min(bl[2], tr[2], p.pos[2]);
                const dz = Math.max(20, Math.abs(tr[2] - bl[2]) || 100);
                center = toScene((bl[0] + tr[0]) / 2, (bl[1] + tr[1]) / 2, z0 + dz / 2);
                q.identity();
                sc.set(Math.max(dx, 10) * S, dz * S, Math.max(dy, 10) * S);
            } else {
                const size = 100 * (p.scale > 0 && p.scale < 100 ? p.scale : 1);
                center = toScene(p.pos[0], p.pos[1], p.pos[2] + size / 2);
                q.setFromAxisAngle(new THREE.Vector3(0, 1, 0), p.rotation + Math.PI / 2);
                sc.set(size * S, size * S, size * S);
            }
            m.compose(center, q, sc);
            boxMatrices.push(m.clone());
            boxes.setMatrixAt(i, m);
            boxes.setColorAt(i, hashColor(p.class_id));
        });
        boxed.forEach(p => propScenePos.push(toScene(p.pos[0], p.pos[1], p.pos[2])));
    }
    boxes.instanceMatrix.needsUpdate = true;
    if (boxes.instanceColor) boxes.instanceColor.needsUpdate = true;
    groups.props.add(boxes);

    // ── events ──
    {
        const pts: number[] = [];
        for (const a of data.areas) for (const e of a.events) {
            const z = e.pos[2] + 30;
            for (const s of e.shapes) {
                for (let k = 0; k < 4; k++) {
                    const a0 = toScene(s[k * 2], s[k * 2 + 1], z), b0 = toScene(s[((k + 1) % 4) * 2], s[((k + 1) % 4) * 2 + 1], z);
                    pts.push(a0.x, a0.y, a0.z, b0.x, b0.y, b0.z);
                }
            }
            if (!e.shapes.length) {
                const p = toScene(e.pos[0], e.pos[1], e.pos[2]);
                pts.push(p.x, p.y, p.z, p.x, p.y + 150 * S, p.z);
            }
        }
        if (pts.length) {
            const geo = new THREE.BufferGeometry();
            geo.setAttribute("position", new THREE.Float32BufferAttribute(pts, 3));
            const mat = new THREE.LineBasicMaterial({ color: 0xffaa3c });
            disposables.push(geo, mat);
            groups.events.add(new THREE.LineSegments(geo, mat));
        }
    }

    // ── camera (orbit around a ground target) ──
    const target = new THREE.Vector3();
    let radius = extent * 0.9 || 50, theta = Math.PI / 4, phi = Math.PI / 3.2;
    let dirty = true;
    let moved = true;
    const invalidate = () => { dirty = true; moved = true; };
    const place = () => {
        camera.position.set(
            target.x + radius * Math.sin(phi) * Math.sin(theta),
            target.y + radius * Math.cos(phi),
            target.z + radius * Math.sin(phi) * Math.cos(theta));
        camera.lookAt(target);
    };
    const reset = () => {
        target.set(0, (isFinite(hmin) ? (hmin + hmax) / 2 : 0) * S, 0);
        radius = extent * 0.9 || 50; theta = Math.PI / 4; phi = Math.PI / 3.2;
        invalidate();
    };
    reset();

    let drag: { x: number; y: number; mode: "orbit" | "pan" } | null = null;
    const onDown = (e: PointerEvent) => {
        drag = { x: e.clientX, y: e.clientY, mode: e.button === 0 && !e.shiftKey ? "orbit" : "pan" };
        canvas.setPointerCapture(e.pointerId);
    };
    const onUp = (e: PointerEvent) => { drag = null; try { canvas.releasePointerCapture(e.pointerId); } catch { /* released */ } };
    const onMove = (e: PointerEvent) => {
        if (!drag) return;
        const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
        drag.x = e.clientX; drag.y = e.clientY;
        if (drag.mode === "orbit") {
            theta -= dx * 0.006;
            phi = Math.max(0.05, Math.min(Math.PI / 2 - 0.02, phi - dy * 0.006));
        } else {
            const k = radius * 0.0018;
            const right = new THREE.Vector3(Math.cos(theta), 0, -Math.sin(theta));
            const fwd = new THREE.Vector3(-Math.sin(theta), 0, -Math.cos(theta));
            target.addScaledVector(right, -dx * k).addScaledVector(fwd, dy * k);
        }
        invalidate();
    };
    const onWheel = (e: WheelEvent) => {
        e.preventDefault();
        radius = Math.max(extent / 2000 + 0.5, Math.min(extent * 4 + 10, radius * (e.deltaY > 0 ? 1.15 : 1 / 1.15)));
        invalidate();
    };
    const onContext = (e: Event) => e.preventDefault();
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointercancel", onUp);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("contextmenu", onContext);
    canvas.addEventListener("dblclick", reset);

    // ── streamed prop models ──
    let disposed = false;
    const templates = new Map<string, Promise<THREE.Group | null>>();
    const failed = new Set<string>();
    const placed = new Map<number, THREE.Object3D>(); // box index -> model
    const textures = new Map<string, Promise<THREE.DataTexture | null>>();
    let inFlight = 0;
    const zero = new THREE.Matrix4().makeScale(0, 0, 0);

    const textureFor = (name: string) => {
        let p = textures.get(name);
        if (!p) {
            p = opts.texture(name).then(t => (t?.rgba && !disposed ? dataTextureFrom(t, renderer) : null)).catch(() => null);
            textures.set(name, p);
        }
        return p;
    };

    const buildTemplate = (parts: PmgPart[]): THREE.Group => {
        const g = new THREE.Group();
        for (const part of parts.filter(p => !/^_+$/.test(p.textureName || ""))) {
            if (part.positions.length < 9 || part.indices.length < 3) continue;
            const geo = new THREE.BufferGeometry();
            geo.setAttribute("position", new THREE.Float32BufferAttribute(part.positions, 3));
            if (part.uvs.length) geo.setAttribute("uv", new THREE.Float32BufferAttribute(part.uvs, 2));
            geo.setIndex(part.indices);
            geo.computeVertexNormals();
            const mat = new THREE.MeshLambertMaterial({ color: 0xd8d8d8, side: THREE.DoubleSide });
            disposables.push(geo, mat);
            if (part.textureName) {
                textureFor(part.textureName).then(tex => {
                    if (!tex || disposed) return;
                    mat.map = tex;
                    if (tex.userData.hasAlpha) mat.alphaTest = 0.5;
                    mat.color.set(0xffffff);
                    mat.needsUpdate = true;
                    dirty = true;
                });
            }
            g.add(new THREE.Mesh(geo, mat));
        }
        return g;
    };

    const placeModel = (i: number, tpl: THREE.Group) => {
        if (placed.has(i) || disposed) return;
        const p = boxed[i];
        const obj = tpl.clone();
        const s = (p.scale > 0 && p.scale < 100 ? p.scale : 1) * S;
        obj.position.copy(toScene(p.pos[0], p.pos[1], p.pos[2]));
        obj.rotation.y = p.rotation + Math.PI / 2;
        obj.scale.set(s, s, -s);
        groups.props.add(obj);
        placed.set(i, obj);
        boxes.setMatrixAt(i, zero);
        boxes.instanceMatrix.needsUpdate = true;
        dirty = true;
    };

    const unplace = (i: number) => {
        const obj = placed.get(i);
        if (!obj) return;
        groups.props.remove(obj);
        placed.delete(i);
        boxes.setMatrixAt(i, boxMatrices[i]);
        boxes.instanceMatrix.needsUpdate = true;
        dirty = true;
    };

    const report = () => {
        let ok = 0;
        templates.forEach((_, k) => { if (!failed.has(k)) ok++; });
        opts.onModels?.(placed.size, ok);
    };

    const stream = () => {
        if (disposed || !moved || !groups.props.visible) return;
        moved = false;
        const order: { i: number; d: number; key: string }[] = [];
        for (let i = 0; i < boxed.length; i++) {
            const key = opts.modelKey(boxed[i]);
            if (!key || failed.has(key)) continue;
            order.push({ i, d: propScenePos[i].distanceToSquared(target), key });
        }
        order.sort((a, b) => a.d - b.d);
        const near = order.slice(0, NEAREST);
        const keep = new Set(near.map(n => n.i));
        // Drop the farthest placed models when over budget.
        if (placed.size > MAX_PLACED) {
            const far = [...placed.keys()].filter(i => !keep.has(i))
                .sort((a, b) => propScenePos[b].distanceToSquared(target) - propScenePos[a].distanceToSquared(target));
            for (const i of far.slice(0, placed.size - MAX_PLACED)) unplace(i);
        }
        for (const n of near) {
            if (placed.has(n.i)) continue;
            let tpl = templates.get(n.key);
            if (!tpl) {
                if (inFlight >= MAX_IN_FLIGHT) { moved = true; continue; } // retry on the next pass
                inFlight++;
                tpl = opts.loadModel(n.key, boxed[n.i])
                    .then(parts => (parts && parts.length && !disposed ? buildTemplate(parts) : null))
                    .catch(() => null)
                    .then(g => {
                        inFlight--;
                        if (!g || !g.children.length) failed.add(n.key);
                        moved = true;
                        report();
                        return g && g.children.length ? g : null;
                    });
                templates.set(n.key, tpl);
            }
            tpl.then(g => { if (g && keep.has(n.i)) { placeModel(n.i, g); report(); } });
        }
    };
    const streamTimer = window.setInterval(stream, 500);

    let frame = 0;
    const tick = () => {
        frame = requestAnimationFrame(tick);
        if (!dirty) return;
        dirty = false;
        place();
        renderer.render(scene, camera);
    };
    tick();

    return {
        setLayer(layer, on) { groups[layer].visible = on; invalidate(); },
        reset,
        resize() {
            const cw = container.clientWidth, ch = container.clientHeight;
            if (!cw || !ch) return;
            renderer.setSize(cw, ch);
            camera.aspect = cw / ch;
            camera.updateProjectionMatrix();
            dirty = true;
        },
        dispose() {
            if (disposed) return;
            disposed = true;
            clearInterval(streamTimer);
            cancelAnimationFrame(frame);
            textures.forEach(p => p.then(t => t?.dispose()));
            disposables.forEach(d => d.dispose());
            boxes.dispose();
            renderer.dispose();
            renderer.forceContextLoss();
            canvas.remove();
        },
    };
}
