// .gm navigation-mesh parser and viewer, ported from the website preview.
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { BinaryReader } from "./binaryReader";

const utf8 = new TextDecoder("utf-8");

type GmRecord = Record<string, number>;

export interface GmFile {
    classes: string[];
    props: { type: number; name: string }[];
    verts: GmRecord[];
    tris: GmRecord[];
}

export interface GmGeometry {
    positions: Float32Array;
    indices: Uint32Array;
    vertexCount: number;
    faceCount: number;
}

export function parseGm(bytes: Uint8Array): GmFile {
    const r = new BinaryReader(bytes);
    const cstr = () => {
        const start = r.pos;
        while (r.pos < r.len && bytes[r.pos] !== 0) r.pos++;
        const s = utf8.decode(bytes.subarray(start, r.pos));
        r.pos++;
        return s;
    };
    r.i32();
    const classes: string[] = [];
    while (r.pos < r.len) {
        if (bytes[r.pos] === 0) { r.pos++; break; }
        classes.push(cstr());
    }
    const props: { type: number; name: string }[] = [];
    while (r.pos < r.len) {
        const type = r.byte();
        if (type === 0) break;
        props.push({ type, name: cstr() });
    }
    const verts: GmRecord[] = [], tris: GmRecord[] = [];
    try {
        while (r.pos < r.len) {
            const c = r.byte();
            if (c === 0) continue;
            if (c - 1 >= classes.length) break;
            const cls = classes[c - 1];
            if (cls === "mesh3DPartitioning") break;
            const rec: GmRecord = {};
            while (r.pos < r.len) {
                const p = r.byte();
                if (p === 0 || p - 1 >= props.length) break;
                const prop = props[p - 1];
                let v: number | undefined;
                if (prop.type === 4) v = r.byte();
                else if (prop.type === 3) v = r.i16();
                else if (prop.type === 2) v = r.i32();
                else if (prop.type === 1) v = r.f32();
                if (v !== undefined) rec[prop.name] = v;
            }
            if (cls === "vert") verts.push(rec);
            if (cls === "tri") tris.push(rec);
        }
    } catch {
        // Truncated tail: keep what was read.
    }
    return { classes, props, verts, tris };
}

export function gmToGeometry(gm: GmFile): GmGeometry {
    const n = gm.verts.length;
    const positions = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
        positions[i * 3] = gm.verts[i].x || 0;
        positions[i * 3 + 2] = gm.verts[i].y || 0;
    }
    const idx: number[] = [];
    for (const t of gm.tris) {
        const a = t.edge0StartVert, b = t.edge1StartVert, c = t.edge2StartVert;
        if (a !== undefined && b !== undefined && c !== undefined && a < n && b < n && c < n) idx.push(a, b, c);
    }
    return { positions, indices: new Uint32Array(idx), vertexCount: n, faceCount: idx.length / 3 };
}

export interface SimpleViewer { resize(): void; dispose(): void }

export function renderGm(geo: GmGeometry, container: HTMLElement): SimpleViewer {
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x222222);
    const camera = new THREE.PerspectiveCamera(60, (container.clientWidth || 400) / (container.clientHeight || 300), 1, 1e6);
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(container.clientWidth || 400, container.clientHeight || 300);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    const controls = new OrbitControls(camera, renderer.domElement);

    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(geo.positions, 3));
    g.setIndex(new THREE.BufferAttribute(geo.indices, 1));
    g.computeVertexNormals();
    const wire = new THREE.MeshBasicMaterial({ color: 0x00ff88, wireframe: true, transparent: true, opacity: 0.5 });
    const solid = new THREE.MeshLambertMaterial({ color: 0x334433, side: THREE.DoubleSide });
    scene.add(new THREE.Mesh(g, wire));
    scene.add(new THREE.Mesh(g, solid));
    scene.add(new THREE.AmbientLight(0xffffff, 0.8));
    const sun = new THREE.DirectionalLight(0xffffff, 0.5);
    sun.position.set(1e4, 2e4, 1e4);
    scene.add(sun);

    g.computeBoundingSphere();
    const bs = g.boundingSphere;
    if (bs) {
        controls.target.copy(bs.center);
        camera.position.set(bs.center.x, bs.center.y + bs.radius * 1.5, bs.center.z + bs.radius * 1.5);
    } else {
        camera.position.set(0, 1e4, 1e4);
    }

    let frame = 0;
    let dirty = true;
    controls.addEventListener("change", () => { dirty = true; });
    const tick = () => {
        frame = requestAnimationFrame(tick);
        controls.update();
        if (dirty) { renderer.render(scene, camera); dirty = false; }
    };
    tick();

    return {
        resize() {
            const w = container.clientWidth, h = container.clientHeight;
            if (!w || !h) return;
            camera.aspect = w / h;
            camera.updateProjectionMatrix();
            renderer.setSize(w, h);
            dirty = true;
        },
        dispose() {
            cancelAnimationFrame(frame);
            controls.dispose();
            renderer.dispose();
            renderer.forceContextLoss();
            g.dispose(); wire.dispose(); solid.dispose();
            container.innerHTML = "";
        },
    };
}
