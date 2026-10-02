// Textured PMG model viewer, ported from the shaggyze.website mabipatcher preview:
// one mesh per texture, DDS textures resolved by name, vertex colours,
// drag/wheel/touch controls, and GLB/OBJ/PNG export.
import * as THREE from "three";
import { GLTFExporter } from "three/examples/jsm/exporters/GLTFExporter.js";
import { OBJExporter } from "three/examples/jsm/exporters/OBJExporter.js";
import type { PmgPart } from "./pmg";
import type { DecodedTexture } from "./ddsDecode";

export interface ModelViewerOptions {
    accent?: number;
    background?: number;
    autoRotate?: boolean;
    antialias?: boolean;
    pixelRatio?: number;
    loadTextures?: boolean;
    accurateDds?: boolean;
    resolveTexture?: (name: string) => Promise<DecodedTexture | null>;
    /** Called as each texture settles, with the loaded and failed counts so far. */
    onTextureProgress?: (loaded: number, failed: number, total: number) => void;
}

export interface ModelViewer {
    setWireframe(on: boolean): void;
    setAutoRotate(on: boolean): void;
    reset(): void;
    resize(): void;
    exportGlb(): Promise<ArrayBuffer>;
    exportObj(): string;
    exportPng(): Promise<Uint8Array>;
    dispose(): void;
}

function colorsVary(c: number[]): boolean {
    const r = c[0], g = c[1], b = c[2];
    for (let i = 3; i < c.length; i += 3) {
        if (Math.abs(c[i] - r) > 0.01 || Math.abs(c[i + 1] - g) > 0.01 || Math.abs(c[i + 2] - b) > 0.01) return true;
    }
    return false;
}

function dataTextureFrom(t: DecodedTexture, renderer: THREE.WebGLRenderer): THREE.DataTexture {
    const tex = new THREE.DataTexture(t.rgba, t.width, t.height, THREE.RGBAFormat);
    tex.flipY = true;
    tex.colorSpace = THREE.SRGBColorSpace;
    tex.wrapS = tex.wrapT = THREE.RepeatWrapping;
    tex.generateMipmaps = true;
    tex.minFilter = THREE.LinearMipmapLinearFilter;
    tex.magFilter = THREE.LinearFilter;
    tex.anisotropy = renderer.capabilities.getMaxAnisotropy?.() || 1;
    tex.needsUpdate = true;
    return tex;
}

/** GLTFExporter cannot read DataTextures; copy them into canvases first. */
function exportableMaterial(m: THREE.Material): THREE.Material {
    const clone = m.clone() as THREE.MeshPhongMaterial;
    const map = clone.map as THREE.DataTexture | null;
    if (map && (map as THREE.DataTexture).isDataTexture && map.image?.data) {
        const { data, width, height } = map.image as { data: Uint8Array; width: number; height: number };
        const canvas = document.createElement("canvas");
        canvas.width = width; canvas.height = height;
        const pixels = new Uint8ClampedArray(data.buffer, data.byteOffset, data.length);
        canvas.getContext("2d")!.putImageData(new ImageData(pixels, width, height), 0, 0);
        const ct = new THREE.CanvasTexture(canvas);
        ct.wrapS = map.wrapS; ct.wrapT = map.wrapT; ct.repeat.copy(map.repeat);
        ct.flipY = map.flipY; ct.colorSpace = THREE.SRGBColorSpace;
        clone.map = ct;
    }
    return clone;
}

export function createModelViewer(container: HTMLElement, parts: PmgPart[], opts: ModelViewerOptions = {}): ModelViewer {
    const accent = opts.accent ?? 0x00d2ff;
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(opts.background ?? 0x0d0d1a);

    const w = container.clientWidth || 400, h = container.clientHeight || 300;
    const camera = new THREE.PerspectiveCamera(60, w / h, 0.01, 5000);
    camera.position.set(0, 0, 5);
    const renderer = new THREE.WebGLRenderer({ antialias: opts.antialias !== false, preserveDrawingBuffer: true });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, opts.pixelRatio ?? 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    let autoRotate = opts.autoRotate ?? true;
    let dirty = true;
    let disposed = false;
    const invalidate = () => { dirty = true; };

    scene.add(new THREE.AmbientLight(0xffffff, 0.7));
    const sun = new THREE.DirectionalLight(0xffffff, 0.9);
    sun.position.set(3, 5, 4);
    scene.add(sun);
    const fill = new THREE.DirectionalLight(new THREE.Color(accent), 0.4);
    fill.position.set(-3, -2, -3);
    scene.add(fill);
    const grid = new THREE.GridHelper(10, 20, new THREE.Color(accent), new THREE.Color(0x333333));
    grid.position.y = -1.5;
    scene.add(grid);

    const model = new THREE.Group();
    const geometries: THREE.BufferGeometry[] = [];
    const materials: THREE.MeshPhongMaterial[] = [];
    const bounds = new THREE.Box3();

    // Parts named only with underscores are collision/helper meshes on the site; skip them.
    for (const part of parts.filter(p => !/^_+$/.test(p.textureName || ""))) {
        if (part.positions.length < 9 || part.indices.length < 3) continue;
        const geo = new THREE.BufferGeometry();
        const vary = part.colors.length >= 6 && colorsVary(part.colors);
        geo.setAttribute("position", new THREE.Float32BufferAttribute(part.positions, 3));
        if (part.uvs.length) geo.setAttribute("uv", new THREE.Float32BufferAttribute(part.uvs, 2));
        if (vary) geo.setAttribute("color", new THREE.Float32BufferAttribute(part.colors, 3));
        geo.setIndex(part.indices);
        geo.computeVertexNormals();
        geo.computeBoundingBox();
        if (geo.boundingBox) bounds.union(geo.boundingBox);
        const mat = new THREE.MeshPhongMaterial({
            color: vary ? 0xffffff : accent,
            emissive: new THREE.Color(accent).multiplyScalar(0.06),
            specular: 0x444444,
            shininess: 30,
            side: THREE.DoubleSide,
            vertexColors: vary,
        });
        mat.userData.textureName = part.textureName || "";
        mat.userData.hasColors = vary;
        const mesh = new THREE.Mesh(geo, mat);
        mesh.name = part.textureName || "part";
        model.add(mesh);
        geometries.push(geo);
        materials.push(mat);
    }

    if (materials.length && !bounds.isEmpty()) {
        const center = new THREE.Vector3(), size = new THREE.Vector3();
        bounds.getCenter(center);
        bounds.getSize(size);
        const half = Math.max(size.x, size.y, size.z) / 2 || 1;
        model.children.forEach(c => c.position.sub(center));
        const s = 1.5 / half;
        model.scale.set(s, s, s);
    } else {
        const box = new THREE.BoxGeometry(1, 1, 1);
        const mat = new THREE.MeshPhongMaterial({ color: accent });
        geometries.push(box);
        materials.push(mat);
        model.add(new THREE.Mesh(box, mat));
    }
    scene.add(model);

    if (opts.loadTextures !== false && opts.resolveTexture) {
        const byName = new Map<string, Promise<THREE.DataTexture | null>>();
        const names = new Set(materials.map(m => m.userData.textureName as string).filter(Boolean));
        let loaded = 0, failed = 0;
        const report = () => { if (!disposed) opts.onTextureProgress?.(loaded, failed, names.size); };
        for (const mat of materials) {
            const name = mat.userData.textureName as string;
            if (!name) continue;
            let p = byName.get(name);
            if (!p) {
                p = opts.resolveTexture(name)
                    .then(t => {
                        if (!t || !t.rgba || disposed) return null;
                        const tex = dataTextureFrom(t, renderer);
                        tex.userData.hasAlpha = t.hasAlpha;
                        return tex;
                    })
                    .catch(() => null)
                    .then(tex => {
                        if (tex) loaded++; else failed++;
                        report();
                        return tex;
                    });
                byName.set(name, p);
            }
            p.then(tex => {
                if (!tex || disposed) return;
                mat.map = tex;
                if (opts.accurateDds && tex.userData.hasAlpha) { mat.alphaTest = 0.5; mat.transparent = false; }
                if (!mat.userData.hasColors) mat.color.set(0xffffff);
                mat.needsUpdate = true;
                invalidate();
            });
        }
    }

    // ── Controls: left-drag rotate, right/middle-drag pan, wheel zoom, touch orbit/pinch ──
    const canvas = renderer.domElement;
    let dragging: "rotate" | "pan" | null = null;
    let last = { x: 0, y: 0 };
    const orbit = (dx: number, dy: number) => { model.rotation.y += dx; model.rotation.x += dy; invalidate(); };
    const zoom = (f: number) => { camera.position.z = Math.max(0.1, Math.min(50, camera.position.z * f)); invalidate(); };
    const pan = (dx: number, dy: number) => {
        model.position.x += dx * camera.position.z * 0.0016;
        model.position.y -= dy * camera.position.z * 0.0016;
        invalidate();
    };
    const reset = () => { model.rotation.set(0, 0, 0); model.position.set(0, 0, 0); camera.position.set(0, 0, 5); invalidate(); };

    const onDown = (e: MouseEvent) => { dragging = e.button === 0 ? "rotate" : "pan"; last = { x: e.offsetX, y: e.offsetY }; };
    const onUp = () => { dragging = null; };
    const onMove = (e: MouseEvent) => {
        if (!dragging) return;
        const dx = e.offsetX - last.x, dy = e.offsetY - last.y;
        last = { x: e.offsetX, y: e.offsetY };
        if (dragging === "rotate") orbit(dx * 0.01, dy * 0.01); else pan(dx, dy);
    };
    const onWheel = (e: WheelEvent) => { e.preventDefault(); zoom(e.deltaY > 0 ? 1.1 : 0.9); };
    const onContext = (e: Event) => e.preventDefault();
    const onDbl = () => reset();
    canvas.addEventListener("mousedown", onDown);
    canvas.addEventListener("mouseup", onUp);
    canvas.addEventListener("mouseleave", onUp);
    canvas.addEventListener("mousemove", onMove);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("contextmenu", onContext);
    canvas.addEventListener("dblclick", onDbl);

    let touch: { x: number; y: number; d: number } | null = null;
    const touchPoint = (t: TouchList) => {
        if (t.length === 1) return { x: t[0].clientX, y: t[0].clientY, d: 0 };
        return {
            x: (t[0].clientX + t[1].clientX) / 2,
            y: (t[0].clientY + t[1].clientY) / 2,
            d: Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY),
        };
    };
    const onTouchStart = (e: TouchEvent) => { touch = touchPoint(e.touches); e.preventDefault(); };
    const onTouchMove = (e: TouchEvent) => {
        if (!touch) return;
        const p = touchPoint(e.touches);
        if (e.touches.length >= 2) {
            if (touch.d > 0 && p.d > 0) zoom(touch.d / p.d);
            pan(p.x - touch.x, p.y - touch.y);
        } else {
            orbit((p.x - touch.x) * 0.01, (p.y - touch.y) * 0.01);
        }
        touch = p;
        e.preventDefault();
    };
    const onTouchEnd = (e: TouchEvent) => { touch = e.touches.length ? touchPoint(e.touches) : null; };
    canvas.addEventListener("touchstart", onTouchStart, { passive: false });
    canvas.addEventListener("touchmove", onTouchMove, { passive: false });
    canvas.addEventListener("touchend", onTouchEnd);
    canvas.addEventListener("touchcancel", onTouchEnd);

    let frame = 0;
    const tick = () => {
        frame = requestAnimationFrame(tick);
        if (autoRotate && !dragging) {
            model.rotation.y += 0.005;
            renderer.render(scene, camera);
        } else if (dirty) {
            renderer.render(scene, camera);
            dirty = false;
        }
    };
    tick();

    return {
        setWireframe(on) { materials.forEach(m => { m.wireframe = on; }); invalidate(); },
        setAutoRotate(on) { autoRotate = on; invalidate(); },
        reset,
        resize() {
            const cw = container.clientWidth, ch = container.clientHeight;
            if (!cw || !ch) return;
            renderer.setSize(cw, ch);
            camera.aspect = cw / ch;
            camera.updateProjectionMatrix();
            invalidate();
        },
        async exportGlb() {
            const copy = model.clone();
            const temp: THREE.Material[] = [];
            copy.traverse(o => {
                const mesh = o as THREE.Mesh;
                if (mesh.isMesh && mesh.material) {
                    const swap = (m: THREE.Material) => { const c = exportableMaterial(m); temp.push(c); return c; };
                    mesh.material = Array.isArray(mesh.material) ? mesh.material.map(swap) : swap(mesh.material);
                }
            });
            try {
                return await new GLTFExporter().parseAsync(copy, { binary: true, embedImages: true, onlyVisible: true }) as ArrayBuffer;
            } finally {
                // Only the canvas copies are new; shared DataTextures stay with the viewer.
                temp.forEach(m => {
                    const map = (m as THREE.MeshPhongMaterial).map;
                    if (map && (map as THREE.CanvasTexture).isCanvasTexture) map.dispose();
                    m.dispose();
                });
            }
        },
        exportObj() {
            return new OBJExporter().parse(model);
        },
        exportPng() {
            renderer.render(scene, camera);
            return new Promise((resolve, reject) => {
                canvas.toBlob(b => {
                    if (!b) { reject(new Error("render capture failed")); return; }
                    b.arrayBuffer().then(buf => resolve(new Uint8Array(buf)), reject);
                }, "image/png");
            });
        },
        dispose() {
            disposed = true;
            cancelAnimationFrame(frame);
            renderer.dispose();
            renderer.forceContextLoss();
            grid.dispose();
            geometries.forEach(g => g.dispose());
            materials.forEach(m => { m.map?.dispose(); m.dispose(); });
            canvas.parentNode?.removeChild(canvas);
        },
    };
}
