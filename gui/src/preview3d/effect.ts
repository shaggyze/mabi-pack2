// .eff effect-group XML parser and placement viewer, ported from the website preview.
import * as THREE from "three";
import type { SimpleViewer } from "./navmesh";

export interface EffectEntry {
    name: string | null;
    parent: string | null;
    effectName: string | null;
    offset: number[];
    rotAxis: number[];
    rotAngle: number;
}

export interface EffectGroup {
    playMode: string | null;
    playLength: number;
    play: string | null;
    effects: EffectEntry[];
}

export interface EffectFile {
    version: string | null | undefined;
    effectVersion: string | null | undefined;
    effectGroups: EffectGroup[];
}

const vec = (s: string | null, fallback: string) => (s || fallback).trim().split(/\s+/).map(Number);

export function parseEffectXml(xml: string): EffectFile {
    const doc = new DOMParser().parseFromString(xml, "text/xml");
    const groups: EffectGroup[] = [];
    for (const g of Array.from(doc.getElementsByTagName("EffectGroup"))) {
        const effects: EffectEntry[] = [];
        for (const e of Array.from(g.getElementsByTagName("Effect"))) {
            effects.push({
                name: e.getAttribute("name"),
                parent: e.getAttribute("parent"),
                effectName: e.getAttribute("effect_name"),
                offset: vec(e.getAttribute("offset"), "0 0 0"),
                rotAxis: vec(e.getAttribute("rot_axis"), "0 0 1"),
                rotAngle: Number(e.getAttribute("rot_angle")) || 0,
            });
        }
        groups.push({
            playMode: g.getAttribute("play_mode"),
            playLength: Number(g.getAttribute("play_length")),
            play: g.getAttribute("play"),
            effects,
        });
    }
    return {
        version: doc.documentElement?.getAttribute("version"),
        effectVersion: doc.documentElement?.getAttribute("effect_version"),
        effectGroups: groups,
    };
}

/** Shows each effect's anchor as a wire sphere at its offset; left-drag orbits, right-drag pans, wheel zooms. */
export function renderEffect(eff: EffectFile, container: HTMLElement): SimpleViewer {
    let dirty = true;
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x111111);
    const camera = new THREE.PerspectiveCamera(45, (container.clientWidth || 400) / (container.clientHeight || 300), 10, 1e5);
    camera.up.set(0, 0, 1);
    const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    renderer.setSize(container.clientWidth || 400, container.clientHeight || 300);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    scene.add(new THREE.AxesHelper(100));
    const grid = new THREE.GridHelper(1000, 10);
    grid.rotation.x = Math.PI / 2;
    scene.add(grid);

    const group = new THREE.Group();
    const sphere = new THREE.SphereGeometry(10, 8, 8);
    const mat = new THREE.MeshBasicMaterial({ color: 0x00ffff, wireframe: true });
    for (const g of eff.effectGroups) {
        for (const e of g.effects) {
            const m = new THREE.Mesh(sphere, mat);
            m.position.set(e.offset[0] || 0, e.offset[1] || 0, e.offset[2] || 0);
            if (e.rotAxis && e.rotAngle) {
                const axis = new THREE.Vector3(e.rotAxis[0], e.rotAxis[1], e.rotAxis[2]);
                if (axis.lengthSq() > 0) m.rotateOnAxis(axis.normalize(), e.rotAngle * Math.PI / 180);
            }
            group.add(m);
        }
    }
    scene.add(group);

    let tx = 0, ty = 0, dist = 1000, pitch = Math.PI / 4, yaw = Math.PI / 4;
    const place = () => {
        camera.position.set(
            tx + dist * Math.cos(yaw) * Math.cos(pitch),
            ty + dist * Math.sin(yaw) * Math.cos(pitch),
            dist * Math.sin(pitch),
        );
        camera.lookAt(tx, ty, 0);
        dirty = true;
    };
    place();

    const canvas = renderer.domElement;
    let rotating = false, panning = false, lx = 0, ly = 0;
    canvas.addEventListener("pointerdown", e => {
        if (e.button === 0) rotating = true; else panning = true;
        lx = e.clientX; ly = e.clientY;
        canvas.setPointerCapture(e.pointerId);
    });
    canvas.addEventListener("pointermove", e => {
        if (!rotating && !panning) return;
        const dx = e.clientX - lx, dy = e.clientY - ly;
        lx = e.clientX; ly = e.clientY;
        if (rotating) {
            yaw -= dx * 0.01;
            pitch = Math.max(0.1, Math.min(Math.PI / 2 - 0.1, pitch + dy * 0.01));
        }
        if (panning) {
            const f = dist * 0.002;
            tx += -Math.cos(yaw) * dy * f + -Math.cos(yaw - Math.PI / 2) * dx * f;
            ty += -Math.sin(yaw) * dy * f + -Math.sin(yaw - Math.PI / 2) * dx * f;
        }
        place();
    });
    canvas.addEventListener("pointerup", e => { rotating = panning = false; canvas.releasePointerCapture(e.pointerId); });
    canvas.addEventListener("contextmenu", e => e.preventDefault());
    canvas.addEventListener("wheel", e => {
        e.preventDefault();
        dist = Math.max(50, Math.min(1e4, dist * (e.deltaY > 0 ? 1.1 : 0.9)));
        place();
    }, { passive: false });

    let frame = 0;
    const tick = () => {
        frame = requestAnimationFrame(tick);
        if (dirty) { renderer.render(scene, camera); dirty = false; }
    };
    tick();

    return {
        resize() {
            const w = container.clientWidth, h = container.clientHeight;
            if (!w || !h) return;
            renderer.setSize(w, h);
            camera.aspect = w / h;
            camera.updateProjectionMatrix();
            dirty = true;
        },
        dispose() {
            cancelAnimationFrame(frame);
            renderer.dispose();
            renderer.forceContextLoss();
            grid.dispose();
            sphere.dispose(); mat.dispose();
            canvas.parentNode?.removeChild(canvas);
        },
    };
}
