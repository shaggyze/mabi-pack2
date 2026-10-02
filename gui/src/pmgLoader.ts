import * as THREE from 'three';

export interface PmgGeometry {
    positions: number[];
    normals: number[];
    uvs: number[];
    indices: number[];
    mesh_name: string;
    texture_name: string;
    vertex_count: number;
    face_count: number;
    /** Per-vertex RGB (r0,g0,b0, r1,g1,b1, …), 0-1. Empty when all vertices are white. */
    vertex_colors?: number[];
    /** Average RGB of all vertices, 0-1. Always present from Rust side. */
    avg_color?: [number, number, number];
}

export interface PMGViewer {
    dispose: () => void;
    setWireframe: (enabled: boolean) => void;
    resize: () => void;
}

export function createPMGViewer(container: HTMLElement, geo: PmgGeometry | null | undefined): PMGViewer {
    // Read CSS vars at call time — they resolve to RGB strings so we parse them into hex
    const accentHex = parseCssColor(getComputedStyle(document.documentElement).getPropertyValue('--accent-cyan').trim()) ?? 0x00d2ff;
    const bgHex     = parseCssColor(getComputedStyle(document.documentElement).getPropertyValue('--bg-surface').trim()) ?? 0x0d0d1a;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(bgHex);

    const w = container.clientWidth  || 400;
    const h = container.clientHeight || 300;
    const camera = new THREE.PerspectiveCamera(60, w / h, 0.01, 5000);
    camera.position.set(0, 0, 5);

    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(w, h);
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    scene.add(new THREE.AmbientLight(0xffffff, 0.7));
    const sun = new THREE.DirectionalLight(0xffffff, 0.9);
    sun.position.set(3, 5, 4);
    scene.add(sun);
    const fill = new THREE.DirectionalLight(new THREE.Color(accentHex), 0.4);
    fill.position.set(-3, -2, -3);
    scene.add(fill);

    const gridColor = new THREE.Color(accentHex);
    const grid = new THREE.GridHelper(10, 20, gridColor, new THREE.Color(0x333333));
    grid.position.y = -1.5;
    scene.add(grid);

    const geometry = new THREE.BufferGeometry();

    // Determine material colour from per-vertex data shipped by the Rust side.
    // Priority: per-vertex colours (varied) > average colour > accent fallback.
    const hasVColors = !!(geo && geo.vertex_colors && geo.vertex_colors.length > 0);
    const vColorsVary = hasVColors && vertexColorsVary(geo!.vertex_colors!);

    // Compute a single diffuse hex from avg_color (if not nearly all-white).
    let diffuseHex = accentHex;
    if (geo?.avg_color) {
        const [ar, ag, ab] = geo.avg_color;
        // Ignore if average is basically white — that means "no material tint"
        if (ar < 0.95 || ag < 0.95 || ab < 0.95) {
            diffuseHex = (Math.round(ar * 255) << 16) | (Math.round(ag * 255) << 8) | Math.round(ab * 255);
        }
    }

    const material = new THREE.MeshPhongMaterial({
        // When using per-vertex colours the base colour must be white so Three.js
        // multiplies it by the vertex colour attribute directly.
        color: vColorsVary ? 0xffffff : diffuseHex,
        emissive: new THREE.Color(diffuseHex).multiplyScalar(0.08),
        specular: 0x555555,
        shininess: 40,
        side: THREE.DoubleSide,
        vertexColors: vColorsVary,
    });
    let meshObject: THREE.Object3D;
    let extraDispose: (() => void) | null = null;

    if (geo && geo.positions.length >= 9 && geo.indices.length >= 3) {
        geometry.setAttribute('position', new THREE.Float32BufferAttribute(geo.positions, 3));
        if (geo.uvs.length > 0) {
            geometry.setAttribute('uv', new THREE.Float32BufferAttribute(geo.uvs, 2));
        }
        if (vColorsVary && geo.vertex_colors) {
            geometry.setAttribute('color', new THREE.Float32BufferAttribute(geo.vertex_colors, 3));
        }
        geometry.setIndex(geo.indices);

        // Center geometry at origin first, then recompute normals from faces
        geometry.center();
        geometry.computeVertexNormals();
        geometry.computeBoundingSphere();

        meshObject = new THREE.Mesh(geometry, material);

        if (geometry.boundingSphere && geometry.boundingSphere.radius > 0.0001) {
            const s = 1.5 / geometry.boundingSphere.radius;
            meshObject.scale.set(s, s, s);
            // meshObject.position stays (0,0,0) — geometry.center() already zeroed the centroid
        }
    } else {
        // Stub/empty PMG — show 3D extruded "MP" letters as placeholder
        const group = new THREE.Group();
        const mpMat = new THREE.MeshPhongMaterial({ color: accentHex, shininess: 60,
            emissive: new THREE.Color(accentHex).multiplyScalar(0.12) });
        const extOpts = { depth: 0.3, bevelEnabled: true, bevelSize: 0.03, bevelThickness: 0.03, bevelSegments: 2 };

        const mShape = new THREE.Shape();
        mShape.moveTo(0, 0);     mShape.lineTo(0, 1);
        mShape.lineTo(0.15, 1);  mShape.lineTo(0.4, 0.55);
        mShape.lineTo(0.65, 1);  mShape.lineTo(0.8, 1);
        mShape.lineTo(0.8, 0);   mShape.lineTo(0.65, 0);
        mShape.lineTo(0.65, 0.72); mShape.lineTo(0.4, 0.32);
        mShape.lineTo(0.15, 0.72); mShape.lineTo(0.15, 0);
        mShape.closePath();
        const mGeo = new THREE.ExtrudeGeometry(mShape, extOpts);
        mGeo.center();
        const mMesh = new THREE.Mesh(mGeo, mpMat);
        mMesh.position.x = -0.55;
        group.add(mMesh);

        const pShape = new THREE.Shape();
        pShape.moveTo(0, 0);    pShape.lineTo(0, 1);
        pShape.lineTo(0.5, 1);  pShape.lineTo(0.65, 0.85);
        pShape.lineTo(0.65, 0.55); pShape.lineTo(0.5, 0.4);
        pShape.lineTo(0.15, 0.4);  pShape.lineTo(0.15, 0);
        pShape.closePath();
        const pHole = new THREE.Path();
        pHole.moveTo(0.15, 0.55); pHole.lineTo(0.45, 0.55);
        pHole.lineTo(0.5, 0.62);  pHole.lineTo(0.5, 0.78);
        pHole.lineTo(0.45, 0.85); pHole.lineTo(0.15, 0.85);
        pHole.closePath();
        pShape.holes.push(pHole);
        const pGeo = new THREE.ExtrudeGeometry(pShape, extOpts);
        pGeo.center();
        const pMesh = new THREE.Mesh(pGeo, mpMat);
        pMesh.position.x = 0.55;
        group.add(pMesh);

        group.scale.set(1.2, 1.2, 1.2);
        meshObject = group;
        extraDispose = () => { mGeo.dispose(); pGeo.dispose(); mpMat.dispose(); };
    }

    scene.add(meshObject);

    let isDragging = false;
    let prevMouse = { x: 0, y: 0 };
    renderer.domElement.addEventListener('mousedown', (e) => { isDragging = true; prevMouse = { x: e.offsetX, y: e.offsetY }; });
    renderer.domElement.addEventListener('mouseup',   () => { isDragging = false; });
    renderer.domElement.addEventListener('mouseleave',() => { isDragging = false; });
    renderer.domElement.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        meshObject.rotation.y += (e.offsetX - prevMouse.x) * 0.01;
        meshObject.rotation.x += (e.offsetY - prevMouse.y) * 0.01;
        prevMouse = { x: e.offsetX, y: e.offsetY };
    });
    // Zoom with scroll
    renderer.domElement.addEventListener('wheel', (e) => {
        camera.position.z = Math.max(0.1, Math.min(50, camera.position.z + e.deltaY * 0.005));
        e.preventDefault();
    }, { passive: false });

    let animId: number;
    const animate = () => {
        animId = requestAnimationFrame(animate);
        if (!isDragging) meshObject.rotation.y += 0.005;
        renderer.render(scene, camera);
    };
    animate();

    return {
        setWireframe: (enabled) => { material.wireframe = enabled; },
        resize: () => {
            const nw = container.clientWidth || 400;
            const nh = container.clientHeight || 300;
            camera.aspect = nw / nh;
            camera.updateProjectionMatrix();
            renderer.setSize(nw, nh);
        },
        dispose: () => {
            cancelAnimationFrame(animId);
            renderer.dispose();
            geometry.dispose();
            material.dispose();
            if (extraDispose) extraDispose();
        },
    };
}

/**
 * Returns true if the per-vertex colour array has meaningful variation
 * (i.e. not all vertices share the same RGB within a small tolerance).
 * Uniform-colour arrays (e.g. all-grey default tints) are not worth enabling
 * vertexColors for — a single material colour looks identical and is cheaper.
 */
function vertexColorsVary(colors: number[]): boolean {
    if (colors.length < 6) return false;
    const r0 = colors[0], g0 = colors[1], b0 = colors[2];
    for (let i = 3; i < colors.length; i += 3) {
        if (Math.abs(colors[i]     - r0) > 0.01 ||
            Math.abs(colors[i + 1] - g0) > 0.01 ||
            Math.abs(colors[i + 2] - b0) > 0.01) {
            return true;
        }
    }
    return false;
}

function parseCssColor(css: string): number | null {
    if (!css) return null;
    // hex: #rrggbb or #rgb
    const hex = css.match(/^#([0-9a-f]{6})/i);
    if (hex) return parseInt(hex[1], 16);
    const hex3 = css.match(/^#([0-9a-f]{3})/i);
    if (hex3) {
        const [r, g, b] = hex3[1].split('').map(c => parseInt(c + c, 16));
        return (r << 16) | (g << 8) | b;
    }
    // rgb(r, g, b) / rgba(...)
    const rgb = css.match(/rgba?\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
    if (rgb) return (parseInt(rgb[1]) << 16) | (parseInt(rgb[2]) << 8) | parseInt(rgb[3]);
    return null;
}
