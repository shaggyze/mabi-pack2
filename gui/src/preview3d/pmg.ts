// PMG model parser, ported from the shaggyze.website mabipatcher preview.
// Handles submesh versions 1.7, 2.0 and 3.0, applies each submesh's major matrix,
// converts triangle strips, and groups submeshes by texture for rendering.
import { BinaryReader } from "./binaryReader";

interface PmgVertex {
    x: number; y: number; z: number;
    nx: number; ny: number; nz: number;
    r: number; g: number; b: number; a: number;
    u: number; v: number;
}

export interface PmgSubmesh {
    parts: string;
    meshName: string;
    parts2: string;
    stats: string;
    normal: string;
    colorMap: string;
    textureName: string;
    minorMatrix: number[];
    majorMatrix: number[];
    faceIndices: number[];
    stripIndices: number[];
    vertices: PmgVertex[];
}

export interface PmgFile {
    meshName: string;
    version: [number, number];
    groups: { label: string; count: number }[];
    submeshes: PmgSubmesh[];
}

/** One renderable part: every submesh sharing a texture, merged. */
export interface PmgPart {
    textureName: string;
    colorSlot: number;
    positions: number[];
    uvs: number[];
    colors: number[];
    indices: number[];
    vertexCount: number;
    faceCount: number;
}

function readVertex(r: BinaryReader): PmgVertex {
    const x = r.f32(), y = r.f32(), z = r.f32();
    const nx = r.f32(), ny = r.f32(), nz = r.f32();
    const b = r.byte(), g = r.byte(), red = r.byte(), a = r.byte();
    return { x, y, z, nx, ny, nz, r: red, g, b, a, u: r.f32(), v: r.f32() };
}

function stripToTriangles(strip: number[]): number[] {
    const out: number[] = [];
    for (let i = 0; i + 2 < strip.length; i++) {
        const a = strip[i], b = strip[i + 1], c = strip[i + 2];
        if (a === b || b === c || a === c) continue;
        if (i % 2 === 0) out.push(a, b, c); else out.push(b, a, c);
    }
    return out;
}

/** Reads the counts block and the index/vertex arrays shared by every submesh version. */
function readBody(r: BinaryReader, faceCount: number, stripCount: number, vertCount: number, skinCount: number) {
    const faceIndices = new Array<number>(faceCount);
    for (let i = 0; i < faceCount; i++) faceIndices[i] = r.u16();
    const stripIndices = new Array<number>(stripCount);
    for (let i = 0; i < stripCount; i++) stripIndices[i] = r.u16();
    const vertices = new Array<PmgVertex>(vertCount);
    for (let i = 0; i < vertCount; i++) vertices[i] = readVertex(r);
    for (let i = 0; i < skinCount; i++) { r.i32(); r.i32(); r.f32(); r.i32(); }
    return { faceIndices, stripIndices, vertices };
}

function readCounts(r: BinaryReader) {
    r.i32(); r.bytes(36);
    const faces = r.i32(); r.i32();
    const strips = r.i32(); r.i32();
    const verts = r.i32();
    const skins = r.i32();
    r.bytes(32); r.i32(); r.i32(); r.i32(); r.i32(); r.i32();
    return { faces, strips, verts, skins };
}

/** Submesh v2.0 (and v3.0 when `extraName` is set: one extra string before the texture). */
function parseSubmeshLp(bytes: Uint8Array, extraName: boolean): PmgSubmesh {
    const r = new BinaryReader(bytes);
    const minorMatrix = r.floats(16);
    const majorMatrix = r.floats(16);
    r.i32(); r.bytes(8);
    const c = readCounts(r);
    r.bytes(4);
    const parts = r.lpStr(), meshName = r.lpStr(), parts2 = r.lpStr(), stats = r.lpStr();
    const normal = r.lpStr(), colorMap = r.lpStr();
    if (extraName) r.lpStr();
    const textureName = r.lpStr();
    r.bytes(4); r.floats(15);
    const body = readBody(r, c.faces, c.strips, c.verts, c.skins);
    return { parts, meshName, parts2, stats, normal, colorMap, textureName, minorMatrix, majorMatrix, ...body };
}

/** Submesh v1.7 (fixed-size strings). */
function parseSubmesh17(bytes: Uint8Array): PmgSubmesh {
    const r = new BinaryReader(bytes);
    const parts = r.strFixed(32), meshName = r.strFixed(128), parts2 = r.strFixed(32);
    const stats = r.strFixed(32), normal = r.strFixed(32), colorMap = r.strFixed(32);
    const minorMatrix = r.floats(16);
    const majorMatrix = r.floats(16);
    r.i32(); r.bytes(8);
    const textureName = r.strFixed(32);
    r.i32(); r.bytes(36);
    const faces = r.i32(); r.i32();
    const strips = r.i32(); r.i32();
    const verts = r.i32();
    const skins = r.i32();
    r.bytes(32); r.i32(); r.i32(); r.i32(); r.i32(); r.i32(); r.bytes(8); r.floats(15);
    const body = readBody(r, faces, strips, verts, skins);
    return { parts, meshName, parts2, stats, normal, colorMap, textureName, minorMatrix, majorMatrix, ...body };
}

function looksValid(m: PmgSubmesh): boolean {
    if (!m.vertices || m.vertices.length < 3 || m.vertices.length > 200_000) return false;
    const v0 = m.vertices[0];
    if (!isFinite(v0.x) || !isFinite(v0.y) || !isFinite(v0.z)) return false;
    const idx = m.faceIndices.length ? m.faceIndices : m.stripIndices;
    if (!idx.length) return false;
    let max = 0;
    for (const i of idx) if (i > max) max = i;
    return max < m.vertices.length;
}

function parseGroups(bytes: Uint8Array): { label: string; count: number }[] {
    const r = new BinaryReader(bytes);
    const out: { label: string; count: number }[] = [];
    while (r.remaining >= 68) {
        const label = r.strFixed(64);
        const count = r.i32();
        if (count < 0 || r.remaining < count * 204) break;
        r.bytes(count * 204);
        out.push({ label, count });
    }
    return out;
}

export function parsePmg(bytes: Uint8Array): PmgFile {
    const r = new BinaryReader(bytes);
    const magic = r.bytes(4);
    if (!(magic[0] === 0x70 && magic[1] === 0x6d && magic[2] === 0x67)) throw new Error("not a PMG file");
    const version: [number, number] = [r.byte(), r.byte()];
    const headSize = r.i32();
    const meshName = r.strFixed(32);
    r.bytes(100);
    const groups = parseGroups(r.bytes(Math.max(0, Math.min(headSize - 142, r.remaining))));
    const submeshes: PmgSubmesh[] = [];
    while (r.remaining >= 10) {
        const h = r.bytes(10);
        if (!(h[0] === 0x70 && h[1] === 0x6d && h[2] === 0x21 && h[3] === 0)) break;
        const major = h[4], minor = h[5];
        const size = h[6] | (h[7] << 8) | (h[8] << 16) | (h[9] << 24);
        if (size < 10 || r.remaining < size - 10) break;
        const body = r.bytes(size - 10);
        try {
            if (major === 2 && minor === 0) submeshes.push(parseSubmeshLp(body, false));
            else if (major === 1 && minor === 7) submeshes.push(parseSubmesh17(body));
            else if (major === 3 && minor === 0) {
                const m = parseSubmeshLp(body, true);
                if (looksValid(m)) submeshes.push(m);
            }
        } catch {
            // Skip a malformed submesh; the rest of the model still renders.
        }
    }
    return { meshName, version, groups, submeshes };
}

interface SubmeshGeometry {
    positions: Float32Array;
    uvs: Float32Array;
    colors: Float32Array;
    indices: number[];
    vertexCount: number;
}

function submeshGeometry(m: PmgSubmesh): SubmeshGeometry {
    const n = m.vertices.length;
    const positions = new Float32Array(n * 3);
    const uvs = new Float32Array(n * 2);
    const colors = new Float32Array(n * 3);
    const o = m.majorMatrix;
    const useMatrix = Array.isArray(o) && o.length === 16 && isFinite(o[0]);
    for (let i = 0; i < n; i++) {
        const v = m.vertices[i];
        if (useMatrix) {
            positions[i * 3]     = o[0] * v.x + o[1] * v.y + o[2] * v.z + o[3];
            positions[i * 3 + 1] = o[4] * v.x + o[5] * v.y + o[6] * v.z + o[7];
            positions[i * 3 + 2] = o[8] * v.x + o[9] * v.y + o[10] * v.z + o[11];
        } else {
            positions[i * 3] = v.x; positions[i * 3 + 1] = v.y; positions[i * 3 + 2] = v.z;
        }
        uvs[i * 2] = v.u; uvs[i * 2 + 1] = v.v;
        colors[i * 3] = v.r / 255; colors[i * 3 + 1] = v.g / 255; colors[i * 3 + 2] = v.b / 255;
    }
    const indices = m.faceIndices.length ? m.faceIndices.slice() : stripToTriangles(m.stripIndices);
    // A mirroring matrix flips winding; swap two corners so faces stay front-facing.
    if (useMatrix) {
        const det = o[0] * (o[5] * o[10] - o[6] * o[9]) - o[1] * (o[4] * o[10] - o[6] * o[8]) + o[2] * (o[4] * o[9] - o[5] * o[8]);
        if (det < 0) {
            for (let t = 0; t + 2 < indices.length; t += 3) {
                const tmp = indices[t + 1]; indices[t + 1] = indices[t + 2]; indices[t + 2] = tmp;
            }
        }
    }
    return { positions, uvs, colors, indices, vertexCount: n };
}

/** Merges the visible submeshes into one part per texture. */
export function pmgParts(file: PmgFile): PmgPart[] {
    let subs = file.submeshes.filter(s => s.stats === "e" || s.stats === "");
    if (!subs.length) subs = file.submeshes;
    const byTexture = new Map<string, PmgPart>();
    for (const s of subs) {
        const g = submeshGeometry(s);
        const tex = s.textureName || "";
        let part = byTexture.get(tex);
        if (!part) {
            const slot = /^b(\d+)$/i.exec(s.colorMap || "");
            part = { textureName: tex, colorSlot: slot ? Number(slot[1]) - 1 : -1, positions: [], uvs: [], colors: [], indices: [], vertexCount: 0, faceCount: 0 };
            byTexture.set(tex, part);
        }
        for (const x of g.positions) part.positions.push(x);
        for (const x of g.uvs) part.uvs.push(x);
        for (const x of g.colors) part.colors.push(x);
        for (const i of g.indices) part.indices.push(i + part.vertexCount);
        part.vertexCount += g.vertexCount;
    }
    return [...byTexture.values()].map(p => ({ ...p, faceCount: p.indices.length / 3 }));
}
