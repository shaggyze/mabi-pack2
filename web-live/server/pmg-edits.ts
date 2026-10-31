import {PmgDocument} from './pmg-document.js';

export interface PmgVertexEdit {
    block: number;
    vertex: number;
    /** Human-facing RGBA; native storage is BGRA. */
    color?: readonly [number, number, number, number];
    /** Native UV coordinates; no OBJ/export V inversion. */
    uv?: readonly [number, number];
}
export interface PmgVertexValues {
    readonly position: readonly [number, number, number];
    readonly normal: readonly [number, number, number];
    readonly color: readonly [number, number, number, number];
    readonly uv: readonly [number, number];
}

function vertexOffset(document: PmgDocument, bytes: Uint8Array, block: number, vertex: number): number {
    if (!Number.isSafeInteger(block) || block < 0 || block >= document.blocks.length) throw Error('Choose an existing native mesh block.');
    const info = document.blocks[block];
    if (!info.geometry) throw Error('This mesh version is preserved but does not support vertex edits.');
    if (!Number.isSafeInteger(vertex) || vertex < 0 || vertex >= info.geometry.vertices) throw Error('Choose an existing vertex in this mesh.');
    let start = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(6, true);
    for (let i = 0; i < block; i++) start += document.blocks[i].byteLength;
    return start + info.geometry.vertexOffset + vertex * 36;
}

export function readPmgVertex(document: PmgDocument, block: number, vertex: number): PmgVertexValues {
    const bytes = document.toBytes(), offset = vertexOffset(document, bytes, block, vertex);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const vector = (relative: number) => Object.freeze([0, 4, 8].map(p => view.getFloat32(offset + relative + p, true))) as readonly [number, number, number];
    return Object.freeze({
        position: vector(0), normal: vector(12),
        color: Object.freeze([bytes[offset + 26], bytes[offset + 25], bytes[offset + 24], bytes[offset + 27]]) as readonly [number, number, number, number],
        uv: Object.freeze([view.getFloat32(offset + 28, true), view.getFloat32(offset + 32, true)]) as readonly [number, number],
    });
}

/** Apply a batch transaction to a new document. Only the requested vertex
 * attributes are written; matrices, bounds, topology, skin/morph/physics data,
 * strings, opaque blocks and the source document remain byte-identical.
 * Position/normal/topology changes require further native format validation.
 */
export function editPmgVertices(document: PmgDocument, edits: readonly PmgVertexEdit[]): PmgDocument {
    if (!Array.isArray(edits) || edits.length > 100_000) throw Error('Provide at most 100,000 vertex edits.');
    const bytes = document.toBytes(), targets = new Set<string>();
    const checked = edits.map(edit => {
        if (!edit || typeof edit !== 'object' || Object.keys(edit).some(key => !['block', 'vertex', 'color', 'uv'].includes(key))) throw Error('Only vertex RGBA and UV edits are supported.');
        const {block, vertex, color: inputColor, uv: inputUv} = edit;
        const color = Array.isArray(inputColor) ? [...inputColor] : inputColor;
        const uv = Array.isArray(inputUv) ? [...inputUv] : inputUv;
        const offset = vertexOffset(document, bytes, block, vertex), key = `${block}:${vertex}`;
        if (targets.has(key)) throw Error('A vertex may appear only once per edit batch.');
        targets.add(key);
        if (color === undefined && uv === undefined) throw Error('Choose a color or UV change.');
        if (color !== undefined && (!Array.isArray(color) || color.length !== 4 || !color.every(v => Number.isInteger(v) && v >= 0 && v <= 255))) throw Error('RGBA channels must be integers from 0 to 255.');
        if (uv !== undefined && (!Array.isArray(uv) || uv.length !== 2 || !uv.every(v => Number.isFinite(v) && Number.isFinite(Math.fround(v))))) throw Error('UV coordinates must be finite 32-bit numbers.');
        return {offset, color, uv};
    });
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (const edit of checked) {
        if (edit.color) bytes.set([edit.color[2], edit.color[1], edit.color[0], edit.color[3]], edit.offset + 24);
        if (edit.uv) {view.setFloat32(edit.offset + 28, edit.uv[0], true);view.setFloat32(edit.offset + 32, edit.uv[1], true);}
    }
    return PmgDocument.parse(bytes);
}
