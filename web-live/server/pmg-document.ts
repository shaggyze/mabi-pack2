/** Shared lossless native PMG document. Unlike the rendering parser, this retains
 * unknown versions, header fields, physics/morph data and trailing bytes.
 * Geometry/topology editing is deliberately outside this round-trip API.
 */
export interface PmgBlockInfo {
    readonly index: number;
    readonly group: number;
    readonly lod: number;
    readonly version: readonly [number, number];
    readonly byteLength: number;
    /** Absent for opaque, unsupported submesh versions. */
    readonly geometry?: Readonly<{
        vertices: number;
        triangleIndices: number;
        stripIndices: number;
        skinRecords: number;
        /** Offset within the complete mesh block, including its 10-byte header. */
        vertexOffset: number;
        skinOffset: number;
        trailingBytes: number;
    }>;
}

function invalid(message: string): never {
    throw new Error(`Invalid PMG document: ${message}`);
}

class Reader {
    offset = 0;
    readonly view: DataView;
    constructor(readonly bytes: Uint8Array) {
        this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    }
    skip(length: number): void {
        if (!Number.isSafeInteger(length) || length < 0 || length > this.bytes.length - this.offset) {
            invalid('truncated data');
        }
        this.offset += length;
    }
    count(): number {
        this.skip(4);
        const value = this.view.getInt32(this.offset - 4, true);
        if (value < 0) invalid('negative length or count');
        return value;
    }
    string(): void { this.skip(this.count()); }
}

function geometryInfo(block: Uint8Array, major: number, minor: number): PmgBlockInfo['geometry'] {
    if (!((major === 1 && minor === 7) || (major === 2 && minor === 0) || (major === 3 && minor === 0))) return;
    const r = new Reader(block);
    r.skip(10);
    if (major === 1) r.skip(288); // Six fixed strings: 32 + 128 + 4*32.
    r.skip(128 + 12); // Two matrices, part index and eight reserved bytes.
    if (major === 1) r.skip(32); // Fixed texture name.
    r.skip(40); // Texture mapping flag and reserved fields.
    const triangleIndices = r.count(); r.count();
    const stripIndices = r.count(); r.count();
    const vertices = r.count(), skinRecords = r.count();
    r.skip(56); // Physics/morph fields, sizes and reserved value.
    if (major !== 1) for (let i = 0; i < (major === 3 ? 8 : 7); i++) r.string();
    r.skip(64); // Unknown size and fifteen floats.
    const indexOffset = r.offset;
    r.skip((triangleIndices + stripIndices) * 2);
    const vertexOffset = r.offset;
    r.skip(vertices * 36);
    const skinOffset = r.offset;
    r.skip(skinRecords * 16);
    // Bad indices must not be silently accepted by a native save path.
    for (let p = indexOffset; p < vertexOffset; p += 2) {
        if (r.view.getUint16(p, true) >= vertices) invalid('mesh index outside vertex array');
    }
    return Object.freeze({ vertices, triangleIndices, stripIndices, skinRecords,
        vertexOffset, skinOffset, trailingBytes: block.length - r.offset });
}

export class PmgDocument {
    readonly blocks: readonly PmgBlockInfo[];
    readonly version: readonly [number, number];
    readonly byteLength: number;
    readonly trailingByteLength: number;
    private constructor(
        private readonly header: Uint8Array,
        private readonly meshBlocks: readonly Uint8Array[],
        private readonly trailer: Uint8Array,
        blocks: PmgBlockInfo[],
        version: [number, number],
    ) {
        this.blocks = Object.freeze(blocks);
        this.version = Object.freeze(version);
        this.trailingByteLength = trailer.length;
        this.byteLength = header.length + meshBlocks.reduce((n, b) => n + b.length, 0) + trailer.length;
    }

    static parse(input: Uint8Array): PmgDocument {
        // Own the bytes: caller changes must not mutate a pending save.
        const bytes = input.slice(), r = new Reader(bytes);
        r.skip(142);
        if (bytes[0] !== 0x70 || bytes[1] !== 0x6d || bytes[2] !== 0x67 || bytes[3] !== 0) invalid('signature');
        const headSize = r.view.getInt32(6, true), groupCount = r.view.getInt32(138, true);
        if (headSize < 142 || headSize > bytes.length || groupCount < 0 || groupCount > (headSize - 142) / 68) invalid('header size or group count');
        const headerReader = new Reader(bytes.subarray(0, headSize));
        headerReader.offset = 142;
        const counts: number[] = [];
        for (let group = 0; group < groupCount; group++) {
            headerReader.skip(64);
            const count = headerReader.count();
            headerReader.skip(count * 204);
            counts.push(count);
        }
        r.offset = headSize;
        const meshBlocks: Uint8Array[] = [], blocks: PmgBlockInfo[] = [];
        for (let group = 0; group < counts.length; group++) for (let lod = 0; lod < counts[group]; lod++) {
            const start = r.offset;
            r.skip(10);
            if (bytes[start] !== 0x70 || bytes[start + 1] !== 0x6d || bytes[start + 2] !== 0x21 || bytes[start + 3] !== 0) invalid('mesh signature');
            const size = r.view.getInt32(start + 6, true);
            if (size < 10) invalid('mesh block length');
            r.skip(size - 10);
            const block = bytes.slice(start, r.offset), major = block[4], minor = block[5];
            const version = Object.freeze([major, minor] as [number, number]);
            // The 3.0 layout is only checked on synthetic files: when it does not
            // parse, keep the block opaque (preserved, not editable).
            let geometry: PmgBlockInfo['geometry'];
            try { geometry = geometryInfo(block, major, minor); }
            catch (e) { if (major !== 3) throw e; }
            blocks.push(Object.freeze({ index: blocks.length, group, lod, version,
                byteLength: size, geometry }));
            meshBlocks.push(block);
        }
        return new PmgDocument(bytes.slice(0, headSize), meshBlocks, bytes.slice(r.offset), blocks, [bytes[4], bytes[5]]);
    }

    /** Serialize owned native sections without converting through render geometry.
     * No-op saves are byte-identical, including opaque versions and float bits.
     * The returned array is independent of the document and may be transferred.
     */
    toBytes(): Uint8Array {
        const output = new Uint8Array(this.byteLength);
        let offset = 0;
        for (const section of [this.header, ...this.meshBlocks, this.trailer]) {
            output.set(section, offset);
            offset += section.length;
        }
        return output;
    }
}
