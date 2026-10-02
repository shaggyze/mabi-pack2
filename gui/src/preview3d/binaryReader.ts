// Little-endian reader shared by the PMG and GM parsers (ported from the website preview).
const utf16 = new TextDecoder("utf-16le");
const utf8 = new TextDecoder("utf-8");

export class BinaryReader {
    readonly dv: DataView;
    readonly u8: Uint8Array;
    readonly len: number;
    pos = 0;

    constructor(bytes: Uint8Array) {
        this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        this.u8 = bytes;
        this.len = bytes.byteLength;
    }

    get remaining(): number { return this.len - this.pos; }

    i16(): number { const v = this.dv.getInt16(this.pos, true); this.pos += 2; return v; }
    u16(): number { const v = this.dv.getUint16(this.pos, true); this.pos += 2; return v; }
    i32(): number { const v = this.dv.getInt32(this.pos, true); this.pos += 4; return v; }
    u32(): number { const v = this.dv.getUint32(this.pos, true); this.pos += 4; return v; }
    f32(): number { const v = this.dv.getFloat32(this.pos, true); this.pos += 4; return v; }
    byte(): number { return this.dv.getUint8(this.pos++); }

    bytes(n: number): Uint8Array {
        const start = this.pos;
        this.pos += n;
        if (this.pos > this.len) throw new RangeError("read past end of buffer");
        return this.u8.subarray(start, start + n);
    }

    floats(n: number): number[] {
        const out = new Array<number>(n);
        for (let i = 0; i < n; i++) out[i] = this.f32();
        return out;
    }

    /** Fixed-size UTF-8 field, cut at the first NUL. */
    strFixed(n: number): string {
        const s = utf8.decode(this.bytes(n));
        const nul = s.indexOf("\0");
        return nul >= 0 ? s.slice(0, nul) : s;
    }

    /** i32 length-prefixed string. */
    lpStr(): string {
        const n = this.i32();
        return n <= 0 ? "" : this.strFixed(n);
    }

    /** NUL-terminated UTF-16LE string. */
    wstr(): string {
        const start = this.pos;
        let n = 0;
        while (this.pos < this.len - 1) {
            const c = this.dv.getInt16(this.pos, true);
            this.pos += 2;
            if (c === 0) break;
            n += 2;
        }
        return utf16.decode(this.u8.subarray(start, start + n));
    }
}
