// DDS → RGBA decoder (DXT1/DXT3/DXT5 and uncompressed 16/24/32bpp), ported from the website preview.
// `accurate` rounds 565 expansion and palette blends instead of truncating.

export interface DecodedTexture {
    width: number;
    height: number;
    rgba: Uint8Array;
    hasAlpha: boolean;
}

const fourCC = (s: string) => s.charCodeAt(0) | (s.charCodeAt(1) << 8) | (s.charCodeAt(2) << 16) | (s.charCodeAt(3) << 24);
const DXT1 = fourCC("DXT1");
const DXT3 = fourCC("DXT3");
const DXT5 = fourCC("DXT5");
const DDS_MAGIC = 0x20534444;

function expand565(c: number, out: Uint8Array, accurate: boolean) {
    const r = (c >> 11) & 31, g = (c >> 5) & 63, b = c & 31;
    if (accurate) {
        out[0] = Math.round(r * 255 / 31); out[1] = Math.round(g * 255 / 63); out[2] = Math.round(b * 255 / 31);
    } else {
        out[0] = (r * 255 / 31) | 0; out[1] = (g * 255 / 63) | 0; out[2] = (b * 255 / 31) | 0;
    }
}

function decodeColorBlock(dv: DataView, off: number, out: Uint8Array, accurate: boolean, dxt1: boolean) {
    const c0 = dv.getUint16(off, true), c1 = dv.getUint16(off + 2, true), bits = dv.getUint32(off + 4, true);
    const pal = [new Uint8Array(3), new Uint8Array(3), new Uint8Array(3), new Uint8Array(3)];
    expand565(c0, pal[0], accurate);
    expand565(c1, pal[1], accurate);
    const punchThrough = dxt1 && c0 <= c1;
    const mix = accurate
        ? (a: number, b: number, wa: number, wb: number, d: number) => Math.round((a * wa + b * wb) / d)
        : (a: number, b: number, wa: number, wb: number, d: number) => ((a * wa + b * wb) / d) | 0;
    for (let k = 0; k < 3; k++) {
        if (punchThrough) {
            pal[2][k] = mix(pal[0][k], pal[1][k], 1, 1, 2);
            pal[3][k] = 0;
        } else {
            pal[2][k] = mix(pal[0][k], pal[1][k], 2, 1, 3);
            pal[3][k] = mix(pal[0][k], pal[1][k], 1, 2, 3);
        }
    }
    for (let p = 0; p < 16; p++) {
        const idx = (bits >>> (2 * p)) & 3;
        out[p * 4] = pal[idx][0]; out[p * 4 + 1] = pal[idx][1]; out[p * 4 + 2] = pal[idx][2];
        out[p * 4 + 3] = punchThrough && idx === 3 ? 0 : 255;
    }
}

function decodeDxt5Alpha(dv: DataView, off: number, out: Uint8Array) {
    const a0 = dv.getUint8(off), a1 = dv.getUint8(off + 1);
    const pal = [a0, a1, 0, 0, 0, 0, 0, 0];
    if (a0 > a1) {
        for (let i = 1; i < 7; i++) pal[i + 1] = (((7 - i) * a0 + i * a1) / 7) | 0;
    } else {
        for (let i = 1; i < 5; i++) pal[i + 1] = (((5 - i) * a0 + i * a1) / 5) | 0;
        pal[6] = 0; pal[7] = 255;
    }
    // 48 bits of 3-bit indices, read as two 24-bit halves (8 pixels each).
    for (let half = 0; half < 2; half++) {
        const b = off + 2 + half * 3;
        const bits = dv.getUint8(b) | (dv.getUint8(b + 1) << 8) | (dv.getUint8(b + 2) << 16);
        for (let p = 0; p < 8; p++) out[half * 8 + p] = pal[(bits >> (3 * p)) & 7];
    }
}

export function decodeDds(bytes: Uint8Array, accurate = false): DecodedTexture {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.byteLength < 128 || dv.getUint32(0, true) !== DDS_MAGIC) throw new Error("not a DDS");
    const height = dv.getUint32(12, true);
    const width = dv.getUint32(16, true);
    const pfFlags = dv.getUint32(80, true);
    const cc = dv.getUint32(84, true);
    const bpp = dv.getUint32(88, true);
    const rgba = new Uint8Array(width * height * 4);
    let off = 128;
    let hasAlpha = false;
    const compressed = (pfFlags & 4) !== 0;

    if (compressed && (cc === DXT1 || cc === DXT3 || cc === DXT5)) {
        const block = new Uint8Array(64);
        const alpha = new Uint8Array(16);
        for (let by = 0; by < height; by += 4) {
            for (let bx = 0; bx < width; bx += 4) {
                let explicitAlpha = false;
                if (cc === DXT3) {
                    for (let p = 0; p < 16; p++) alpha[p] = ((dv.getUint8(off + (p >> 1)) >> ((p & 1) * 4)) & 15) * 17;
                    off += 8; explicitAlpha = true; hasAlpha = true;
                } else if (cc === DXT5) {
                    decodeDxt5Alpha(dv, off, alpha);
                    off += 8; explicitAlpha = true; hasAlpha = true;
                }
                decodeColorBlock(dv, off, block, accurate, cc === DXT1);
                off += 8;
                for (let y = 0; y < 4; y++) {
                    for (let x = 0; x < 4; x++) {
                        const px = bx + x, py = by + y;
                        if (px >= width || py >= height) continue;
                        const s = (y * 4 + x) * 4, d = (py * width + px) * 4;
                        rgba[d] = block[s]; rgba[d + 1] = block[s + 1]; rgba[d + 2] = block[s + 2];
                        const a = explicitAlpha ? alpha[y * 4 + x] : block[s + 3];
                        if (a < 255) hasAlpha = true;
                        rgba[d + 3] = a;
                    }
                }
            }
        }
    } else if (!compressed && (bpp === 16 || bpp === 24 || bpp === 32)) {
        // Uncompressed: decode through the pixel-format channel masks (A8R8G8B8, X8R8G8B8,
        // R8G8B8, A4R4G4B4, A1R5G5B5, R5G6B5 …). Missing masks fall back to BGRA order.
        const bytesPer = bpp / 8;
        if (bytes.byteLength < off + width * height * bytesPer) throw new Error("truncated DDS");
        const alphaFlag = (pfFlags & 1) !== 0;
        let rMask = dv.getUint32(92, true), gMask = dv.getUint32(96, true), bMask = dv.getUint32(100, true);
        let aMask = alphaFlag || bpp === 32 ? dv.getUint32(104, true) : 0;
        if (!rMask && !gMask && !bMask) {
            rMask = 0xff0000; gMask = 0xff00; bMask = 0xff;
            aMask = bpp === 32 ? 0xff000000 : 0;
        }
        const channel = (mask: number) => {
            if (!mask) return null;
            let shift = 0;
            while (((mask >>> shift) & 1) === 0) shift++;
            const max = mask >>> shift;
            return (px: number) => Math.round((((px & mask) >>> shift) * 255) / max);
        };
        const rc = channel(rMask), gc = channel(gMask), bc = channel(bMask), ac = channel(aMask);
        for (let i = 0; i < width * height; i++) {
            const o = off + i * bytesPer;
            let px = bytes[o] | (bytes[o + 1] << 8);
            if (bytesPer >= 3) px |= bytes[o + 2] << 16;
            if (bytesPer === 4) px = (px | (bytes[o + 3] << 24)) >>> 0;
            const a = ac ? ac(px) : 255;
            rgba[i * 4] = rc ? rc(px) : 0;
            rgba[i * 4 + 1] = gc ? gc(px) : 0;
            rgba[i * 4 + 2] = bc ? bc(px) : 0;
            rgba[i * 4 + 3] = a;
            if (a < 255) hasAlpha = true;
        }
    } else {
        throw new Error(`unsupported DDS format (fourCC=0x${cc.toString(16)}, bpp=${bpp})`);
    }
    return { width, height, rgba, hasAlpha };
}
