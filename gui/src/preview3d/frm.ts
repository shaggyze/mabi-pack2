import { BinaryReader } from "./binaryReader";

export interface FrmBone {
    id: number;
    parentId: number;
    localMatrix: number[];
    globalMatrix: number[];
    inverseGlobalMatrix: number[];
    name: string;
}

export interface FrmFile {
    version: number;
    bones: FrmBone[];
}

export function parseFrm(bytes: Uint8Array): FrmFile {
    const r = new BinaryReader(bytes);
    const magic = r.bytes(4);
    if (magic[0] !== 0x70 || magic[1] !== 0x66 || magic[2] !== 0x21 || magic[3] !== 0x00) {
        throw new Error("Not a valid FRM file (missing pf! magic)");
    }

    const version = r.u16();
    const boneCount = r.u32();

    const bones: FrmBone[] = [];
    for (let i = 0; i < boneCount; i++) {
        if (r.remaining < 260) break;
        
        const id = r.i32();
        const parentId = r.i32();
        r.i32(); // unknown/padding
        
        const localMatrix = r.floats(16);
        const globalMatrix = r.floats(16);
        const inverseGlobalMatrix = r.floats(16);
        
        const name = r.strFixed(56);
        
        bones.push({
            id,
            parentId,
            localMatrix,
            globalMatrix,
            inverseGlobalMatrix,
            name
        });
    }

    return { version, bones };
}
