// Run with node tests/pmg_roundtrip_checks.mjs [native.pmg ...].
// Uses the frontend's existing esbuild dependency; no dependency installation.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),esbuild=require('../gui/node_modules/esbuild/lib/main.js');
const bundle=esbuild.buildSync({entryPoints:['gui/src/preview3d/pmgDocument.ts'],bundle:true,format:'esm',write:false}).outputFiles[0].text;
const {PmgDocument}=await import('data:text/javascript;base64,'+Buffer.from(bundle).toString('base64'));
const parser=esbuild.buildSync({entryPoints:['gui/src/preview3d/pmg.ts'],bundle:true,format:'esm',write:false}).outputFiles[0].text;
const {parsePmg}=await import('data:text/javascript;base64,'+Buffer.from(parser).toString('base64'));

export function fixture(versions){
 const parts=[];const i32=value=>{const b=Buffer.alloc(4);b.writeInt32LE(value);return b;};
 for(const [major,minor] of versions){
  if(major===9){const opaque=Buffer.from('pm!\0\x09\x01\0\0\0\0opaque');opaque.writeInt32LE(opaque.length,6);parts.push(opaque);continue;}
  const bytes=[],zeros=n=>bytes.push(Buffer.alloc(n)),int=n=>bytes.push(i32(n));
  if(major===1)zeros(288);
  // Nonzero matrices, reserved fields, skin records and extra tail ensure the
  // round trip exercises data that a rendering-only reconstruction would drop.
  const matrices=Buffer.alloc(128);for(let p=0;p<128;p+=4)matrices.writeFloatLE(p%20===0?1:0,p);bytes.push(matrices);
  zeros(12);if(major===1)zeros(32);zeros(40);
  for(const value of [3,1,3,1,3,1])int(value);
  bytes.push(Buffer.alloc(56,0x5a));
  if(major!==1)for(let i=0;i<(major===3?8:7);i++){const name=Buffer.from('native-name-'+i+'\0');int(name.length);bytes.push(name);}
  zeros(64);
  const indices=Buffer.alloc(12);[0,1,2,2,1,0].forEach((v,i)=>indices.writeUInt16LE(v,i*2));bytes.push(indices);
  const vertices=Buffer.alloc(108);for(let i=0;i<3;i++){
   vertices.writeFloatLE(i*10+1,i*36);vertices.writeFloatLE(i*10+2,i*36+4);vertices.writeFloatLE(i*10+3,i*36+8);
   vertices.writeFloatLE(1,i*36+20);vertices.set([17,29,91,255],i*36+24);vertices.writeFloatLE(.25,i*36+28);vertices.writeFloatLE(.75,i*36+32);
  }bytes.push(vertices,Buffer.from('0123456789abcdef'),Buffer.from('opaque-physics-morph-tail'));
  const body=Buffer.concat(bytes),head=Buffer.from([0x70,0x6d,0x21,0,major,minor,0,0,0,0]);head.writeInt32LE(body.length+10,6);parts.push(Buffer.concat([head,body]));
 }
 const header=Buffer.alloc(142+68+204*parts.length,0x37);header.set([0x70,0x6d,0x67,0,2,1]);header.writeInt32LE(header.length,6);header.writeInt32LE(1,138);header.writeInt32LE(parts.length,206);
 for(let i=0;i<parts.length;i++)header.writeInt32LE(parts[i].length,210+i*204);
 return Buffer.concat([header,...parts,Buffer.from('native-file-tail')]);
}

const native=fixture([[1,7],[2,0],[3,0],[9,1]]),input=new Uint8Array(native),doc=PmgDocument.parse(input);
assert.equal(doc.blocks.length,4);assert.equal(doc.trailingByteLength,16);
assert.deepEqual(Buffer.from(doc.toBytes()),native);
for(const block of doc.blocks.slice(0,3))assert.deepEqual({...block.geometry}, {
 vertices:3,triangleIndices:3,stripIndices:3,skinRecords:1,
 vertexOffset:block.geometry.vertexOffset,skinOffset:block.geometry.vertexOffset+108,trailingBytes:25,
});
assert.equal(doc.blocks[3].geometry,undefined);
assert.deepEqual(doc.blocks.slice(0,3).map(b=>b.geometry.vertexOffset),[666,472,490]);
const before=parsePmg(native),after=parsePmg(doc.toBytes());assert.deepEqual(after,before);assert.equal(after.submeshes.length,3);
assert(after.submeshes.every(s=>s.vertices.length===3&&s.skins.length===1));
for(const mesh of after.submeshes){
 assert.deepEqual(mesh.vertices.map(v=>[v.x,v.y,v.z]),[[1,2,3],[11,12,13],[21,22,23]]);
 assert.deepEqual(mesh.faceIndices,[0,1,2]);assert.deepEqual(mesh.stripIndices,[2,1,0]);
 assert.equal(mesh.vertices[0].r,91);assert.equal(mesh.vertices[0].u,.25);
}
input.fill(0);assert.deepEqual(Buffer.from(doc.toBytes()),native);
doc.toBytes().fill(0);assert.deepEqual(Buffer.from(doc.toBytes()),native);
assert.throws(()=>doc.blocks.push({}),TypeError);
assert.throws(()=>{doc.blocks[0].geometry.vertices=999;},TypeError);
// Typed-array views must not accidentally serialize their surrounding buffer.
const padded=Buffer.concat([Buffer.alloc(13),native,Buffer.alloc(11)]);
assert.deepEqual(Buffer.from(PmgDocument.parse(padded.subarray(13,-11)).toBytes()),native);

function rejects(change){const bad=Buffer.from(native);change(bad);assert.throws(()=>PmgDocument.parse(bad),/Invalid PMG document/);}
rejects(b=>b[3]=1);rejects(b=>b.writeInt32LE(-1,6));rejects(b=>b.writeInt32LE(b.length+1,6));
rejects(b=>b.writeInt32LE(-1,138));rejects(b=>b.writeInt32LE(0x7fffffff,206));
const start=native.readInt32LE(6);
rejects(b=>b[start]=0);rejects(b=>b.writeInt32LE(9,start+6));rejects(b=>b.writeInt32LE(0x7fffffff,start+6));
rejects(b=>b.writeInt32LE(-1,start+10+288+128+12+32+40));
rejects(b=>b.writeUInt16LE(3,start+doc.blocks[0].geometry.vertexOffset-12));
// A mesh truncated before its declared end must fail even if its header is valid.
assert.throws(()=>PmgDocument.parse(native.subarray(0,start+12)),/Invalid PMG document/);
const lpStart=start+doc.blocks[0].byteLength;
rejects(b=>b.writeInt32LE(-1,lpStart+10+128+12+40+24+56));
console.log('PASS PMG 1.7/2.0/3.0 round trip, opaque blocks/tails, skin/material retention, ownership and malformed input');

for(const file of process.argv.slice(2)){
 const bytes=new Uint8Array(fs.readFileSync(file)),document=PmgDocument.parse(bytes),output=document.toBytes();
 assert.deepEqual(output,bytes);
 const original=parsePmg(bytes),written=parsePmg(output);assert.deepEqual(written,original);
 assert(document.blocks.length>0);assert(original.submeshes.length>0);
 console.log(JSON.stringify({file,bytes:bytes.length,blocks:document.blocks.length,versions:document.blocks.map(b=>b.version.join('.')),vertices:original.submeshes.reduce((n,s)=>n+s.vertices.length,0),skins:original.submeshes.reduce((n,s)=>n+s.skins.length,0),byteIdentical:true}));
}
