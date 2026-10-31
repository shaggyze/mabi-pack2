import assert from 'node:assert/strict';import fs from 'node:fs';import {createRequire} from 'node:module';
import {fixture} from './pmg_roundtrip_checks.mjs';
const require=createRequire(import.meta.url),esbuild=require('../gui/node_modules/esbuild/lib/main.js');
const load=async entry=>import('data:text/javascript;base64,'+Buffer.from(esbuild.buildSync({entryPoints:[entry],bundle:true,format:'esm',write:false}).outputFiles[0].text).toString('base64'));
const {PmgDocument}=await load('web-live/server/pmg-document.ts'),{readPmgVertex,editPmgVertices}=await load('web-live/server/pmg-edits.ts'),{parsePmg}=await load('gui/src/preview3d/pmg.ts');
function permittedOffsets(bytes,document,edits){
 const allowed=new Set();for(const edit of edits){let offset=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getInt32(6,true);for(let i=0;i<edit.block;i++)offset+=document.blocks[i].byteLength;offset+=document.blocks[edit.block].geometry.vertexOffset+edit.vertex*36;
  if(edit.color)for(let i=24;i<28;i++)allowed.add(offset+i);if(edit.uv)for(let i=28;i<36;i++)allowed.add(offset+i);
 }return allowed;
}
function verify(bytes){
 const document=PmgDocument.parse(bytes),blocks=document.blocks.filter(b=>b.geometry?.vertices>0);assert(blocks.length);
 const edits=blocks.map(block=>({block:block.index,vertex:block.geometry.vertices-1,color:[10,20,30,40],uv:[-.25,1.5]}));
 const original=bytes.slice(),written=editPmgVertices(document,edits),output=written.toBytes();assert.equal(output.length,bytes.length);assert.deepEqual(document.toBytes(),original);
 const allowed=permittedOffsets(bytes,document,edits);let changed=0;
 for(let i=0;i<bytes.length;i++)if(bytes[i]!==output[i]){assert(allowed.has(i),'Unexpected byte changed at '+i);changed++;}
 assert(changed>0);const before=parsePmg(bytes),after=parsePmg(output);assert.equal(before.submeshes.length,after.submeshes.length);
 for(const edit of edits){const values=readPmgVertex(written,edit.block,edit.vertex),old=readPmgVertex(document,edit.block,edit.vertex);assert.deepEqual(values.color,edit.color);assert.deepEqual(values.uv,edit.uv);assert.deepEqual(values.position,old.position);assert.deepEqual(values.normal,old.normal);}
 // Independently decoded skin records, matrices, indices, material metadata,
 // and every unedited vertex must match; remove only intended attributes.
 for(let i=0;i<before.submeshes.length;i++){
  const a=structuredClone(before.submeshes[i]),b=structuredClone(after.submeshes[i]);
  const index=a.vertices.length-1;a.vertices[index].r=b.vertices[index].r;a.vertices[index].g=b.vertices[index].g;a.vertices[index].b=b.vertices[index].b;a.vertices[index].a=b.vertices[index].a;a.vertices[index].u=b.vertices[index].u;a.vertices[index].v=b.vertices[index].v;assert.deepEqual(b,a);
 }
 // Inverse edits restore the exact original bytes, not only render geometry.
 const inverse=edits.map(e=>{const v=readPmgVertex(document,e.block,e.vertex);return {block:e.block,vertex:e.vertex,color:v.color,uv:v.uv};});assert.deepEqual(editPmgVertices(written,inverse).toBytes(),bytes);
 return {blocks:blocks.length,changedBytes:changed,unchangedBytes:bytes.length-changed};
}
const bytes=new Uint8Array(fixture([[1,7],[2,0],[3,0],[9,1]])),document=PmgDocument.parse(bytes);verify(bytes);
const source=document.toBytes();
for(const edit of [
 {block:0,vertex:-1,color:[1,2,3,4]}, {block:0,vertex:.5,color:[1,2,3,4]}, {block:0,vertex:3,color:[1,2,3,4]},
 {block:3,vertex:0,color:[1,2,3,4]}, {block:4,vertex:0,color:[1,2,3,4]},
 {block:0,vertex:0,color:[256,2,3,4]}, {block:0,vertex:0,color:[1.5,2,3,4]}, {block:0,vertex:0,color:[1,2,3]},
 {block:0,vertex:0,uv:[Infinity,1]}, {block:0,vertex:0,uv:[NaN,1]}, {block:0,vertex:0,uv:[1e100,1]},
 {block:0,vertex:0,position:[1,2,3]}, {block:0,vertex:0},
]){assert.throws(()=>editPmgVertices(document,[{block:1,vertex:1,color:[1,2,3,4]},edit]));assert.deepEqual(document.toBytes(),source);}
assert.throws(()=>editPmgVertices(document,[{block:0,vertex:0,color:[1,2,3,4]},{block:0,vertex:0,uv:[1,2]}]));
assert.deepEqual(editPmgVertices(document,[]).toBytes(),source);
const colorOnly=editPmgVertices(document,[{block:0,vertex:0,color:[1,2,3,4]}]);assert.deepEqual(readPmgVertex(colorOnly,0,0).uv,readPmgVertex(document,0,0).uv);
const uvOnly=editPmgVertices(document,[{block:0,vertex:0,uv:[-0,2]}]);assert.deepEqual(readPmgVertex(uvOnly,0,0).color,readPmgVertex(document,0,0).color);assert(Object.is(readPmgVertex(uvOnly,0,0).uv[0],-0));
console.log('PASS native PMG RGBA/UV edits, exact byte boundaries, independent decode, inverse undo and atomic invalid-batch rejection');
for(const file of process.argv.slice(2)){const result=verify(new Uint8Array(fs.readFileSync(file)));console.log(JSON.stringify({file,...result,passed:true}));}
