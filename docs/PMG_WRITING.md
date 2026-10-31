# Native PMG round-trip documents

`gui/src/preview3d/pmgDocument.ts` exports the native save foundation shared with
`web-live/server/pmg-document.ts`. Nothing in the desktop app imports it yet; the
website's Community Mods packager is its first planned user. A 3.0 mesh block
whose geometry does not parse stays opaque: it is preserved and cannot be edited.
The rendering parser intentionally extracts only useful model fields. A native
save must also retain the fields it does not understand, so `PmgDocument` owns
the original header, each declared mesh block, and the file trailer separately.

```ts
import { PmgDocument } from './pmgDocument';

const document = PmgDocument.parse(originalBytes);
const nativeBytes = document.toBytes();
```

No-op output is byte-identical to the input. Input and output arrays are owned
independently, so changing either array does not alter a later save. The block
inventory exposes original group/LOD indices, submesh versions and lengths.
For versions 1.7, 2.0 and 3.0 it also exposes validated geometry counts and
vertex/skin offsets. Unsupported mesh versions remain opaque and are preserved.

The document rejects invalid signatures, negative or out-of-range lengths,
truncated declared blocks/geometry, and indices outside the vertex array. It
preserves unknown header bytes, physics/morph tails, original string encodings,
floating-point bit patterns and any file trailer. It does not reconstruct a
PMG from OBJ or from merged/transformed rendering geometry.

The document API supports preservation and inspection. The separate
`web-live/server/pmg-edits.ts` module adds transactional vertex RGBA and native UV
edits on a new document. It writes only the requested 4-byte color and/or 8-byte
UV fields in an existing 36-byte vertex. Color input is RGBA and native storage
is BGRA. UV coordinates are native values without an export-time V inversion.
Mesh/vertex indices and channel/float ranges are checked before any patch is
applied; rejected batches leave the source intact. Unsupported block versions
remain preserved but cannot be selected for editing.

Planned, in the website source outside this repository: the PMG upload form exposes mesh/LOD and vertex selection, color/UV
fields, Undo, Restore Original and Use edited PMG for upload. Undo history stores
small attribute patches rather than whole file copies. The uploaded package
contains the edited native bytes at the user's original game path.

Position, normal and topology edits require further validation of native bounds,
LODs, skin and morph relationships. Byte preservation and native re-parsing do
not demonstrate in-game compatibility for edited models or visual correctness
of the current renderer.

Run from the repository root, using the existing frontend dependencies:

```sh
node tests/pmg_roundtrip_checks.mjs
node tests/pmg_roundtrip_checks.mjs path/to/original.pmg
node tests/pmg_edit_checks.mjs path/to/original.pmg
```

The tests exercise synthetic 1.7/2.0/3.0 blocks, unknown versions, multiple LODs,
opaque records, malformed inputs and buffer ownership. Optional native files
are checked byte-for-byte and independently re-parsed through the existing
viewer parser. Original game assets are not distributed with the tests.

Original version-2.0 models checked during implementation: Nao (48 blocks,
1,686 vertices, 701 skin records), Dark Knight two-handed sword (6 blocks),
Tir Chonaill windmill (18 blocks), and waterfall soundbox (1 block). All four
round trips were byte-identical, with equal parsed model data.

Attribute-edit tests compare all output bytes against an allowlist of selected
vertex fields and independently decode the saved file. Inverse edits restore
the original bytes exactly. Nao's 48 blocks and the windmill's 18 blocks passed
these tests, including skin/material/topology preservation. The authenticated
browser flow also verifies that the actual edited upload changes only the
selected vertex bytes and that extracting its generated IT archive returns
the same edited PMG.
