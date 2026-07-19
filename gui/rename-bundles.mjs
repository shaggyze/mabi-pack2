import { existsSync, mkdirSync, readdirSync, renameSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const releaseDir = join(__dirname, 'src-tauri', 'target', 'release');
const nsisDir = join(releaseDir, 'bundle', 'nsis');
const msiDir  = join(releaseDir, 'bundle', 'msi');

if (!existsSync(nsisDir) && !existsSync(msiDir)) process.exit(0);

const outDir = join(releaseDir, 'release');
if (!existsSync(outDir)) mkdirSync(outDir);

for (const f of readdirSync(nsisDir).filter(f => f.endsWith('.exe')))
    renameSync(join(nsisDir, f), join(outDir, 'mabi-pack2-setup.exe'));

for (const f of readdirSync(msiDir).filter(f => f.endsWith('.msi')))
    renameSync(join(msiDir, f), join(outDir, 'mabi-pack2-setup.msi'));
