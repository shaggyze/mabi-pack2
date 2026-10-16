// Checks the GUI translations. Exits 1 when:
//   - a key in the en locale is missing from tw, ja or ko (or the other way round);
//   - gui/index.html uses a data-i18n or data-i18n-placeholder key that en lacks;
//   - gui/src/app.ts calls this.t("key") with a key that en lacks.
// Run from the repository root: node scripts/check-locales.mjs
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const gui = join(dirname(fileURLToPath(import.meta.url)), '..', 'gui');
const read = (p) => readFileSync(join(gui, p), 'utf-8');

// locales.ts is one object literal with only string values: evaluate it as JS.
const src = read('src/locales.ts');
const body = src.slice(src.indexOf('{', src.indexOf('export const locales')));
const locales = new Function(`return (${body.replace(/;\s*$/, '')});`)();

const langs = ['en', 'tw', 'ja', 'ko'];
const problems = [];
const en = new Set(Object.keys(locales.en ?? {}));
for (const lang of langs) {
    const keys = new Set(Object.keys(locales[lang] ?? {}));
    if (!locales[lang]) { problems.push(`locale ${lang} is missing`); continue; }
    const missing = [...en].filter((k) => !keys.has(k));
    const extra = [...keys].filter((k) => !en.has(k));
    if (missing.length) problems.push(`${lang} lacks ${missing.length} key(s): ${missing.join(', ')}`);
    if (extra.length) problems.push(`${lang} has ${extra.length} key(s) en lacks: ${extra.join(', ')}`);
}

const used = (text, re) => [...text.matchAll(re)].map((m) => m[1]);
const html = read('index.html');
const app = read('src/app.ts');
const refs = [
    ...used(html, /data-i18n="([^"]+)"/g).map((k) => ['index.html data-i18n', k]),
    ...used(html, /data-i18n-placeholder="([^"]+)"/g).map((k) => ['index.html data-i18n-placeholder', k]),
    ...used(app, /this\.t\(\s*["']([A-Za-z0-9_]+)["']/g).map((k) => ['app.ts this.t()', k]),
];
const unknown = new Map();
for (const [where, key] of refs) if (!en.has(key)) unknown.set(`${where}: ${key}`, true);
for (const k of unknown.keys()) problems.push(`unknown key in ${k}`);

if (problems.length) {
    console.error(`check-locales: ${problems.length} problem(s)`);
    for (const p of problems) console.error(`  ${p}`);
    process.exit(1);
}
console.log(`check-locales: ${en.size} keys in ${langs.length} locales, ${refs.length} references, all present.`);
