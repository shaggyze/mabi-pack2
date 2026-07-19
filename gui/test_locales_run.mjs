import fs from 'fs';

// Read locales.ts
const content = fs.readFileSync('src/locales.ts', 'utf-8');

// Strip the export const locales: any = { part
const jsonStr = content.replace(/export const locales:\s*any\s*=\s*/, '').replace(/export const locales:\s*Record<string,\s*any>\s*=\s*/, '');

// Evaluate the object
let locales;
eval(`locales = ${jsonStr}`);

let log = "=== LANGUAGE TEST LOG ===\n\n";
const langs = ['en', 'tw', 'ja', 'ko'];
const baseKeys = Object.keys(locales['en']);

log += `Total keys in English: ${baseKeys.length}\n\n`;

let allGood = true;
for (const lang of langs) {
    log += `--- Testing Language: ${lang.toUpperCase()} ---\n`;
    if (!locales[lang]) {
        log += `ERROR: Missing language object for ${lang}\n`;
        allGood = false;
        continue;
    }
    const langKeys = Object.keys(locales[lang]);
    log += `Keys present: ${langKeys.length}\n`;
    
    let missing = [];
    for (const key of baseKeys) {
        if (!(key in locales[lang])) {
            missing.push(key);
        }
    }
    
    if (missing.length > 0) {
        log += `MISSING KEYS: ${missing.join(', ')}\n`;
        allGood = false;
    } else {
        log += `Status: ALL KEYS PRESENT.\n`;
    }
    
    // Sample a few translations to show they are different
    log += `Sample 'title': ${locales[lang].title}\n`;
    log += `Sample 'extract': ${locales[lang].extract}\n`;
    log += `Sample 'ready': ${locales[lang].ready}\n\n`;
}

if (allGood) {
    log += "RESULT: SUCCESS. All languages are fully populated.\n";
} else {
    log += "RESULT: FAILURE. Missing translations detected.\n";
}

fs.writeFileSync('../language_test.log', log);
console.log("Log written to ../language_test.log");
