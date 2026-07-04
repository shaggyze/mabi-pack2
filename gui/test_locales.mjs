import { readFileSync, writeFileSync } from 'fs';

// simple script to parse locales.ts and test the keys
const content = readFileSync('./src/locales.ts', 'utf-8');

// A bit of a hacky way to extract the object without full TS parsing
const match = content.match(/export const locales:\s*Record<string,\s*any>\s*=\s*([\s\S]+);$/);
if (!match) {
    console.error("Could not parse locales.ts");
    process.exit(1);
}

// Convert the object literal to JSON-like string (requires care with unquoted keys)
let objStr = match[1];
// This is risky, let's use a simpler eval approach since it's just a test script
const testScript = "
    ${content.replace(/export const locales.*=/, 'const locales =')}
    
    import fs from 'fs';
    
    let log = \"=== LANGUAGE TEST LOG ===\\n\";
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
        log += \"RESULT: SUCCESS. All languages are fully populated.\\n\";
    } else {
        log += \"RESULT: FAILURE. Missing translations detected.\\n\";
    }
    
    fs.writeFileSync('language_test.log', log);
    console.log(\"Log written to language_test.log\");
";

writeFileSync('run_test.js', testScript);
