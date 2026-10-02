// Worker-pool DDS decoding with an in-memory cache, as on the website preview.
import { decodeDds, type DecodedTexture } from "./ddsDecode";

interface Job { id: number; buf: ArrayBuffer; accurate: boolean }

let workers: Worker[] | null = null;
const idle: Worker[] = [];
const queue: Job[] = [];
const pending = new Map<number, (t: DecodedTexture | null) => void>();
const busy = new Map<Worker, number>();
let nextId = 1;

function startPool() {
    if (workers !== null) return;
    workers = [];
    try {
        const n = Math.max(2, Math.min((navigator.hardwareConcurrency || 4) - 1, 8));
        for (let i = 0; i < n; i++) {
            const w = new Worker(new URL("./ddsWorker.ts", import.meta.url), { type: "module" });
            w.onmessage = (e: MessageEvent) => {
                const { id, ok, width, height, rgba, hasAlpha } = e.data;
                busy.delete(w);
                const done = pending.get(id);
                pending.delete(id);
                done?.(ok ? { width, height, rgba: new Uint8Array(rgba), hasAlpha } : null);
                idle.push(w);
                pump();
            };
            // A worker that fails to load or crashes drops out of the pool; its job resolves to null.
            w.onerror = () => {
                const id = busy.get(w);
                busy.delete(w);
                if (id !== undefined) { pending.get(id)?.(null); pending.delete(id); }
                const i = idle.indexOf(w);
                if (i >= 0) idle.splice(i, 1);
                workers = workers!.filter(x => x !== w);
                w.terminate();
                if (!workers.length) for (const job of queue.splice(0)) { pending.get(job.id)?.(null); pending.delete(job.id); }
                else pump();
            };
            workers.push(w);
            idle.push(w);
        }
    } catch {
        workers = [];
    }
}

function pump() {
    while (idle.length && queue.length) {
        const w = idle.pop()!;
        const job = queue.shift()!;
        busy.set(w, job.id);
        w.postMessage(job, [job.buf]);
    }
}

export function decodeDdsAsync(bytes: Uint8Array, accurate = false): Promise<DecodedTexture | null> {
    startPool();
    if (!workers || workers.length === 0) {
        try { return Promise.resolve(decodeDds(bytes, accurate)); } catch { return Promise.resolve(null); }
    }
    return new Promise(resolve => {
        const id = nextId++;
        pending.set(id, resolve);
        const whole = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
        const buf = (whole ? bytes.buffer : bytes.slice().buffer) as ArrayBuffer;
        queue.push({ id, buf, accurate });
        pump();
    });
}

// Decoded textures kept for re-use, least recently used evicted past CACHE_BYTES.
const cache = new Map<string, Promise<DecodedTexture | null>>();
const sizes = new Map<string, number>();
const CACHE_BYTES = 256 * 1024 * 1024;
let cachedBytes = 0;

function evict() {
    for (const k of cache.keys()) {
        if (cachedBytes <= CACHE_BYTES) break;
        const n = sizes.get(k);
        if (n === undefined) continue; // still loading
        cache.delete(k);
        sizes.delete(k);
        cachedBytes -= n;
    }
}

/** Loads and decodes a texture once per key; `load` supplies the DDS bytes. Failures are not cached. */
export function cachedTexture(key: string, accurate: boolean, load: () => Promise<Uint8Array | null>): Promise<DecodedTexture | null> {
    const k = `${key}|${accurate ? "a" : "f"}`;
    const hit = cache.get(k);
    if (hit) {
        cache.delete(k);
        cache.set(k, hit); // refresh recency
        return hit;
    }
    const p = (async () => {
        try {
            const bytes = await load();
            return bytes ? await decodeDdsAsync(bytes, accurate) : null;
        } catch {
            return null;
        }
    })();
    cache.set(k, p);
    p.then(t => {
        if (cache.get(k) !== p) return;
        if (!t) { cache.delete(k); return; }
        sizes.set(k, t.rgba.byteLength);
        cachedBytes += t.rgba.byteLength;
        evict();
    });
    return p;
}
