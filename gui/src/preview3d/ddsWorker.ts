// Decodes DDS textures off the UI thread.
import { decodeDds } from "./ddsDecode";

self.onmessage = (e: MessageEvent<{ id: number; buf: ArrayBuffer; accurate: boolean }>) => {
    const { id, buf, accurate } = e.data;
    try {
        const t = decodeDds(new Uint8Array(buf), accurate);
        (self as unknown as Worker).postMessage(
            { id, ok: true, width: t.width, height: t.height, rgba: t.rgba.buffer, hasAlpha: t.hasAlpha },
            [t.rgba.buffer],
        );
    } catch (err) {
        (self as unknown as Worker).postMessage({ id, ok: false, error: String(err) });
    }
};
