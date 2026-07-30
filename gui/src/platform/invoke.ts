import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { isTauri } from "./isTauri";
import { webInvoke } from "./webApi";

/** Drop-in replacement for @tauri-apps/api/core's invoke(): Tauri IPC inside
 * the desktop app, REST calls against src/api.rs when running as a browser
 * WebUI. This is the only import app.ts needs to change to gain WebUI support. */
export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return isTauri() ? tauriInvoke<T>(cmd, args) : webInvoke<T>(cmd, args ?? {});
}
