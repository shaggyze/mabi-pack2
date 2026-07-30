import { listen as tauriListen } from "@tauri-apps/api/event";
import { isTauri } from "./isTauri";

type UnlistenFn = () => void;

/** Drop-in replacement for @tauri-apps/api/event's listen(). In the browser
 * WebUI there's no Tauri event bus (progress/log-message/drag-drop events
 * never fire from a REST backend), so this resolves to a no-op unlisten
 * instead of rejecting — event subscriptions are best-effort UI polish
 * (live progress, log streaming), not required for any action to complete. */
export async function listen<T>(
  event: string,
  handler: (event: { event: string; payload: T }) => void
): Promise<UnlistenFn> {
  if (isTauri()) {
    return tauriListen(event, handler as any) as unknown as Promise<UnlistenFn>;
  }
  return () => {};
}
