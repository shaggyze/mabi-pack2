/** True when running inside the Tauri desktop shell, false in a plain browser (WebUI). */
export function isTauri(): boolean {
  return (
    typeof window !== "undefined" &&
    ((window as any).__TAURI_INTERNALS__ !== undefined || (window as any).__TAURI__ !== undefined)
  );
}
