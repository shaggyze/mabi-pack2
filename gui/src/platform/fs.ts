import { writeTextFile as tauriWriteTextFile } from "@tauri-apps/plugin-fs";
import { isTauri } from "./isTauri";

/** Drop-in replacement for @tauri-apps/plugin-fs's writeTextFile(). The
 * browser has no arbitrary local filesystem write access, so this falls
 * back to triggering a normal browser download of the content instead —
 * the user ends up with the same file, just in their Downloads folder
 * rather than at the exact path the desktop app would have used. */
export async function writeTextFile(path: string, contents: string): Promise<void> {
  if (isTauri()) return tauriWriteTextFile(path, contents);

  const filename = path.split(/[\\/]/).pop() || "download.txt";
  const blob = new Blob([contents], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
