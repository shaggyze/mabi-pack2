import {
  open as tauriOpen,
  save as tauriSave,
  ask as tauriAsk,
  message as tauriMessage,
} from "@tauri-apps/plugin-dialog";
import { isTauri } from "./isTauri";

// Browser WebUI fallback for native file dialogs: the REST backend operates
// on *server-local* file paths (it's a local process with full filesystem
// access, same as the Tauri app), which a browser's File System Access API
// cannot produce (it hands back opaque file handles, not paths). So instead
// of a native picker, fall back to asking the user to type the path — this
// keeps the same "string path in/out" contract the rest of app.ts expects.

type OpenOptions = Parameters<typeof tauriOpen>[0];
type SaveOptions = Parameters<typeof tauriSave>[0];
type AskOptions = Parameters<typeof tauriAsk>[1];
type MessageOptions = Parameters<typeof tauriMessage>[1];

export async function open(options?: OpenOptions): Promise<string | string[] | null> {
  if (isTauri()) return tauriOpen(options);
  const title = (options as any)?.title ?? "Enter a path";
  const result = window.prompt(title);
  return result && result.trim() ? result.trim() : null;
}

export async function save(options?: SaveOptions): Promise<string | null> {
  if (isTauri()) return tauriSave(options);
  const defaultPath = (options as any)?.defaultPath ?? "";
  const result = window.prompt("Enter output path", defaultPath);
  return result && result.trim() ? result.trim() : null;
}

export async function ask(message: string, options?: AskOptions): Promise<boolean> {
  if (isTauri()) return tauriAsk(message, options);
  const title = (options as any)?.title;
  return window.confirm(title ? `${title}\n\n${message}` : message);
}

export async function message(message: string, options?: MessageOptions): Promise<void> {
  if (isTauri()) { await tauriMessage(message, options); return; }
  const title = (options as any)?.title;
  window.alert(title ? `${title}\n\n${message}` : message);
}
