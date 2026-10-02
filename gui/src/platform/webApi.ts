// REST-backed implementation of Tauri's invoke() surface, used when the app
// is running as a plain browser WebUI (via `mabi-patcher serve`) instead of
// inside the Tauri desktop shell. Maps the commands needed by the Dashboard,
// Extract, Pack, List, Mod Browser/Apply, Launcher, and Preview (image/text/
// PMG 3D/RGN/area/audio) surfaces onto the REST API in src/api.rs (see
// MISSION_CONTROL_PLAN.md Phases 2 and 5). Everything else (native file
// dialogs, registry/association editing, elevation, etc.) is
// desktop-only and throws a clear error — those actions are already wrapped
// in try/catch upstream in app.ts, so this degrades to "button does nothing"
// rather than a crash.

const API_BASE: string =
  (window as any).__MABI_API_BASE__ ?? (import.meta as any).env?.VITE_API_BASE ?? "";

type Args = Record<string, unknown>;

async function apiFetch<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let json: any = null;
  try { json = await res.json(); } catch { /* fall through to malformed-response error below */ }
  if (!json || typeof json.success !== "boolean") {
    throw new Error(`Malformed API response from ${path} (HTTP ${res.status})`);
  }
  if (!json.success) {
    const err: any = new Error(json.error ?? `Request to ${path} failed (HTTP ${res.status})`);
    err.status = res.status;
    throw err;
  }
  return json.data as T;
}

function unsupported(cmd: string): never {
  throw new Error(
    `"${cmd}" is a desktop-only feature and isn't available in the browser WebUI. ` +
    `Use the Antigravity/Tauri desktop app for this action.`
  );
}

// ── localStorage-backed config (no server-side concept of "this browser's settings") ──

const CONFIG_KEY = "mabi-patcher.webui.config";

function loadLocalConfig(): Record<string, unknown> {
  try {
    const raw = localStorage.getItem(CONFIG_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveLocalConfig(config: Record<string, unknown>) {
  try { localStorage.setItem(CONFIG_KEY, JSON.stringify(config)); } catch { /* storage disabled/full — non-fatal */ }
}

// ── pure client-side port of the Tauri `detect_data_prefix` string logic ──
// (see gui/src-tauri/src/lib.rs — it does no filesystem I/O, just path matching)

function detectDataPrefix(path: string): string | null {
  const normalized = path.replace(/\//g, "\\");
  const lower = normalized.toLowerCase();
  const idx = lower.indexOf("\\data\\");
  if (idx !== -1) {
    return normalized.slice(idx + 1).replace(/\\+$/, "");
  }
  if (lower.endsWith("\\data") || lower === "data") {
    return "data";
  }
  return null;
}

export async function webInvoke<T>(cmd: string, args: Args = {}): Promise<T> {
  switch (cmd) {
    // ── Dashboard / bootstrap ──────────────────────────────────────────────
    case "get_all_salts":
      return apiFetch<T>("GET", "/api/v1/salts");
    case "get_mabi_version_local":
      try {
        return await apiFetch<T>("GET", "/api/v1/mabi-version");
      } catch (e: any) {
        if (e?.status === 404) return null as T; // Tauri returns None, not an error, when not installed
        throw e;
      }
    case "get_system_info":
      return { cpu_usage: 0, memory_used_mb: 0, memory_total_mb: 0 } as T;
    case "get_initial_file":
      return null as T; // browser has no "opened via file explorer" concept
    case "is_ran_as_admin":
      return true as T; // suppresses the (Windows-only) elevation warning, irrelevant to a browser tab
    case "request_elevation":
      return undefined as T;
    case "drain_log_buffer":
      return [] as T;
    case "get_mods_dir":
      return "mods" as T; // display-only in browser mode; REST resolves its own mods dir server-side

    // ── Config (client-side only — no server-side "this browser" concept) ──
    case "get_config":
      return loadLocalConfig() as T;
    case "save_config":
    case "set_config":
      saveLocalConfig((args.config as Record<string, unknown>) ?? {});
      return undefined as T;

    // ── Extract / Pack / List ───────────────────────────────────────────────
    case "extract_pack_to":
      return apiFetch<T>("POST", "/api/v1/extract", {
        archive: args.input,
        output: args.output,
        key: args.key,
        filters: args.filters ?? [],
      });
    case "create_archive":
      return apiFetch<T>("POST", "/api/v1/pack", {
        source: args.input,
        output: args.output,
        key: args.key,
        formats: args.formats,
        iv: args.iv,
        path_prefix: args.pathPrefix,
        wrap_data: args.wrapData,
      });
    case "list_pack_contents":
      return apiFetch<T>("POST", "/api/v1/list", { archive: args.input, key: args.key });
    case "check_data_folder":
      return apiFetch<{ has_data_folder: boolean }>("POST", "/api/v1/fs/check-data-folder", { path: args.path })
        .then((r) => r.has_data_folder as unknown as T);
    case "detect_data_prefix":
      return detectDataPrefix(args.path as string) as T;

    // ── Mods ────────────────────────────────────────────────────────────────
    case "list_mod_files":
      return apiFetch<{ mods: unknown[] }>("GET", "/api/v1/mods").then((r) => r.mods as unknown as T);
    case "get_mod_template":
      return apiFetch<{ template: string }>("GET", "/api/v1/mod-template").then((r) => r.template as unknown as T);
    case "load_mod_file":
      return apiFetch<{ content: string }>(
        "GET",
        `/api/v1/mod-file?path=${encodeURIComponent(args.path as string)}`
      ).then((r) => r.content as unknown as T);
    case "apply_mod":
      return apiFetch<T>("POST", "/api/v1/mod/apply", {
        mod_toml: args.modToml,
        archive: args.archive,
        key: args.key,
        mod_dir: args.modDir,
      });
    case "apply_vfs_changes":
      return apiFetch<T>("POST", "/api/v1/mod/vfs/apply", {
        archive: args.archive,
        key: args.key,
        changes: args.changes,
      });
    case "save_pending_changes":
      return apiFetch<T>("POST", "/api/v1/mod/pending/save", { archive: args.archive, changes: args.changes });
    case "load_pending_changes":
      return apiFetch<{ changes: unknown }>(
        "GET",
        `/api/v1/mod/pending?archive=${encodeURIComponent(args.archive as string)}`
      ).then((r) => r.changes as unknown as T);

    // ── Features.xml editor ────────────────────────────────────────────────
    case "get_features_from_archive":
      return apiFetch<T>("POST", "/api/v1/features/get", { archive: args.archive, key: args.key });
    case "save_features_to_archive":
      return apiFetch<T>("POST", "/api/v1/features/save", {
        archive: args.archive,
        key: args.key,
        features_json: args.featuresJson,
      });

    // ── Diff / patch ────────────────────────────────────────────────────────
    case "create_patch":
      return apiFetch<T>("POST", "/api/v1/patch/create", {
        base_dir: args.base,
        modified_dir: args.modified,
        output: args.output,
        key: args.key,
        iv: 0,
      });

    // ── Launcher ────────────────────────────────────────────────────────────
    case "launcher_login":
      return apiFetch<T>("POST", "/api/v1/launcher/login", {
        username: args.username,
        password: args.password,
        remember: args.remember,
      });
    case "launcher_autologin":
      return apiFetch<T>("POST", "/api/v1/launcher/autologin", { session_token: args.sessionToken });
    case "launcher_check_maintenance":
      return apiFetch<{ maintenance: boolean }>("POST", "/api/v1/launcher/maintenance", { session: args.session })
        .then((r) => r.maintenance as unknown as T);
    case "launcher_get_version":
      return apiFetch<{ version: number; session?: unknown }>("POST", "/api/v1/launcher/version", { session: args.session })
        .then((r) => ({ version: r.version, session: r.session }) as unknown as T);
    case "launcher_list_profiles":
      return apiFetch<{ profiles: unknown[] }>("GET", "/api/v1/launcher/profiles").then((r) => r.profiles as unknown as T);
    case "launcher_save_profile":
      return apiFetch<{ id: string }>("POST", "/api/v1/launcher/profile/save", {
        id: args.id,
        name: args.name,
        email: args.email,
        client_dir: args.clientDir,
        auto_login: args.autoLogin,
      }).then((r) => r.id as unknown as T);
    case "launcher_delete_profile":
      return apiFetch<{ deleted: boolean }>("POST", "/api/v1/launcher/profile/delete", { id: args.id })
        .then((r) => r.deleted as unknown as T);
    case "launcher_set_active_profile":
      return apiFetch<T>("POST", "/api/v1/launcher/profile/activate", { id: args.id });
    case "launcher_load_profile":
      return apiFetch<T>("POST", "/api/v1/launcher/profile/load", { id: args.id });
    case "launcher_update_profile_session":
      return apiFetch<T>("POST", "/api/v1/launcher/profile/session", {
        id: args.id,
        session_token: args.sessionToken,
        expires_in: args.expiresIn,
      });
    case "launcher_launch":
      return apiFetch<T>("POST", "/api/v1/launcher/launch", { session: args.session, client_dir: args.clientDir });

    // ── Preview (image/text/mml/pmg/rgn/area/set/audio/binary) + convert ────
    case "get_preview_ext":
      return apiFetch<T>("POST", "/api/v1/preview", {
        archive: args.archivePath,
        entry_name: args.entryName,
        key: args.key,
      });
    case "run_convert":
      return apiFetch<T>("POST", "/api/v1/convert", {
        input: args.input,
        output: args.output,
        key: args.key,
        wrap_data: args.wrapData,
      });

    // ── Desktop-only: native dialogs are shimmed separately (platform/dialog.ts);
    //    everything below has no browser equivalent (registry/association
    //    editing, elevation, single-entry extract-to-arbitrary-
    //    path, local loose-file preview) — see MISSION_CONTROL_PLAN.md. ─────
    default:
      return unsupported(cmd);
  }
}
