import { invoke } from "./platform/invoke";
import { open, save, ask, message } from "./platform/dialog";
import { writeTextFile, writeFile } from "./platform/fs";
import { listen } from "./platform/event";
import { isTauri } from "./platform/isTauri";
import { locales as TRANSLATIONS } from "./locales";
import type { PMGViewer, PmgGeometry } from "./pmgLoader";
import type { Mounted3d } from "./preview3d/panel";
import type { AssetHost } from "./preview3d/worldData";

interface JobEntry {
    id: number;
    type: "extract" | "pack" | "differ" | "merge" | "apply-mod";
    input: string;
    output: string;
    key?: string;
    status: "pending" | "running" | "done" | "error";
    progress: number;
    log: string;
}

interface FileEntry {
    name: string;
    original_size: number;
    raw_size: number;
    offset: number;
    checksum: number;
    flags: number;
    key: number[];
}

/** Answer to a "target already exists" conflict in the List tab editor. */
type VfsConflictAction = "overwrite" | "newer" | "size" | "rename" | "skip";

interface AggregateEntry extends FileEntry {
    source_archive: string;
    salt_used: string;
    entries_salt_used: string;
    iv0: number;
    h_off: number;
    mode: string;
}

/** Where a preview's bytes come from, captured when the preview was requested. */
interface PreviewSource {
    entry?: AggregateEntry;
    loosePath?: string;
}

interface ArchiveDetails {
    file_count: number;
    salt: string;
    iv0: number;
    header_offset: number;
}

interface PackListResponse {
    entries: AggregateEntry[];
    details: ArchiveDetails;
}

interface ThemeOverrides {
    bg_deep?: string;
    bg_sidebar?: string;
    bg_input?: string;
    bg_surface_color?: string;
    surface_opacity?: number;
    border_color?: string;
    border_opacity?: number;
    accent_cyan?: string;
    accent_blue?: string;
    text_primary?: string;
    text_muted?: string;
    font_family?: string;
    font_size?: number;
}

interface Config {
    theme: string;
    locale: string;
    log_level: string;
    associate_it: boolean;
    associate_pack: boolean;
    associate_it_full: boolean;
    startup_auto_extract: boolean;
    startup_auto_switch: boolean;
    salt_history: string[];
    last_key: string;
    region_key: string;
    suppress_admin_warning: boolean;
    auto_convert_png: boolean;
    auto_convert_dds: boolean;
    auto_convert_features: boolean;
    auto_convert_pmg: boolean;
    list_full_sequence: boolean;
    list_auto_expand: boolean;
    list_auto_select: "none" | "first" | "all";
    startup_path: string;
    pack_wrap_data: boolean;
    pack_wrap_mode: "ask" | "structure" | "data" | "none";
    write_salt: string;
    audio_autoplay: boolean;
    audio_loop: boolean;
    associate_dds: boolean;
    associate_pmg: boolean;
    associate_xmlcompiled: boolean;
    pack_v1_version: number;
    sequence_ignore_list: string[];
    theme_overrides: ThemeOverrides;
    custom_themes: Record<string, ThemeOverrides>;
    patcher_game_path: string;
    patcher_hyddwn_enabled: boolean;
    patcher_hyddwn_url: string;
    patcher_auto_update: boolean;
    patcher_focus_on_start: boolean;
    patcher_max_workers: number;
    patcher_run_elevated: boolean;
    /** Wildcard paths (`*`, `?`) the patcher never touches — keeps local mods safe. */
    patcher_ignore_list?: string[];
    launch_use_nexon_launcher: boolean;
    launch_cmd_override: string;
    pre_patch_cmd: string;
    post_patch_cmd: string;
    api_enabled: boolean;
    api_port: number;
    pre_launch_cmd: string;
    post_launch_cmd: string;
    parallel_ops: boolean;
    mod_remote_url: string;
    /** Nexon product id (advanced; default 10200). */
    product_id: number;
    /** Hide to the tray instead of exiting when the window is closed. */
    minimize_to_tray: boolean;
}

/** Hooks + update ignore list, stored in the config shared with the CLI/REST API. */
interface SharedConfig {
    ignore: string[];
    hooks: { before_patch?: string; after_patch?: string; before_launch?: string; after_launch?: string };
}

/** One item of the Nexon news feed (core launcher::news::NewsItem). */
interface NewsItem {
    id: number;
    category: string;
    title: string;
    summary: string;
    url: string;
    date: string;
    image: string;
    maintenance: boolean;
}

/** A file the patcher would update (core launcher::patch::NeedItem). */
interface NeedItem {
    path: string;
    size: number;
    local_size: number;
    reason: string;
}

/** One install from "Check all installs" (core FolderStatus + client_dir). */
interface InstallStatus {
    path: string;
    client_dir: string;
    local_hash: string | null;
    remote_hash: string | null;
    update_available: boolean | null;
    error?: string;
}

interface PreviewData {
    name: string;
    size: number;
    raw_size: number;
    offset: number;
    checksum: number;
    flags: number;
    file_type: string;
    content_text: string | null;
    content_image: string | null; // base64
    raw_bytes: number[];
    source: string;
    salt: string;
    full_preview_size: number;
    truncated: boolean;
    pmg_geometry?: PmgGeometry | null;
    rgn_data?: RgnData | null;
}

interface RgnData {
    version: number;
    region_id: number;
    area_count: number;
    width: number;
    height: number;
    heights: number[];   // normalized 0.0–1.0, row-major
}

/** One package from the website's Mods catalog (https://shaggyze.website/mabipatcher/mods). */
interface WebMod {
    id: number;
    name: string;
    category?: string;
    version?: string;
    author?: string;
    description?: string;
    files?: number;
    hasDelete?: boolean;
    tags?: string[];
}

/** Default catalog source: the website's Mods page (its bundle carries the catalog). */
const DEFAULT_MOD_CATALOG_URL = "https://shaggyze.website/mabipatcher/mods";

/** Build a DOM element with a class and plain-text content (never innerHTML for mod metadata). */
function elText<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text?: string): HTMLElementTagNameMap[K] {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
}

class App {
    /** Value of the "New profile…" entry in the Launcher page profile dropdown. */
    static readonly NEW_PROFILE_OPTION = "__new_profile__";
    private config: Config = {
        theme: "sky-dark",
        locale: "en",
        log_level: "info",
        associate_it: true,
        associate_pack: false,
        associate_it_full: false,
        startup_auto_extract: true,
        startup_auto_switch: true,
        salt_history: ["})wWb4?-sVGHNoPKpc"],
        last_key: "@6QeTuOaDgJlZcBm#9",
        region_key: "data.it",
        suppress_admin_warning: false,
        auto_convert_png: false,
        auto_convert_dds: false,
        auto_convert_features: false,
        auto_convert_pmg: false,
        list_full_sequence: false,
        list_auto_expand: true,
        list_auto_select: "none",
        startup_path: "",
        pack_wrap_data: true,
        pack_wrap_mode: "ask",
        write_salt: "})wWb4?-sVGHNoPKpc",
        audio_autoplay: false,
        audio_loop: false,
        associate_dds: false,
        associate_pmg: false,
        associate_xmlcompiled: false,
        pack_v1_version: 999,
        sequence_ignore_list: [],
        theme_overrides: {},
        custom_themes: {},
        patcher_game_path: "",
        patcher_hyddwn_enabled: false,
        patcher_hyddwn_url: "http://127.0.0.1:11000",
        patcher_auto_update: false,
        patcher_focus_on_start: false,
        patcher_run_elevated: false,
        patcher_ignore_list: [],
        patcher_max_workers: 10,
        launch_use_nexon_launcher: false,
        launch_cmd_override: "",
        pre_patch_cmd: "",
        post_patch_cmd: "",
        api_enabled: false,
        api_port: 7331,
        pre_launch_cmd: "",
        post_launch_cmd: "",
        parallel_ops: true,
        mod_remote_url: "",
        product_id: 10200,
        minimize_to_tray: false,
    };
    private sharedConfig: SharedConfig = { ignore: [], hooks: {} };
    private sharedConfigLoaded: Promise<void> | null = null;
    private patchPaused = false;
    /** A patch or file scan is running (backend allows only one at a time). */
    private patchBusy = false;
    private patchBusyOwner = 0;
    private patchBusySeq = 0;
    /** The running job is a file scan (Stop cancels the scan, not a patch). */
    private scanRunning = false;

    private loadedEntries: AggregateEntry[] = [];
    private selectedEntry: AggregateEntry | null = null;
    private pmgViewer?: PMGViewer;
    private viewer3d?: Mounted3d;
    private previewGen = 0;
    private selectGen = 0;
    private textureIndex?: Map<string, AggregateEntry[]>;
    private textureIndexSource?: AggregateEntry[];
    private currentArchive: string = "";
    private engineSalts: string[] = [];
    private previewCache = new Map<string, PreviewData>();
    private _taskStartTime: number | null = null;
    private _audioBlobUrl: string = "";
    private _activePreviewContainer: string = "preview-visual";
    private _mmlAudioCtx: AudioContext | null = null;
    private _mmlStopFlag: boolean = false;
    private modBrowserMode: 'local' | 'remote' = 'local';
    /** Website mod catalog (fetched once per session via fetch_web_mods_catalog). */
    private webModCatalog: WebMod[] | null = null;
    private webModsInstalled = new Set<number>();
    /** App version from the exe (get_app_version); fills {version} in locale strings. */
    private appVersion: string = "";

    private previewKey(e: AggregateEntry) { return `${e.source_archive}::${e.name}`; }
    
    constructor() {
        this.boot();
    }

    private setupSaltCombo(prefix: string) {
        const btn = document.getElementById(`btn-salt-history-${prefix}`);
        const list = document.getElementById(`salt-list-${prefix}`);

        btn?.addEventListener("click", async (e) => {
            e.stopPropagation();
            if (list) {
                const isHidden = list.style.display === "none";
                // Close others
                document.querySelectorAll(".salt-list-wrapper").forEach(el => (el as HTMLElement).style.display = "none");
                
                list.style.display = isHidden ? "block" : "none";
                if (isHidden) await this.renderSaltHistory(prefix);
            }
        });

        document.addEventListener("click", () => {
            if (list) list.style.display = "none";
        });
    }

    private async renderSaltHistory(onlyPrefix?: string) {
        const prefixes = onlyPrefix ? [onlyPrefix] : ["extract", "pack", "differ"];
        
        // Ensure we have engine salts cached
        if (this.engineSalts.length === 0) {
            try {
                this.engineSalts = await invoke("get_all_salts") as string[];
            } catch (err) {
                this.engineSalts = ["})wWb4?-sVGHNoPKpc", "@6QeTuOaDgJlZcBm#9", "CuAVPMZx:E96:(Rxdw"];
            }
        }
        
        const SUGGESTED = ["@6QeTuOaDgJlZcBm#9", "})wWb4?-sVGHNoPKpc"];
        const userHistory = (this.config.salt_history || []).map(s => s.trim());
        const rest = Array.from(new Set([...userHistory, ...this.engineSalts])).filter(s => s.length > 0 && !SUGGESTED.includes(s));
        const combined = [...SUGGESTED, ...rest].slice(0, 100);

        prefixes.forEach(prefix => {
            const list = document.getElementById(`salt-list-${prefix}`);
            if (!list) return;
            
            // Optimization: Use a fragment for faster DOM updates
            const fragment = document.createDocumentFragment();
            combined.forEach(salt => {
                const item = document.createElement("div");
                item.className = "salt-item";
                
                const val = document.createElement("span");
                val.textContent = salt;
                val.className = "salt-text";
                val.onclick = () => {
                    const input = document.getElementById(`${prefix}-key`) as HTMLInputElement;
                    if (input) input.value = salt;
                    list.style.display = "none";
                };

                if (SUGGESTED.includes(salt)) {
                    const tag = document.createElement("span");
                    tag.textContent = salt === SUGGESTED[0] ? this.t("tag_extract") : this.t("tag_pack");
                    tag.style.cssText = "font-size:10px;color:var(--accent-cyan);border:1px solid var(--accent-cyan);border-radius:3px;padding:0 3px;margin-left:4px;opacity:0.7";
                    item.appendChild(val);
                    item.appendChild(tag);
                } else if (userHistory.includes(salt.trim())) {
                    const del = document.createElement("span");
                    del.textContent = "×";
                    del.className = "delete-btn";
                    del.onclick = (e) => {
                        e.stopPropagation();
                        this.config.salt_history = this.config.salt_history.filter(s => s.trim() !== salt.trim());
                        this.saveConfig();
                        this.renderSaltHistory(prefix);
                    };
                    item.appendChild(val);
                    item.appendChild(del);
                } else {
                    val.style.color = "var(--text-muted)";
                    item.appendChild(val);
                }
                fragment.appendChild(item);
            });
            
            list.innerHTML = "";
            list.appendChild(fragment);
        });
    }

    private async boot() {
        // 1. System Language Detection (Fallback)
        const sysLang = navigator.language.toLowerCase();
        let detectedLocale = "en";
        if (sysLang.startsWith("zh")) detectedLocale = "tw";
        else if (sysLang.startsWith("ja")) detectedLocale = "ja";
        else if (sysLang.startsWith("ko")) detectedLocale = "ko";
        this.config.locale = detectedLocale;

        // Load Saved Config (Overwrites detected)
        try {
            const saved = await invoke("get_config") as any;
            if (saved) {
                for (const key of Object.keys(saved)) {
                    if (saved[key] !== null && saved[key] !== "" && saved[key] !== undefined) {
                        (this.config as any)[key] = saved[key];
                    }
                }
            }
        } catch (e) { console.error("Failed to load config", e); }

        // Pre-fetch all engine salts in the background
        invoke("get_all_salts").then((s) => {
            this.engineSalts = s as string[];
            this.log(`[BOOT] Loaded ${this.engineSalts.length} engine salts.`);
        }).catch(err => {
            console.error("Failed to fetch salts", err);
            this.engineSalts = ["})wWb4?-sVGHNoPKpc", "@6QeTuOaDgJlZcBm#9", "CuAVPMZx:E96:(Rxdw"];
        });

        // 3. Apply Theme Immediately
        this.applyTheme();

        // 4. Initialize rest
        this.init();
    }

    private async init() {
        // Register the Tauri event listeners (log, progress, drag-drop, open-file) first,
        // and isolate every other setup step, so one broken section can't leave the
        // window deaf to dropped files.
        this.setupEventListen();
        // The version comes from the exe, so index.html and locales.ts never hold it.
        try { this.appVersion = await invoke("get_app_version") as string; } catch (_) {}
        this.applyVersionLabels();
        const steps: Array<[string, () => void]> = [
            ["translateUI", () => this.translateUI()],
            ["syncSettingsUI", () => this.syncSettingsUI()],
            ["initTooltip", () => this.initTooltip()],
            ["setupNavigation", () => this.setupNavigation()],
            ["setupDashboard", () => this.setupDashboard()],
            ["setupJobQueue", () => this.setupJobQueue()],
            ["setupVfsEditing", () => this.setupVfsEditing()],
            ["setupLauncher", () => this.setupLauncher()],
            ["setupFeaturesEditor", () => this.setupFeaturesEditor()],
            ["setupThemeCustomizer", () => this.setupThemeCustomizer()],
            ["setupPatcherTab", () => this.setupPatcherTab()],
            ["setupResizableList", () => this.setupResizableList()],
            ["setupResizableConsole", () => this.setupResizableConsole()],
            ["setupMenuButtons", () => this.setupMenuButtons()],
            ["setup3dPreviewResize", () => this.setup3dPreviewResize()],
            ["setupForms", () => this.setupForms()],
            ["setupNews", () => this.setupNews()],
        ];
        for (const [name, step] of steps) {
            try { step(); } catch (e) { console.error(`[INIT] ${name} failed`, e); this.log(`[INIT] ${name} failed: ${e}`, "error"); }
        }

        // Flush any log messages that were emitted before the JS listener was ready
        invoke("drain_log_buffer").then((entries) => {
            for (const [message, level] of entries as [string, string][]) {
                this.log(message, level, true);
            }
        }).catch(() => {});

        // Handle initial file if opened via explorer
        const initial = await invoke("get_initial_file") as { path: string, full_sequence: boolean } | null;
        if (initial && initial.path) {
            const lp = initial.path.toLowerCase();
            const isLoose = lp.endsWith(".dds") || lp.endsWith(".pmg") || lp.endsWith(".compiled");
            if (isLoose) {
                await this.openLooseFile(initial.path);
            } else {
                (document.getElementById("list-input") as HTMLInputElement).value = initial.path;
                (document.getElementById("extract-input") as HTMLInputElement).value = initial.path;
                this.handlePathAutoFill("extract-input", initial.path);
                if (this.config.startup_auto_extract) {
                    this.runList(initial.full_sequence);
                }
                if (this.config.startup_auto_switch) {
                    document.querySelector('.nav-item[data-tab="list"]')?.dispatchEvent(new Event('click'));
                }
            }
        }

        const isAdmin: boolean = await invoke("is_ran_as_admin");
        if (isAdmin) {
            // Windows (UIPI) blocks drag-and-drop from a normal Explorer window into an elevated one.
            this.log(this.t("msg_admin_no_dragdrop"), "warn");
        }
        if (this.config.patcher_run_elevated && !isAdmin) {
            await invoke("request_elevation");
            return;
        }
        if (!this.config.suppress_admin_warning) {
            if (!isAdmin) {
                const confirmed = await ask(this.t("adminReq"), { title: this.t("adminTitle"), kind: "warning" });
                if (confirmed) {
                    await invoke("request_elevation");
                } else {
                    this.config.suppress_admin_warning = true;
                    await this.saveConfig();
                }
            }
        }

        if (this.config.patcher_focus_on_start) {
            document.querySelector('.nav-item[data-tab="patcher"]')?.dispatchEvent(new Event('click'));
        }

        if (this.config.patcher_auto_update && this.config.patcher_game_path) {
            this.log(this.t("log_patcher_autoupdate"), "info");
            this.runPatcher(this.config.patcher_game_path, false);
        }
        this.log(this.t("engineInit"), "success");
    }

    private t(key: string, args: string[] = []): string {
        const lang = this.config.locale || "en";
        let text = TRANSLATIONS[lang]?.[key] || TRANSLATIONS["en"]?.[key] || key;
        args.forEach((val, i) => {
            text = text.replace(`{${i}}`, val);
        });
        if (text.includes("{version}")) text = text.split("{version}").join(this.appVersion);
        return text;
    }

    /** Window title and sidebar tag show the exe's version. */
    private applyVersionLabels() {
        document.title = this.t("title");
        const tag = document.getElementById("version-tag");
        if (tag) tag.textContent = this.appVersion ? `v${this.appVersion}` : "";
    }

    private translateUI() {
        const ids = [
            "tab_dashboard", "tab_extract", "tab_pack", "tab_list", "tab_differ", "tab_settings",
            "label_archive", "label_target", "label_salt", "label_filters", "label_source", "label_output", "label_pack_salt",
            "label_original", "label_modified", "label_out_patch", "label_differ_salt", "set_visuals", "label_lang", "label_theme",
            "label_region_key", "label_region_key_read", "label_region_key_write", "set_startup", "label_startup_extract", "label_startup_switch",
            "set_shell", "label_assoc_it", "label_assoc_pack", "label_settings_assoc_it_full",
            "label_assoc_dds", "label_assoc_pmg", "label_assoc_xmlcompiled",
            "set_pack_opts", "label_pack_v1_version",
            "set_engine", "label_log", "label_compress_fmts", "label_iv",
            "btn_unpack", "btn_create", "btn_diff", "btn_admin", "btn_wipe", "logs", "label-list-full-sequence",
            "label_list_auto_expand", "label_list_auto_select",
            "label_select_none", "label_select_first", "label_select_all",
            "ready", "set_conversion",
            "extractSelected", "extractAll", "ctxConvIt", "ctxConvPack",
            "preview_tab_visual", "preview_tab_hex", "preview_tab_details",
            "label_settings_auto_png", "label_settings_auto_dds",
            "label_audio_autoplay", "label_audio_autoplay_inline", "label_audio_loop",
            "ctx_extract", "ctx_copy_name", "ctx_copy_key", "ctx_conv_png", "ctx_conv_dds",
            "ctx_conv_xml", "ctx_conv_obj", "ctx_rename", "ctx_delete",
            "btn_wipe_assoc", "btn_open_config_dir", "btn_reset_config",
            "dash_mods_title", "lbl_cpu", "lbl_mem",
            "label_hyddwn_enable",
            "label_patcher_server_url",
            "recentActivity", "noActivity",
        ];
        ids.forEach(id => {
            document.querySelectorAll<HTMLElement>(`[id="${id}"]`).forEach(el => {
                el.textContent = this.t(id);
            });
        });

        // Translate any element with data-i18n attribute
        document.querySelectorAll<HTMLElement>("[data-i18n]").forEach(el => {
            const key = el.dataset.i18n!;
            const val = this.t(key);
            if (val && val !== key) el.textContent = val;
        });

        // Translate placeholder attributes
        document.querySelectorAll<HTMLElement>("[data-i18n-placeholder]").forEach(el => {
            const key = (el as any).dataset.i18nPlaceholder as string;
            const val = this.t(key);
            if (val && val !== key) (el as HTMLInputElement).placeholder = val;
        });

        // Translate <optgroup label> attributes
        document.querySelectorAll<HTMLOptGroupElement>("optgroup[data-i18n-label]").forEach(el => {
            const key = el.dataset.i18nLabel!;
            const val = this.t(key);
            if (val && val !== key) el.label = val;
        });

        // Tray menu labels live in Rust; hand them the translated text.
        invoke("set_tray_labels", { show: this.t("tray_show"), quit: this.t("tray_quit") }).catch(() => {});

        // Pause/Resume reflects the current state, not the static label
        const pauseBtn = document.getElementById("btn-patcher-pause");
        if (pauseBtn) pauseBtn.textContent = this.t(this.patchPaused ? "patcher_resume" : "patcher_pause");

        // Empty file tree placeholder
        const treeEmpty = document.getElementById("file-tree-empty");
        if (treeEmpty) treeEmpty.textContent = this.t("tree_empty");

        // Main title
        const mainTitle = document.getElementById("main-title");
        if (mainTitle) mainTitle.textContent = this.t("title");
        this.applyVersionLabels();

        // Run buttons whose IDs don't match locale keys
        const runBtnMap: [string, string][] = [
            ["extract-run", "btn_unpack"],
            ["pack-run", "btn_create"],
            ["differ-run", "btn_diff"],
            ["btn-patcher-verify", "label_patcher_verify"],
            ["btn-patcher-repair", "label_patcher_repair"],
            ["btn-patcher-update", "label_patcher_download_updates"],
            ["btn-patcher-browse", "label_patcher_browse"],
        ];
        runBtnMap.forEach(([id, key]) => {
            const el = document.getElementById(id);
            if (el) el.textContent = this.t(key);
        });

        // Translate span elements with -text suffix IDs (launcher/features/jobs tabs)
        const textMap: [string, string][] = [
            ["launcher-title-text", "launcher_title"],
            ["launcher-login-header-text", "launcher_login_header"],
            ["launcher-email-label-text", "launcher_email_label"],
            ["launcher-password-label-text", "launcher_password_label"],
            ["launcher-remember-text", "launcher_remember_me"],
            ["btn-launcher-login-text", "btn_launcher_login"],
            ["btn-launcher-logout-text", "btn_launcher_logout"],
            ["btn-launcher-import-session-text", "btn_launcher_import_session"],
            ["launcher-session-header-text", "launcher_session_header"],
            ["launcher-session-label-text", "launcher_session_token_label"],
            ["launcher-version-label-text", "launcher_version_label"],
            ["launcher-maintenance-label-text", "launcher_maintenance_label"],
            ["launcher-launch-header-text", "launcher_launch_header"],
            ["launcher-client-label-text", "launcher_client_label"],
            ["btn-launcher-launch-text", "btn_launcher_launch"],
            ["features-title-text", "features_title"],
            ["features-archive-label-text", "features_archive_label"],
            ["features-key-label-text", "features_key_label"],
            ["btn-features-load-text", "btn_features_load"],
            ["btn-features-save-text", "btn_features_save"],
            ["features-servers-header-text", "features_servers_header"],
            ["features-list-header-text", "features_list_header"],
            ["jobs-title-text", "jobs_title"],
            ["jobs-list-header-text", "jobs_list_header"],
        ];
        textMap.forEach(([elemId, key]) => {
            const el = document.getElementById(elemId);
            if (el) el.textContent = this.t(key);
        });

        // Browse buttons
        document.querySelectorAll<HTMLElement>('[data-tooltip="tooltip_browse"]').forEach(el => {
            el.textContent = this.t("browse");
        });

        // Log level option labels
        const logSel = document.getElementById("settings-log") as HTMLSelectElement | null;
        if (logSel) {
            const logMap: Record<string, string> = {
                info: this.t("log_info"), warn: this.t("log_warn"), error: this.t("log_error"),
                debug: this.t("log_debug"), trace: this.t("log_trace")
            };
            for (const opt of Array.from(logSel.options)) {
                if (logMap[opt.value]) opt.textContent = logMap[opt.value];
            }
        }

        // Input placeholders
        const placeholders: [string, string][] = [
            ["extract-input",  "inputFile"],
            ["extract-output", "outputFolder"],
            ["pack-input",     "inputFolder"],
            ["pack-output",    "outputArchive"],
            ["extract-key",    "saltKey"],
            ["pack-key",       "saltKey"],
            ["list-input",     "inputFile"],
            ["differ-key",     "saltKey"],
            ["differ-old",     "inputFolder"],
            ["differ-new",     "inputFolder"],
            ["file-search-filter", "search"],
            ["terminal-input", "terminalPlaceholder"],
            ["differ-output",  "saveAsPath"],
        ];
        placeholders.forEach(([id, key]) => {
            const el = document.getElementById(id) as HTMLInputElement | null;
            if (el) el.placeholder = this.t(key);
        });

        // Preview pane initial text
        ["preview-visual", "preview-hex", "preview-details"].forEach(id => {
            const el = document.getElementById(id);
            if (el && !el.innerHTML.trim()) el.textContent = this.t("preview_select");
        });

        // Tabs + sidebar tooltips
        ["dashboard", "extract", "pack", "list", "differ", "jobs", "mods", "patcher", "features", "launcher", "settings"].forEach(tab => {
            const btn = document.querySelector(`.nav-item[data-tab="${tab}"]`) as HTMLElement;
            if (btn) {
                const label = this.t(`tab_${tab}`);
                const span = btn.querySelector('.nav-text');
                if (span) span.textContent = label;
                btn.dataset.tooltip = `tab_${tab}`;
            }
        });
    }

    private syncSettingsUI() {
        const ids = [
            { id: "theme", prop: "theme" },
            { id: "lang", prop: "locale" },
            { id: "log", prop: "log_level" }
        ];
        ids.forEach(item => {
            const el = document.getElementById(`settings-${item.id}`) as HTMLSelectElement;
            if (el) el.value = (this.config as any)[item.prop];
        });

        const rk = document.getElementById("settings-region-key") as HTMLInputElement;
        if (rk) rk.value = this.config.region_key || "";
        const ws = document.getElementById("settings-write-salt") as HTMLInputElement;
        if (ws) ws.value = this.config.write_salt || "";
        const pk = document.getElementById("pack-key") as HTMLInputElement;
        if (pk && !pk.value) pk.value = this.config.write_salt || "";
        const pv = document.getElementById("settings-pack-v1-version") as HTMLInputElement;
        if (pv) pv.value = String(this.config.pack_v1_version ?? 999);
        
        const toggles = [
            { id: "settings-assoc-it", prop: "associate_it" },
            { id: "settings-assoc-pack", prop: "associate_pack" },
            { id: "settings-assoc-it-full", prop: "associate_it_full" },
            { id: "settings-assoc-dds", prop: "associate_dds" },
            { id: "settings-assoc-pmg", prop: "associate_pmg" },
            { id: "settings-assoc-xmlcompiled", prop: "associate_xmlcompiled" },
            { id: "settings-auto-png", prop: "auto_convert_png" },
            { id: "settings-auto-dds", prop: "auto_convert_dds" },
            { id: "settings-auto-features", prop: "auto_convert_features" },
            { id: "settings-auto-pmg", prop: "auto_convert_pmg" },
            { id: "extract-auto-png", prop: "auto_convert_png" },
            { id: "pack-auto-dds", prop: "auto_convert_dds" },
            { id: "settings-startup-extract", prop: "startup_auto_extract" },
            { id: "settings-startup-switch", prop: "startup_auto_switch" },
            { id: "list-full-sequence", prop: "list_full_sequence" },
            { id: "extract-full-sequence", prop: "list_full_sequence" },
            { id: "settings-list-auto-expand", prop: "list_auto_expand" },
            { id: "audio-autoplay", prop: "audio_autoplay" },
            { id: "settings-audio-autoplay", prop: "audio_autoplay" },
            { id: "audio-loop", prop: "audio_loop" },
            { id: "settings-audio-loop", prop: "audio_loop" },
        ];

        toggles.forEach(t => {
            const el = document.getElementById(t.id) as HTMLInputElement;
            if (el) el.checked = (this.config as any)[t.prop];
        });

        const audioEl = document.getElementById("audio-elem") as HTMLAudioElement | null;
        if (audioEl) audioEl.loop = this.config.audio_loop ?? false;

        // Sync radio group for auto-select mode
        const mode = this.config.list_auto_select || "none";
        const radio = document.querySelector(`input[name="list-auto-select"][value="${mode}"]`) as HTMLInputElement;
        if (radio) radio.checked = true;

        // Sync sequence ignore list textarea
        const sil = document.getElementById("settings-sequence-ignore") as HTMLTextAreaElement;
        if (sil) sil.value = (this.config.sequence_ignore_list ?? []).join('\n');

        // Set tooltip on settings toggles from their label text
        const tooltipPairs: [string, string][] = [
            ["settings-startup-extract", "label_startup_extract"],
            ["settings-startup-switch",  "label_startup_switch"],
            ["settings-list-auto-expand","label_list_auto_expand"],
            ["settings-audio-autoplay",  "label_audio_autoplay"],
            ["settings-audio-loop",      "label_audio_loop"],
            ["settings-assoc-it",        "label_assoc_it"],
            ["settings-assoc-pack",      "label_assoc_pack"],
            ["settings-assoc-it-full",   "label_settings_assoc_it_full"],
            ["settings-auto-png",        "label_settings_auto_png"],
            ["settings-auto-dds",        "label_settings_auto_dds"],
            ["settings-auto-features",   "label_settings_auto_features"],
            ["settings-auto-pmg",        "label_settings_auto_pmg"],
            ["settings-lang",            "tooltip_lang"],
            ["settings-theme",           "tooltip_theme"],
            ["settings-log",             "tooltip_log_level"],
            ["btn_admin",                "tooltip_admin"],
            ["btn_wipe",                 "tooltip_wipe"],
            ["btn_open_config_dir",      "tooltip_open_config_dir"],
            ["btn_reset_config",         "tooltip_reset_config"],
            ["btn_wipe_assoc",           "tooltip_wipe_assoc"],
            ["btn-open-mods-dir",        "tooltip_open_mods_dir"],
            ["btn-new-mod-template",     "tooltip_new_mod_template"],
        ];
        tooltipPairs.forEach(([id, key]) => {
            const el = document.getElementById(id);
            if (el) {
                el.dataset.tooltip = key;
                // Also set on parent label.switch so the visible slider gets the tooltip
                if (el instanceof HTMLInputElement && el.type === "checkbox" && el.parentElement?.classList.contains("switch")) {
                    el.parentElement.dataset.tooltip = key;
                }
            }
        });

        // Set tooltips on .sys-stat spans — use the ID as the key so the resolver
        // translates dynamically at display time (survives locale changes without re-calling this)
        document.querySelectorAll<HTMLElement>(".sys-stat > span[id]").forEach(span => {
            // Prefer the element's locale key; fall back to the id (which is a key for older labels).
            const key = span.dataset.i18n || span.id;
            if (key) span.dataset.tooltip = key;
        });

        // Set tooltips on radio labels
        document.querySelectorAll<HTMLElement>("#list-auto-select-group label.radio-label").forEach(label => {
            const span = label.querySelector<HTMLElement>("span[id]");
            if (span?.id) label.dataset.tooltip = span.id;
        });

        this.syncCustomizerUI();
    }

    private applyTheme() {
        const cls = `theme-${this.config.theme}`;
        document.documentElement.className = cls;
        document.body.className = cls;
        localStorage.setItem("mabi_theme", this.config.theme);
        this.applyThemeOverrides();
        this.syncCustomizerUI();
    }

    private applyThemeOverrides() {
        const o = this.config.theme_overrides ?? {};
        // The theme class (.theme-*) is on BOTH <html> and <body> and redefines every
        // color var. A var set only inline on <html> is therefore shadowed by <body>'s
        // class rule and never reaches the UI, so the overrides go inline on both.
        const targets = [document.documentElement.style, document.body.style];
        const managed = ['--bg-deep', '--bg-sidebar', '--bg-input', '--bg-terminal', '--bg-surface',
            '--accent-cyan', '--accent-blue', '--accent-neon', '--text-primary', '--text-muted',
            '--border-glass', '--grad-body', '--ui-font'];
        // Clear first so the theme's own values can be read as defaults below.
        for (const s of targets) for (const p of managed) s.removeProperty(p);

        const vars: Record<string, string> = {};
        const put = (v: string | undefined, prop: string) => { if (v) vars[prop] = v; };
        put(o.bg_deep, '--bg-deep');
        put(o.bg_deep, '--grad-body'); // light themes paint body with a gradient instead of --bg-deep
        put(o.bg_sidebar, '--bg-sidebar');
        put(o.bg_input, '--bg-input');
        put(o.bg_deep ?? o.bg_surface_color, '--bg-terminal');
        put(o.accent_cyan, '--accent-cyan');
        put(o.accent_blue, '--accent-blue');
        put(o.accent_cyan, '--accent-neon');
        put(o.text_primary, '--text-primary');
        put(o.text_muted, '--text-muted');
        put(o.font_family, '--ui-font');

        const rgba = (color: string, alpha: number) => {
            const hex = this.cssColorToHex(color);
            const r = parseInt(hex.slice(1,3), 16);
            const g = parseInt(hex.slice(3,5), 16);
            const b = parseInt(hex.slice(5,7), 16);
            return `rgba(${r},${g},${b},${alpha.toFixed(2)})`;
        };
        if (o.bg_surface_color !== undefined || o.surface_opacity !== undefined) {
            const themeSurface = this.getCssVar('--bg-surface');
            const base = o.bg_surface_color ?? themeSurface;
            const pct = o.surface_opacity ?? this.rgbaOpacity(themeSurface);
            vars['--bg-surface'] = rgba(base, pct / 100);
        }
        if (o.border_color !== undefined || o.border_opacity !== undefined) {
            const themeBorder = this.getCssVar('--border-glass');
            const base = o.border_color ?? themeBorder;
            const pct = o.border_opacity ?? this.rgbaOpacity(themeBorder);
            vars['--border-glass'] = rgba(base, pct / 100);
        }

        for (const s of targets) for (const [p, v] of Object.entries(vars)) s.setProperty(p, v);

        const s = document.documentElement.style;
        if (o.font_size) s.fontSize = `${o.font_size}px`;
        else s.fontSize = '';
    }

    private getCssVar(name: string): string {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    private cssColorToHex(cssVal: string): string {
        const v = cssVal.trim();
        if (v.startsWith('#')) return v.length === 4
            ? '#' + v[1]+v[1]+v[2]+v[2]+v[3]+v[3]
            : v.slice(0,7);
        const m = v.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
        if (m) return '#' + [m[1],m[2],m[3]].map(n => parseInt(n).toString(16).padStart(2,'0')).join('');
        return '#000000';
    }

    private rgbaOpacity(cssVal: string): number {
        const m = cssVal.trim().match(/rgba\([^,]+,[^,]+,[^,]+,\s*([\d.]+)/);
        return m ? Math.round(parseFloat(m[1]) * 100) : 100;
    }

    private syncCustomizerUI() {
        const o = this.config.theme_overrides ?? {};
        const get = (prop: string) => this.cssColorToHex(this.getCssVar(prop));

        const setColor = (id: string, val: string | undefined, fallbackProp: string) => {
            const el = document.getElementById(id) as HTMLInputElement | null;
            if (el) el.value = val ?? get(fallbackProp);
        };
        setColor('tc-bg-deep',       o.bg_deep,          '--bg-deep');
        setColor('tc-bg-sidebar',    o.bg_sidebar,       '--bg-sidebar');
        setColor('tc-bg-input',      o.bg_input,         '--bg-input');
        setColor('tc-bg-surface',    o.bg_surface_color, '--bg-surface');
        setColor('tc-border-color',  o.border_color,     '--border-glass');
        setColor('tc-accent-cyan',   o.accent_cyan,      '--accent-cyan');
        setColor('tc-accent-blue',   o.accent_blue,      '--accent-blue');
        setColor('tc-text-primary',  o.text_primary,     '--text-primary');
        setColor('tc-text-muted',    o.text_muted,       '--text-muted');

        const surf = o.surface_opacity ?? this.rgbaOpacity(this.getCssVar('--bg-surface'));
        const bord = o.border_opacity  ?? this.rgbaOpacity(this.getCssVar('--border-glass'));
        const fsize = o.font_size ?? 14;

        const setSlider = (id: string, valId: string, v: number, suffix: string) => {
            const el = document.getElementById(id) as HTMLInputElement | null;
            const lbl = document.getElementById(valId);
            if (el) el.value = String(v);
            if (lbl) lbl.textContent = v + suffix;
        };
        setSlider('tc-surface-opacity', 'tc-surface-opacity-val', surf, '%');
        setSlider('tc-border-opacity',  'tc-border-opacity-val',  bord, '%');
        setSlider('tc-font-size',        'tc-font-size-val',      fsize, 'px');

        const ff = document.getElementById('tc-font-family') as HTMLSelectElement | null;
        if (ff) ff.value = o.font_family ?? '';

        // Populate saved themes dropdown
        const sel = document.getElementById('custom-theme-select') as HTMLSelectElement | null;
        if (sel) {
            sel.innerHTML = '';
            const none = document.createElement('option');
            none.value = '';
            none.dataset.i18n = 'theme_saved_themes';
            none.textContent = this.t('theme_saved_themes');
            sel.appendChild(none);
            for (const name of Object.keys(this.config.custom_themes ?? {})) {
                const opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name;
                sel.appendChild(opt);
            }
        }
    }

    private setupThemeCustomizer() {
        const update = (key: keyof ThemeOverrides, value: any) => {
            if (!this.config.theme_overrides || typeof this.config.theme_overrides !== 'object') this.config.theme_overrides = {};
            (this.config.theme_overrides as any)[key] = value;
            this.applyThemeOverrides();
            this.saveConfig();
        };

        const bindColor = (id: string, key: keyof ThemeOverrides) => {
            // 'input' fires live while dragging in the picker; some WebView color
            // dialogs only fire 'change' when they close, so listen to both.
            const el = document.getElementById(id);
            const onPick = (e: Event) => update(key, (e.target as HTMLInputElement).value);
            el?.addEventListener('input', onPick);
            el?.addEventListener('change', onPick);
        };
        const bindSlider = (id: string, valId: string, key: keyof ThemeOverrides, suffix: string) => {
            document.getElementById(id)?.addEventListener('input', (e) => {
                const v = parseInt((e.target as HTMLInputElement).value);
                const lbl = document.getElementById(valId);
                if (lbl) lbl.textContent = v + suffix;
                update(key, v);
            });
        };

        bindColor('tc-bg-deep',      'bg_deep');
        bindColor('tc-bg-sidebar',   'bg_sidebar');
        bindColor('tc-bg-input',     'bg_input');
        bindColor('tc-bg-surface',   'bg_surface_color');
        bindColor('tc-border-color', 'border_color');
        bindColor('tc-accent-cyan',  'accent_cyan');
        bindColor('tc-accent-blue',  'accent_blue');
        bindColor('tc-text-primary', 'text_primary');
        bindColor('tc-text-muted',   'text_muted');

        bindSlider('tc-surface-opacity', 'tc-surface-opacity-val', 'surface_opacity', '%');
        bindSlider('tc-border-opacity',  'tc-border-opacity-val',  'border_opacity',  '%');
        bindSlider('tc-font-size',       'tc-font-size-val',       'font_size',       'px');

        document.getElementById('tc-font-family')?.addEventListener('change', (e) => {
            update('font_family', (e.target as HTMLSelectElement).value || undefined);
        });

        document.getElementById('btn-theme-reset')?.addEventListener('click', () => {
            this.config.theme_overrides = {};
            this.applyTheme();
            this.syncCustomizerUI();
            this.saveConfig();
        });

        document.getElementById('btn-theme-save')?.addEventListener('click', () => {
            const nameEl = document.getElementById('custom-theme-name') as HTMLInputElement | null;
            const name = nameEl?.value.trim();
            if (!name) { alert(this.t("theme_name_required")); return; }
            if (!this.config.custom_themes) this.config.custom_themes = {};
            this.config.custom_themes[name] = { ...this.config.theme_overrides };
            this.saveConfig();
            this.syncCustomizerUI();
            // Select the newly saved theme in the dropdown and show feedback
            const sel = document.getElementById('custom-theme-select') as HTMLSelectElement | null;
            if (sel) sel.value = name;
            if (nameEl) {
                nameEl.value = '';
                nameEl.placeholder = this.t("theme_saved_as", [name]);
                setTimeout(() => { nameEl.placeholder = this.t("theme_name_placeholder"); }, 2000);
            }
        });

        document.getElementById('btn-theme-load')?.addEventListener('click', () => {
            const sel = document.getElementById('custom-theme-select') as HTMLSelectElement | null;
            const name = sel?.value;
            if (!name || !this.config.custom_themes?.[name]) return;
            this.config.theme_overrides = { ...this.config.custom_themes[name] };
            this.applyThemeOverrides();
            this.syncCustomizerUI();
            this.saveConfig();
        });

        document.getElementById('btn-theme-delete')?.addEventListener('click', () => {
            const sel = document.getElementById('custom-theme-select') as HTMLSelectElement | null;
            const name = sel?.value;
            if (!name || !this.config.custom_themes?.[name]) return;
            if (!confirm(this.t("confirm_delete_theme", [name]))) return;
            delete this.config.custom_themes[name];
            this.saveConfig();
            this.syncCustomizerUI();
        });
    }

    private setGauge(arcId: string, pct: number) {
        const arc = document.getElementById(arcId) as SVGPathElement | null;
        if (!arc) return;
        // Half-circle arc from (10,65) to (110,65) via top — circumference ≈ 157px
        const CIRC = 157;
        const fill = Math.max(0, Math.min(1, pct / 100)) * CIRC;
        arc.setAttribute("stroke-dasharray", `${fill.toFixed(1)} ${CIRC}`);
        // Color shift: green → yellow → red
        const hue = Math.round(120 - pct * 1.2);
        arc.style.stroke = `hsl(${hue},80%,55%)`;
    }

    private setupPatcherTab() {
        const gamePathEl = () => document.getElementById("patcher-game-path") as HTMLInputElement | null;
        const getGamePath = () => gamePathEl()?.value?.trim() ?? "";
        const statusEl = document.getElementById("patcher-status");
        const setText = (msg: string, ok?: boolean) => {
            if (!statusEl) return;
            statusEl.textContent = msg;
            statusEl.style.color = ok === false ? "var(--accent-neon)" : ok === true ? "var(--accent-cyan)" : "var(--text-muted)";
        };

        // Restore saved game path
        if (this.config.patcher_game_path) {
            const el = gamePathEl();
            if (el) el.value = this.config.patcher_game_path;
        }

        // Custom patch server toggle (in Launcher settings)
        const hyddwnChk = document.getElementById("patcher-hyddwn-enable") as HTMLInputElement | null;
        const hyddwnUrlRow = document.getElementById("patcher-hyddwn-url-row");
        const updateHyddwnRow = () => {
            if (hyddwnUrlRow) hyddwnUrlRow.style.display = this.config.patcher_hyddwn_enabled ? "" : "none";
        };
        if (hyddwnChk) hyddwnChk.checked = this.config.patcher_hyddwn_enabled;
        updateHyddwnRow();
        hyddwnChk?.addEventListener("change", () => {
            this.config.patcher_hyddwn_enabled = hyddwnChk.checked;
            updateHyddwnRow();
            this.saveConfig();
        });

        // Folder browse (directory picker)
        document.getElementById("btn-patcher-browse")?.addEventListener("click", async () => {
            const chosen = await open({ directory: true, title: this.t("dlg_select_mabi_folder") });
            if (!chosen) return;
            const p = typeof chosen === "string" ? chosen : (chosen as any).path ?? chosen[0];
            const el = gamePathEl();
            if (el) el.value = p;
            this.config.patcher_game_path = p;
            this.saveConfig();
        });
        gamePathEl()?.addEventListener("blur", () => {
            this.config.patcher_game_path = getGamePath();
            this.saveConfig();
        });

        // Check for updates
        document.getElementById("btn-patcher-check")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText(this.t("patcher_set_path_first"), false); return; }
            setText(this.t("patcher_checking"));
            this.log(this.t("log_patcher_checking_updates"));
            try {
                const res = await invoke("check_patch_version", { gamePath: gp, session: this.launcherSession }) as any;
                this.keepRefreshedSession(res.session);
                if (res.relogin_required) {
                    setText(this.t("launcher_session_expired"), false);
                    await this.promptRelogin();
                    return;
                }
                const localEl = document.getElementById("patcher-version-local");
                const remoteEl = document.getElementById("patcher-version-remote");
                if (localEl) localEl.textContent = String(res.local_version ?? "—");
                if (remoteEl) remoteEl.textContent = String(res.remote_version ?? "—");
                if (res.error && res.remote_version == null && !res.remote_hash) {
                    this.log(this.t("log_patcher_remote_check", [String(res.error)]));
                }
                if (res.needs_update) {
                    setText(this.t("patcher_update_available", [String(res.remote_version)]), false);
                    this.log(this.t("log_patcher_update_available", [String(res.local_version), String(res.remote_version)]));
                } else if (res.remote_version == null) {
                    setText(this.t("patcher_installed_ver", [String(res.local_version ?? "?")]), true);
                    this.log(this.t("log_patcher_local_ver_no_remote", [String(res.local_version ?? "?")]));
                } else {
                    setText(this.t("patcher_up_to_date"), true);
                    this.log(this.t("log_patcher_up_to_date", [String(res.local_version)]));
                }
            } catch(e) {
                if (this.isReloginError(e)) {
                    setText(this.t("launcher_session_expired"), false);
                    await this.promptRelogin();
                    return;
                }
                setText(this.t("patcher_check_failed", [this.cleanErr(e)]), false);
                this.log(this.t("log_patcher_check_error", [this.cleanErr(e)]));
            }
        });

        // Patch / Repair buttons
        document.getElementById("btn-patcher-patch")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText(this.t("patcher_set_path_first"), false); return; }
            await this.runPatcher(gp, false);
        });
        document.getElementById("btn-patcher-repair")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText(this.t("patcher_set_path_first"), false); return; }
            // Repair = SHA1-check every file and re-download only bad ones.
            await this.runPatcher(gp, false, true);
        });

        // Verify button
        document.getElementById("btn-patcher-verify")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText(this.t("patcher_set_path_first"), false); return; }
            setText(this.t("patcher_verifying"));
            this.log(this.t("log_patcher_verifying", [gp]));
            try {
                const res = await invoke("verify_game_files", { gamePath: gp }) as any;
                if (res.error && !res.version) { setText(this.t("msg_error_fmt", [String(res.error)]), false); this.log(this.t("msg_error_fmt", [String(res.error)])); return; }
                const managed = res.managed_version ?? res.version ?? 0;
                const local = res.local_version ?? res.version ?? 0;
                const bt = res.buildtime ? new Date(res.buildtime * 1000).toLocaleDateString() : "";
                const verLabel = (managed !== local) ? this.t("patcher_ver_local", [String(managed), String(local)]) : `v${managed}`;
                const header = verLabel + (bt ? ` (${bt})` : "") + " — " + this.t("patcher_verify_summary", [String(res.files_ok ?? 0), String(res.files_missing ?? 0), String(res.files_mismatched ?? 0)]);
                if (res.ok) {
                    setText(header, true);
                    this.log(this.t("log_patcher_verify_ok", [header]));
                    const localEl = document.getElementById("patcher-version-local");
                    if (localEl && local) localEl.textContent = String(local);
                } else {
                    const missStr = (res.missing ?? []).slice(0, 5).join(", ");
                    const mismStr = (res.mismatched ?? []).slice(0, 3).map((m: any) => m.path ?? m).join(", ");
                    setText(header, false);
                    this.log(this.t("log_patcher_verify_issues", [header]));
                    if (missStr) this.log(this.t("log_patcher_missing", [missStr]));
                    if (mismStr) this.log(this.t("log_patcher_wrong", [mismStr]));
                }
            } catch(e) {
                setText(this.t("msg_error_fmt", [String(e)]), false);
                this.log(this.t("log_patcher_verify_error", [String(e)]));
            }
        });

        // Stop button
        document.getElementById("btn-patcher-stop")?.addEventListener("click", () => {
            this.log(this.t("log_patcher_stop_requested"));
            invoke(this.scanRunning ? "patch_scan_cancel" : "patch_cancel").catch(() => {});
        });

        // Pause / Resume button (shown next to Stop while patching)
        document.getElementById("btn-patcher-pause")?.addEventListener("click", async () => {
            const pause = !this.patchPaused;
            try {
                await invoke(pause ? "patch_pause" : "patch_resume");
                this.setPatchPaused(pause);
                this.log(this.t(pause ? "log_patcher_paused" : "log_patcher_resumed"));
            } catch (e) {
                this.log(this.t("msg_error_fmt", [String(e)]), "error");
            }
        });

        // Choose which files to update
        document.getElementById("btn-patcher-scan")?.addEventListener("click", () => {
            const gp = getGamePath();
            if (!gp) { setText(this.t("patcher_set_path_first"), false); return; }
            this.scanPatchFiles(gp);
        });
        document.getElementById("btn-scan-select-all")?.addEventListener("click", () => this.setScanSelection(true));
        document.getElementById("btn-scan-select-none")?.addEventListener("click", () => this.setScanSelection(false));
        document.getElementById("btn-scan-close")?.addEventListener("click", () => {
            document.getElementById("patcher-scan-panel")?.classList.add("hidden");
        });
        document.getElementById("btn-scan-patch-selected")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText(this.t("patcher_set_path_first"), false); return; }
            const only = Array.from(document.querySelectorAll<HTMLInputElement>("#patcher-scan-list input[type=checkbox]:checked"))
                .map(cb => cb.dataset.path || "").filter(Boolean);
            if (only.length === 0) { setText(this.t("patcher_nothing_selected"), false); return; }
            document.getElementById("patcher-scan-panel")?.classList.add("hidden");
            await this.runPatcher(gp, false, false, only);
        });

        // Check all installs (Patcher tab)
        document.getElementById("btn-patcher-installs")?.addEventListener("click", () => this.checkAllInstalls("patcher-installs-panel"));

        // Settings > Patcher subtab wiring (elements live in stab-patcher but found by ID)
        const autoUpdateChk = document.getElementById("patcher-auto-update") as HTMLInputElement | null;
        const focusOnStartChk = document.getElementById("patcher-focus-on-start") as HTMLInputElement | null;
        const runElevatedChk = document.getElementById("patcher-run-elevated") as HTMLInputElement | null;
        const maxWorkersEl = document.getElementById("patcher-max-workers") as HTMLInputElement | null;
        const hyddwnUrlEl = document.getElementById("patcher-hyddwn-url") as HTMLInputElement | null;
        const launchNexonEl = document.getElementById("launch-use-nexon-launcher") as HTMLInputElement | null;
        const launchCmdEl = document.getElementById("launch-cmd-override") as HTMLTextAreaElement | null;
        const prePatchEl = document.getElementById("pre-patch-cmd") as HTMLTextAreaElement | null;
        const postPatchEl = document.getElementById("post-patch-cmd") as HTMLTextAreaElement | null;
        const preLaunchEl = document.getElementById("pre-launch-cmd") as HTMLTextAreaElement | null;
        const postLaunchEl = document.getElementById("post-launch-cmd") as HTMLTextAreaElement | null;
        const ignoreListEl = document.getElementById("patcher-ignore-list") as HTMLTextAreaElement | null;
        const productIdEl = document.getElementById("settings-product-id") as HTMLInputElement | null;

        if (autoUpdateChk) autoUpdateChk.checked = this.config.patcher_auto_update;
        if (focusOnStartChk) focusOnStartChk.checked = this.config.patcher_focus_on_start;
        if (runElevatedChk) runElevatedChk.checked = this.config.patcher_run_elevated ?? false;
        if (maxWorkersEl) maxWorkersEl.value = String(this.config.patcher_max_workers ?? 10);
        if (hyddwnUrlEl && this.config.patcher_hyddwn_url) hyddwnUrlEl.value = this.config.patcher_hyddwn_url;
        if (launchNexonEl) launchNexonEl.checked = this.config.launch_use_nexon_launcher ?? false;
        if (launchCmdEl) launchCmdEl.value = this.config.launch_cmd_override ?? "";
        if (productIdEl) productIdEl.value = String(this.config.product_id || 10200);
        // Hooks + ignore list come from the config shared with the CLI/REST API.
        this.loadSharedConfig().then(() => {
            const h = this.sharedConfig.hooks;
            if (prePatchEl) prePatchEl.value = h.before_patch ?? "";
            if (postPatchEl) postPatchEl.value = h.after_patch ?? "";
            if (preLaunchEl) preLaunchEl.value = h.before_launch ?? "";
            if (postLaunchEl) postLaunchEl.value = h.after_launch ?? "";
            if (ignoreListEl) ignoreListEl.value = this.sharedConfig.ignore.join("\n");
        });

        autoUpdateChk?.addEventListener("change", () => { this.config.patcher_auto_update = autoUpdateChk.checked; this.saveConfig(); });
        focusOnStartChk?.addEventListener("change", () => { this.config.patcher_focus_on_start = focusOnStartChk.checked; this.saveConfig(); });
        runElevatedChk?.addEventListener("change", () => { this.config.patcher_run_elevated = runElevatedChk.checked; this.saveConfig(); });
        maxWorkersEl?.addEventListener("change", () => {
            const v = parseInt(maxWorkersEl.value, 10);
            this.config.patcher_max_workers = isNaN(v) ? 10 : Math.min(32, Math.max(1, v));
            maxWorkersEl.value = String(this.config.patcher_max_workers);
            this.saveConfig();
        });
        hyddwnUrlEl?.addEventListener("blur", () => {
            this.config.patcher_hyddwn_url = hyddwnUrlEl.value.trim() || "http://127.0.0.1:11000";
            this.saveConfig();
        });
        launchNexonEl?.addEventListener("change", () => { this.config.launch_use_nexon_launcher = launchNexonEl.checked; this.saveConfig(); });
        launchCmdEl?.addEventListener("blur", () => { this.config.launch_cmd_override = launchCmdEl.value.trim(); this.saveConfig(); });
        prePatchEl?.addEventListener("blur", () => { this.sharedConfig.hooks.before_patch = prePatchEl.value.trim(); this.saveSharedConfig(); });
        postPatchEl?.addEventListener("blur", () => { this.sharedConfig.hooks.after_patch = postPatchEl.value.trim(); this.saveSharedConfig(); });
        preLaunchEl?.addEventListener("blur", () => { this.sharedConfig.hooks.before_launch = preLaunchEl.value.trim(); this.saveSharedConfig(); });
        postLaunchEl?.addEventListener("blur", () => { this.sharedConfig.hooks.after_launch = postLaunchEl.value.trim(); this.saveSharedConfig(); });
        ignoreListEl?.addEventListener("blur", () => {
            this.sharedConfig.ignore = ignoreListEl.value.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
            this.saveSharedConfig();
        });
        productIdEl?.addEventListener("change", () => {
            const v = parseInt(productIdEl.value, 10);
            this.config.product_id = isNaN(v) || v <= 0 ? 10200 : v;
            productIdEl.value = String(this.config.product_id);
            this.saveConfig();
            this.refreshNews();
        });

        // Patcher settings: version refresh + force re-download + clear cache
        document.getElementById("btn-patcher-settings-check")?.addEventListener("click", async () => {
            const gp = this.config.patcher_game_path;
            if (!gp) return;
            try {
                const res = await invoke("check_patch_version", { gamePath: gp, session: this.launcherSession }) as any;
                this.keepRefreshedSession(res.session);
                const el = document.getElementById("patcher-settings-version");
                if (el) el.textContent = `v${res.local_version ?? "?"}`;
                if (res.relogin_required) await this.promptRelogin();
            } catch {}
        });
        document.getElementById("btn-patcher-force-repair")?.addEventListener("click", async () => {
            const gp = this.config.patcher_game_path;
            if (!gp) return;
            document.querySelector('.nav-item[data-tab="patcher"]')?.dispatchEvent(new Event('click'));
            await this.runPatcher(gp, true);
        });
        document.getElementById("btn-patcher-clear-cache")?.addEventListener("click", async () => {
            const gp = this.config.patcher_game_path;
            if (!gp) return;
            const el = document.getElementById("patcher-settings-version");
            try {
                const res = await invoke("clear_patch_cache", { gamePath: gp }) as any;
                if (el) el.textContent = res.deleted ? this.t("patcher_cache_cleared") : this.t("patcher_no_cache");
            } catch(e) {
                if (el) el.textContent = this.t("msg_error_fmt", [String(e)]);
            }
        });

        // Progress event listeners
        import("./platform/event").then(({ listen }) => {
            // Global progress bar
            listen("patch-progress", (event: any) => {
                const e = event.payload as {
                    phase: string; current_file: string;
                    parts_done: number; parts_total: number;
                    files_done: number; files_total: number;
                    pct: number; speed_bps?: number; error?: string;
                };
                const wrap = document.getElementById("patcher-progress-wrap");
                const bar = document.getElementById("patcher-progress-bar");
                const detail = document.getElementById("patcher-progress-detail");
                const speedEl = document.getElementById("patcher-speed");
                const pipeBar = document.getElementById("dash-pipe-extract");
                const pipeLabel = document.getElementById("dash-pipe-label");
                const pipeCard = document.getElementById("dash-pipe-card");
                const stopBtn = document.getElementById("btn-patcher-stop");
                const pct = Math.round(e.pct);
                if (e.phase === "done" || e.phase === "error") {
                    if (wrap) wrap.style.display = "none";
                    if (pipeCard) pipeCard.style.display = "none";
                    if (pipeBar) pipeBar.style.width = "0%";
                    if (pipeLabel) pipeLabel.textContent = this.t("dash_pipe_idle");
                    if (stopBtn) stopBtn.style.display = "none";
                    this.setPatchPaused(false, true);
                    if (e.error) this.log(this.t("msg_error_fmt", [this.cleanErr(e.error)]));
                    // Clear all worker bars on completion
                    const barsEl = document.getElementById("patcher-bars");
                    if (barsEl) barsEl.innerHTML = "";
                    this.workerBars.clear();
                } else {
                    if (pipeCard) pipeCard.style.display = "";
                    if (wrap) wrap.style.display = "block";
                    if (bar) bar.style.width = pct + "%";
                    if (stopBtn) stopBtn.style.display = "";
                    const pauseBtnEl = document.getElementById("btn-patcher-pause");
                    if (pauseBtnEl) pauseBtnEl.style.display = "";
                    const info = e.phase === "downloading"
                        ? this.t("patcher_prog_parts", [String(e.parts_done), String(e.parts_total), String(pct)])
                        : e.phase === "scanning"
                        ? this.t("patcher_prog_scanning", [String(e.parts_done), String(e.parts_total), String(e.files_done)])
                        : this.t("patcher_prog_files", [String(e.files_done), String(e.files_total), String(pct)]);
                    const fileShort = e.current_file.length > 55 ? "..." + e.current_file.slice(-52) : e.current_file;
                    if (detail) detail.textContent = info + " — " + fileShort;
                    if (e.phase === "scanning" && e.parts_done === e.parts_total) {
                        this.log(this.t("log_patcher_scan_complete", [String(e.files_done), String(e.parts_total)]));
                    }
                    if (e.phase === "installing" && e.files_done > 0 && e.files_done % 50 === 0) {
                        this.log(this.t("log_patcher_installing_progress", [String(e.files_done), String(e.files_total), String(pct)]));
                    }
                    if (pipeBar) pipeBar.style.width = pct + "%";
                    if (pipeLabel) pipeLabel.textContent = this.t("dash_pipe_patching", [info]);
                    if (speedEl && e.speed_bps) {
                        const mb = (e.speed_bps / 1048576).toFixed(1);
                        speedEl.textContent = `${mb} MB/s`;
                    }
                }
            });

            // Per-worker bars (appear/disappear like HyddwnLauncher)
            listen("patch-worker", (event: any) => {
                const e = event.payload as { worker_id: number; phase: string; file_name: string; parts_done: number; parts_total: number; };
                const barsEl = document.getElementById("patcher-bars");
                if (!barsEl) return;
                const id = e.worker_id;
                const fileShort = e.file_name.length > 50
                    ? "..." + e.file_name.slice(-47) : e.file_name;
                if (e.phase === "done" || e.phase === "error") {
                    const bar = this.workerBars.get(id);
                    if (bar) {
                        bar.style.opacity = "0";
                        bar.style.transition = "opacity 0.4s";
                        setTimeout(() => { bar.remove(); }, 400);
                        this.workerBars.delete(id);
                    }
                } else {
                    let bar = this.workerBars.get(id);
                    if (!bar) {
                        bar = document.createElement("div");
                        bar.style.cssText = "display:flex;align-items:center;gap:6px;padding:2px 0;animation:fadeIn 0.2s";
                        const nameEl = document.createElement("span");
                        nameEl.className = "wbar-name";
                        nameEl.style.cssText = "font-size:0.7rem;color:var(--text-muted);width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex-shrink:0";
                        const track = document.createElement("div");
                        track.style.cssText = "flex:1;height:6px;background:var(--bg-input);border-radius:3px;overflow:hidden;position:relative";
                        const fill = document.createElement("div");
                        fill.className = "wbar-fill";
                        fill.style.cssText = "position:absolute;top:0;height:100%;background:var(--accent-cyan);border-radius:3px;width:0%;transition:width 0.15s";
                        const phaseEl = document.createElement("span");
                        phaseEl.className = "wbar-phase";
                        phaseEl.style.cssText = "font-size:0.65rem;color:var(--text-muted);width:90px;text-align:right;flex-shrink:0";
                        track.appendChild(fill);
                        bar.appendChild(nameEl);
                        bar.appendChild(track);
                        bar.appendChild(phaseEl);
                        barsEl.appendChild(bar);
                        this.workerBars.set(id, bar);
                    }
                    const nameEl = bar.querySelector(".wbar-name") as HTMLElement;
                    const phaseEl = bar.querySelector(".wbar-phase") as HTMLElement;
                    const fill = bar.querySelector(".wbar-fill") as HTMLElement;
                    if (nameEl) nameEl.textContent = fileShort;
                    if (e.phase === "assembling") {
                        const pct = e.parts_total > 0 ? Math.round(e.parts_done / e.parts_total * 100) : 0;
                        if (fill) { fill.style.animation = "none"; fill.style.width = pct + "%"; }
                        if (phaseEl) phaseEl.textContent = this.t("patcher_worker_installing", [String(e.parts_done), String(e.parts_total)]);
                        if (e.parts_done === 1) this.log(this.t("log_patcher_installing_file", [fileShort]));
                    } else {
                        if (fill) { fill.style.animation = "patcher-sweep 1.5s linear infinite"; fill.style.width = "40%"; }
                        if (phaseEl) phaseEl.textContent = this.t("patcher_worker_downloading");
                    }
                }
            });
        });
    }

    async runPatcher(gamePath: string, forceRepair: boolean, verifyOnly = false, only: string[] | null = null) {
        const statusEl = document.getElementById("patcher-status");
        const wrap = document.getElementById("patcher-progress-wrap");
        const bar = document.getElementById("patcher-progress-bar");
        const detail = document.getElementById("patcher-progress-detail");
        const pipeCard = document.getElementById("dash-pipe-card");
        const stopBtn = document.getElementById("btn-patcher-stop");
        const setText = (msg: string, ok?: boolean) => {
            if (statusEl) { statusEl.textContent = msg; statusEl.style.color = ok === false ? "var(--accent-neon)" : ok === true ? "var(--accent-cyan)" : "var(--text-muted)"; }
        };
        if (this.patchBusy) { setText(this.t("patcher_err_busy"), false); return; }
        const busyToken = this.setPatchBusy(true);
        if (pipeCard) pipeCard.style.display = "";
        if (wrap) wrap.style.display = "block";
        if (bar) bar.style.width = "0%";
        if (detail) detail.textContent = this.t("patcher_starting");
        if (stopBtn) stopBtn.style.display = "";
        this.setPatchPaused(false);
        const pauseBtn = document.getElementById("btn-patcher-pause");
        if (pauseBtn) pauseBtn.style.display = "";
        setText(forceRepair ? this.t("patcher_repairing") : this.t("patcher_patching"));
        this.log(forceRepair ? this.t("log_patcher_start_repair") : this.t("log_patcher_start_patch"));
        try {
            const maxWorkers = this.config.patcher_max_workers ?? 10;
            const parallelOps = this.config.parallel_ops ?? true;
            if (!this.launcherSession) {
                throw new Error(this.t("patcher_err_login_first"));
            }
            await this.loadSharedConfig();
            const res = await invoke("patch_game_files", {
                gamePath, maxWorkers, forceRepair, verify: verifyOnly, parallelOps,
                ignore: this.sharedConfig.ignore, session: this.launcherSession,
                prePatchCmd: this.sharedConfig.hooks.before_patch || null,
                postPatchCmd: this.sharedConfig.hooks.after_patch || null,
                only: only && only.length ? only : null,
                profileId: this.activeProfileId || null,
                profileName: this.activeProfileName() || null,
            }) as any;
            this.keepRefreshedSession(res.session);
            if (wrap) wrap.style.display = "none";
            if (pipeCard) pipeCard.style.display = "none";
            if (stopBtn) stopBtn.style.display = "none";
            this.setPatchPaused(false, true);
            if (res.managed_version) {
                const localEl = document.getElementById("patcher-version-local");
                if (localEl) localEl.textContent = String(res.managed_version);
            }
            if (res.needs_elevation) {
                setText(this.t("patcher_needs_admin"), false);
                this.log(this.t("log_patcher_perm_denied"));
                await invoke("request_elevation");
            } else if (res.ok) {
                const msg = res.patched === 0
                    ? this.t("log_patcher_up_to_date", [String(res.managed_version ?? "?")])
                    : this.t("patcher_patched_files", [String(res.patched), String(res.managed_version ?? "?")]);
                setText(msg, true);
                this.log(msg);
            } else if (res.message) {
                setText(res.message, true);
                this.log(res.message);
            } else {
                const errs = (res.errors ?? []).slice(0, 3).join("; ");
                setText(this.t("patcher_errors", [errs]), false);
                this.log(this.t("patcher_errors", [errs]));
            }
        } catch(e) {
            e = this.errWithSession(e);
            // Another patch/scan owns the install: leave its progress, Stop and
            // Pause controls alone.
            if (String(e) === "patch_busy") {
                setText(this.t("patcher_err_busy"), false);
                return;
            }
            if (wrap) wrap.style.display = "none";
            if (pipeCard) pipeCard.style.display = "none";
            if (stopBtn) stopBtn.style.display = "none";
            this.setPatchPaused(false, true);
            if (this.isReloginError(e)) {
                setText(this.t("launcher_session_expired"), false);
                this.log(this.t("msg_error_fmt", [this.cleanErr(e)]));
                await this.promptRelogin();
                return;
            }
            const errStr = String(e).toLowerCase();
            if (errStr.includes("access is denied") || errStr.includes("permissiondenied") || errStr.includes("permission denied")) {
                setText(this.t("patcher_needs_admin"), false);
                this.log(this.t("log_patcher_perm_denied"));
                await invoke("request_elevation");
            } else {
                setText(this.t("patcher_failed", [String(e)]), false);
                this.log(this.t("msg_error_fmt", [String(e)]));
            }
        } finally {
            this.releasePatchBusy(busyToken);
        }
    }

    /** Clear the busy state only if `token`'s run is the one that set it. */
    private releasePatchBusy(token: number) {
        if (this.patchBusy && this.patchBusyOwner === token) this.setPatchBusy(false);
    }

    /** Disable every button that starts a patch/scan while one runs. Returns
     *  the owner token for a `true` call (pass it to releasePatchBusy). */
    private setPatchBusy(busy: boolean): number {
        this.patchBusy = busy;
        this.patchBusyOwner = busy ? ++this.patchBusySeq : 0;
        for (const id of ["btn-patcher-patch", "btn-patcher-repair", "btn-patcher-scan", "btn-scan-patch-selected", "btn-patcher-force-repair"]) {
            const b = document.getElementById(id) as HTMLButtonElement | null;
            if (b) b.disabled = busy;
        }
        return this.patchBusyOwner;
    }



    /** Load the shared hooks/ignore config once (migrates old GUI values on first run). */
    private loadSharedConfig(): Promise<void> {
        if (!this.sharedConfigLoaded) {
            this.sharedConfigLoaded = invoke<SharedConfig>("shared_config_load").then(cfg => {
                this.sharedConfig = { ignore: cfg?.ignore ?? [], hooks: cfg?.hooks ?? {} };
            }).catch(e => {
                this.log(this.t("log_shared_config_failed", [String(e)]), "warn");
            });
        }
        return this.sharedConfigLoaded;
    }

    private async saveSharedConfig() {
        try {
            await invoke("shared_config_save", { config: this.sharedConfig });
        } catch (e) {
            this.log(this.t("log_shared_config_failed", [String(e)]), "warn");
        }
    }

    private activeProfileName(): string {
        return this.launcherProfiles.find(p => p.id === this.activeProfileId)?.name ?? "";
    }

    /** Reflect the pause state on the Pause/Resume button (optionally hiding it). */
    private setPatchPaused(paused: boolean, hide = false) {
        this.patchPaused = paused;
        const btn = document.getElementById("btn-patcher-pause");
        if (!btn) return;
        btn.textContent = this.t(paused ? "patcher_resume" : "patcher_pause");
        if (hide) btn.style.display = "none";
        else if (paused) btn.style.display = "";
    }

    private formatBytes(n: number): string {
        if (n >= 1073741824) return `${(n / 1073741824).toFixed(2)} GB`;
        if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
        if (n >= 1024) return `${(n / 1024).toFixed(0)} KB`;
        return `${n} B`;
    }

    /** Scan the install and list the files that need updating, with checkboxes. */
    private async scanPatchFiles(gamePath: string) {
        const statusEl = document.getElementById("patcher-status");
        const panel = document.getElementById("patcher-scan-panel");
        const list = document.getElementById("patcher-scan-list");
        const setText = (msg: string, ok?: boolean) => {
            if (statusEl) { statusEl.textContent = msg; statusEl.style.color = ok === false ? "var(--accent-neon)" : ok === true ? "var(--accent-cyan)" : "var(--text-muted)"; }
        };
        if (!this.launcherSession) { setText(this.t("patcher_err_login_first"), false); return; }
        if (this.patchBusy) { setText(this.t("patcher_err_busy"), false); return; }
        const busyToken = this.setPatchBusy(true);
        let busyRejected = false;
        this.scanRunning = true;
        const stopBtn = document.getElementById("btn-patcher-stop");
        if (stopBtn) stopBtn.style.display = "";
        setText(this.t("patcher_scanning_files"));
        this.log(this.t("log_patcher_scan_start", [gamePath]));
        try {
            await this.loadSharedConfig();
            const res = await invoke("patch_scan", {
                gamePath, verify: false, maxWorkers: this.config.patcher_max_workers ?? 10,
                ignore: this.sharedConfig.ignore, session: this.launcherSession,
                profileId: this.activeProfileId || null,
            }) as { need: NeedItem[]; session?: any; cancelled?: boolean };
            this.keepRefreshedSession(res.session);
            if (res.cancelled) {
                setText(this.t("patcher_scan_cancelled"), false);
                this.log(this.t("patcher_scan_cancelled"));
                panel?.classList.add("hidden");
                return;
            }
            const need = res.need ?? [];
            if (need.length === 0) {
                setText(this.t("patcher_up_to_date"), true);
                this.log(this.t("patcher_up_to_date"));
                panel?.classList.add("hidden");
                return;
            }
            if (list) {
                list.innerHTML = "";
                for (const item of need) {
                    const row = document.createElement("label");
                    row.className = "patcher-scan-row";
                    const cb = document.createElement("input");
                    cb.type = "checkbox";
                    cb.checked = true;
                    cb.dataset.path = item.path;
                    cb.dataset.size = String(item.size);
                    cb.addEventListener("change", () => this.updateScanSummary());
                    row.appendChild(cb);
                    row.appendChild(elText("span", "patcher-scan-path", item.path));
                    row.appendChild(elText("span", "patcher-scan-reason", this.scanReasonText(item.reason)));
                    row.appendChild(elText("span", "patcher-scan-size", this.formatBytes(item.size)));
                    list.appendChild(row);
                }
            }
            panel?.classList.remove("hidden");
            this.updateScanSummary();
            setText(this.t("patcher_scan_found", [String(need.length)]), false);
            this.log(this.t("patcher_scan_found", [String(need.length)]));
        } catch (e) {
            if (String(e) === "patch_busy") {
                // Another patch/scan owns the install: leave its Stop button alone.
                busyRejected = true;
                setText(this.t("patcher_err_busy"), false);
            } else {
                setText(this.t("patcher_check_failed", [String(e)]), false);
                this.log(this.t("msg_error_fmt", [String(e)]), "error");
            }
        } finally {
            if (stopBtn && !busyRejected) stopBtn.style.display = "none";
            this.scanRunning = false;
            this.releasePatchBusy(busyToken);
        }
    }

    private scanReasonText(reason: string): string {
        const map: Record<string, string> = {
            "New": "scan_reason_new",
            "Size changed": "scan_reason_size",
            "Content changed": "scan_reason_content",
            "Re-download": "scan_reason_redownload",
        };
        return map[reason] ? this.t(map[reason]) : reason;
    }

    private setScanSelection(checked: boolean) {
        document.querySelectorAll<HTMLInputElement>("#patcher-scan-list input[type=checkbox]").forEach(cb => { cb.checked = checked; });
        this.updateScanSummary();
    }

    private updateScanSummary() {
        const boxes = Array.from(document.querySelectorAll<HTMLInputElement>("#patcher-scan-list input[type=checkbox]"));
        const sel = boxes.filter(cb => cb.checked);
        const bytes = sel.reduce((sum, cb) => sum + (parseInt(cb.dataset.size || "0", 10) || 0), 0);
        const el = document.getElementById("patcher-scan-summary");
        if (el) el.textContent = this.t("patcher_scan_selected", [String(sel.length), String(boxes.length), this.formatBytes(bytes)]);
    }

    /** Detect every install on this PC, check each against Nexon, and list them in `panelId`. */
    private async checkAllInstalls(panelId: string) {
        const panel = document.getElementById(panelId);
        if (!panel) return;
        panel.classList.remove("hidden");
        panel.innerHTML = "";
        panel.appendChild(elText("div", "installs-note", this.t("installs_checking")));
        this.log(this.t("log_installs_checking"));
        const extra = [
            this.config.patcher_game_path,
            (document.getElementById("launcher-client-dir") as HTMLInputElement | null)?.value?.trim() ?? "",
            ...this.launcherProfiles.map(p => p.client_dir || ""),
        ].filter(Boolean);
        try {
            const res = await invoke("patch_check_all_installs", {
                extra, session: this.launcherSession || null, profileId: this.activeProfileId || null,
            }) as { folders: InstallStatus[]; session?: any };
            this.keepRefreshedSession(res.session);
            this.renderInstalls(panel, res.folders ?? []);
        } catch (e) {
            panel.innerHTML = "";
            panel.appendChild(elText("div", "installs-note", this.t("msg_error_fmt", [String(e)])));
            this.log(this.t("msg_error_fmt", [String(e)]), "error");
        }
    }

    private renderInstalls(panel: HTMLElement, folders: InstallStatus[]) {
        panel.innerHTML = "";
        const head = document.createElement("div");
        head.className = "installs-head";
        head.appendChild(elText("span", "", this.t("installs_title", [String(folders.length)])));
        const close = elText("button", "tab-btn", this.t("btn_close"));
        close.addEventListener("click", () => panel.classList.add("hidden"));
        head.appendChild(close);
        panel.appendChild(head);
        if (folders.length === 0) {
            panel.appendChild(elText("div", "installs-note", this.t("installs_none")));
            return;
        }
        for (const f of folders) {
            const row = document.createElement("div");
            row.className = "installs-row";
            const status = f.error
                ? (this.launcherSession ? this.t("installs_status_error") : this.t("installs_status_login"))
                : f.update_available ? this.t("installs_status_update") : this.t("installs_status_ok");
            const cls = f.error ? "unknown" : f.update_available ? "update" : "ok";
            const badge = elText("span", `installs-badge ${cls}`, status);
            if (f.error) badge.title = f.error;
            row.appendChild(badge);
            row.appendChild(elText("span", "installs-path", f.path));
            const patchBtn = elText("button", "tab-btn", this.t("installs_use_patch"));
            patchBtn.addEventListener("click", () => {
                const el = document.getElementById("patcher-game-path") as HTMLInputElement | null;
                if (el) el.value = f.path;
                this.config.patcher_game_path = f.path;
                this.saveConfig();
                this.log(this.t("log_installs_selected_patch", [f.path]));
                document.querySelector('.nav-item[data-tab="patcher"]')?.dispatchEvent(new Event('click'));
            });
            row.appendChild(patchBtn);
            const launchBtn = elText("button", "tab-btn", this.t("installs_use_launch"));
            launchBtn.disabled = !f.client_dir;
            launchBtn.addEventListener("click", () => {
                const el = document.getElementById("launcher-client-dir") as HTMLInputElement | null;
                if (el) el.value = f.client_dir;
                this.log(this.t("log_installs_selected_launch", [f.client_dir]));
                document.querySelector('.nav-item[data-tab="launcher"]')?.dispatchEvent(new Event('click'));
            });
            row.appendChild(launchBtn);
            panel.appendChild(row);
        }
    }

    // ── News (Dashboard) ────────────────────────────────────────────────────

    private setupNews() {
        document.getElementById("btn-news-refresh")?.addEventListener("click", () => this.refreshNews());
        this.refreshNews();
    }

    private async refreshNews() {
        const list = document.getElementById("dash-news-list");
        if (!list) return;
        let items: NewsItem[];
        try {
            items = await invoke<NewsItem[]>("fetch_news");
        } catch (e) {
            // Failures are a quiet log line; keep whatever is shown.
            this.log(this.t("log_news_failed", [String(e)]), "warn");
            if (!list.querySelector(".news-item")) {
                list.innerHTML = "";
                list.appendChild(elText("div", "activity-item no-activity", this.t("news_unavailable")));
            }
            return;
        }
        list.innerHTML = "";
        if (!items || items.length === 0) {
            list.appendChild(elText("div", "activity-item no-activity", this.t("news_empty")));
            return;
        }
        for (const n of items.slice(0, 12)) {
            const row = document.createElement("div");
            row.className = "news-item" + (n.maintenance ? " maintenance" : "");
            row.tabIndex = 0;
            row.title = n.summary || n.title;
            const meta = document.createElement("div");
            meta.className = "news-meta";
            const d = n.date ? new Date(n.date) : null;
            meta.appendChild(elText("span", "news-date", d && !isNaN(d.getTime()) ? d.toLocaleDateString() : n.date));
            meta.appendChild(elText("span", "news-cat", n.maintenance ? this.t("news_maintenance") : n.category));
            row.appendChild(meta);
            row.appendChild(elText("div", "news-title", n.title));
            const openIt = () => {
                if (!n.url) return;
                invoke("open_external_url", { url: n.url }).catch(e => this.log(this.t("msg_error_fmt", [String(e)]), "warn"));
            };
            row.addEventListener("click", openIt);
            row.addEventListener("keydown", (ev) => { if (ev.key === "Enter") openIt(); });
            list.appendChild(row);
        }
    }

    private setupDashboard() {
        const pollStats = async () => {
            try {
                const info = await invoke("get_system_info") as {
                    cpu_usage: number; memory_used_mb: number; memory_total_mb: number;
                    net_down_kbps: number; net_up_kbps: number; net_link_max_kbps: number;
                    disk_used_gb: number; disk_total_gb: number;
                };
                const set = (id: string, text: string) => { const el = document.getElementById(id); if (el) el.textContent = text; };

                this.setGauge("cpu-arc", info.cpu_usage);
                set("cpu-val", `${info.cpu_usage.toFixed(1)}%`);

                const memPct = info.memory_total_mb > 0 ? (info.memory_used_mb / info.memory_total_mb) * 100 : 0;
                this.setGauge("mem-arc", memPct);
                set("mem-val", `${info.memory_used_mb} / ${info.memory_total_mb} MB`);

                const diskPct = info.disk_total_gb > 0 ? (info.disk_used_gb / info.disk_total_gb) * 100 : 0;
                this.setGauge("disk-arc", diskPct);
                set("disk-val", `${info.disk_used_gb.toFixed(0)} / ${info.disk_total_gb.toFixed(0)} GB`);

                const totalNetKbps = info.net_down_kbps + info.net_up_kbps;
                const linkMax = info.net_link_max_kbps > 0 ? info.net_link_max_kbps : 100_000;
                const netPct = Math.min(100, (totalNetKbps / linkMax) * 100);
                this.setGauge("net-arc", netPct);
                const fmt = (kbps: number) => kbps >= 1024 ? `${(kbps/1024).toFixed(1)} MB/s` : `${kbps} KB/s`;
                set("net-val", `↓${fmt(info.net_down_kbps)} ↑${fmt(info.net_up_kbps)}`);
            } catch (_) {}
        };
        setTimeout(() => { pollStats(); setInterval(pollStats, 2000); }, 1800);
        this.refreshModsList();
        this.setupModsActions();
    }

    /** Reflect modBrowserMode in the Mods tab: toggle buttons + online toolbar. */
    private syncModsViewUI() {
        const remote = this.modBrowserMode === 'remote';
        document.getElementById("btn-mods-view-local")?.classList.toggle("active", !remote);
        document.getElementById("btn-mods-view-online")?.classList.toggle("active", remote);
        const toolbar = document.getElementById("mods-online-toolbar");
        if (toolbar) toolbar.style.display = remote ? "" : "none";
    }

    /** Show the in-app API's state on the Mods tab badge. */
    private async refreshApiBadge() {
        const badge = document.getElementById("mods-api-badge");
        if (!badge) return;
        try {
            const port = await invoke<number>("get_api_port");
            badge.textContent = port > 0 ? `API :${port}` : this.t("api_badge_off");
            badge.classList.toggle("api-badge-off", port === 0);
        } catch (_) {
            badge.style.display = "none";
        }
    }

    private async refreshModsList() {
        this.syncModsViewUI();
        if (this.modBrowserMode === 'remote') {
            await this.refreshRemoteMods();
            return;
        }
        const list  = document.getElementById("mods-list");
        const empty = document.getElementById("mods-empty");
        const path  = document.getElementById("mods-path");
        if (!list) return;
        list.querySelectorAll(".mod-item").forEach(el => el.remove());
        if (empty) { empty.textContent = this.t("mods_empty_local"); empty.style.display = ""; }
        try {
            const dir  = await invoke("get_mods_dir") as string;
            const mods = await invoke("list_mod_files") as Array<{
                file: string; name: string; version?: string; author?: string;
                description?: string; tags?: string[]; file_count: number; is_public: boolean; error?: string;
            }>;
            if (this.modBrowserMode !== 'local') return; // switched views while loading
            if (path) path.textContent = dir;
            list.querySelectorAll(".mod-item").forEach(el => el.remove());
            if (empty) empty.style.display = mods.length === 0 ? "" : "none";
            // .mod metadata is user-supplied: build rows with textContent only.
            for (const m of mods) {
                const el = elText("div", "mod-item");
                if (m.error) {
                    el.append(elText("span", "mod-item-name", m.file), elText("span", "mod-item-err", m.error));
                } else {
                    const header = elText("div", "mod-item-header");
                    header.append(elText("span", "mod-item-name", m.name));
                    if (m.is_public) header.append(elText("span", "mod-item-badge-pub", this.t("mod_public")));
                    const btn = elText("button", "tab-btn mod-apply-btn", this.t("mod_apply"));
                    btn.style.marginLeft = "auto";
                    btn.addEventListener("click", async () => {
                        await this.applyModFromDashboard(dir + "/" + m.file);
                    });
                    header.append(btn);
                    const byline = [m.version, m.author].filter(Boolean) as string[];
                    byline.push(this.t("mod_file_count", [String(m.file_count)]));
                    const meta = elText("div", "mod-item-meta", byline.join(" · "));
                    for (const tag of m.tags ?? []) meta.append(elText("span", "mod-tag", tag));
                    el.append(header, meta);
                    if (m.description) el.append(elText("div", "mod-item-desc", m.description));
                }
                list.insertBefore(el, empty);
            }
        } catch (e) {
            if (empty) { empty.textContent = String(e); empty.style.display = ""; }
        }
    }

    /** Catalog source: config override or the website's Mods page. http(s) only. */
    private modCatalogUrl(): string {
        const u = (this.config.mod_remote_url || "").trim();
        return /^https?:\/\//i.test(u) ? u : DEFAULT_MOD_CATALOG_URL;
    }

    /** The website builds packages at `<origin>/api/pack` (POST {selected, format}). */
    private modPackUrl(): string {
        try { return new URL(this.modCatalogUrl()).origin + "/api/pack"; }
        catch { return new URL(DEFAULT_MOD_CATALOG_URL).origin + "/api/pack"; }
    }

    private async refreshRemoteMods(force = false) {
        const list  = document.getElementById("mods-list");
        const empty = document.getElementById("mods-empty");
        const path  = document.getElementById("mods-path");
        if (!list) return;
        const url = this.modCatalogUrl();
        if (path) path.textContent = url;
        list.querySelectorAll(".mod-item").forEach(el => el.remove());
        if (!this.webModCatalog || force) {
            if (empty) { empty.textContent = this.t("mods_loading"); empty.style.display = ""; }
            try {
                // Fetched in Rust (no CORS); the site has no JSON list, so the
                // command reads the catalog out of the Mods page's JS bundle.
                const raw = await invoke("fetch_web_mods_catalog", { url }) as unknown;
                const arr: unknown[] = Array.isArray(raw) ? raw
                    : (raw && Array.isArray((raw as any).mods)) ? (raw as any).mods : [];
                this.webModCatalog = arr.filter((m): m is WebMod =>
                    !!m && typeof (m as any).id === "number" && typeof (m as any).name === "string");
                this.populateModCategories();
            } catch (e) {
                if (this.modBrowserMode === 'remote' && empty) {
                    empty.textContent = this.t("mods_catalog_failed", [String(e)]);
                    empty.style.display = "";
                }
                return;
            }
        }
        await this.refreshInstalledWebMods();
        if (this.modBrowserMode === 'remote') this.renderRemoteMods();
    }

    private async refreshInstalledWebMods() {
        try { this.webModsInstalled = new Set(await invoke("list_installed_web_mods") as number[]); }
        catch { /* keep previous set */ }
    }

    private populateModCategories() {
        const sel = document.getElementById("mods-category") as HTMLSelectElement | null;
        if (!sel || !this.webModCatalog) return;
        const current = sel.value;
        while (sel.options.length > 1) sel.remove(1);
        const cats = [...new Set(this.webModCatalog.map(m => m.category).filter(Boolean) as string[])].sort();
        for (const c of cats) {
            const o = document.createElement("option");
            o.value = c;
            o.textContent = c;
            sel.append(o);
        }
        sel.value = cats.includes(current) ? current : "";
    }

    /** Render the website catalog with the current search / category / installed filters. */
    private renderRemoteMods() {
        const list  = document.getElementById("mods-list");
        const empty = document.getElementById("mods-empty");
        if (!list || !this.webModCatalog) return;
        const q   = ((document.getElementById("mods-search") as HTMLInputElement | null)?.value || "").trim().toLowerCase();
        const cat = (document.getElementById("mods-category") as HTMLSelectElement | null)?.value || "";
        const installedOnly = (document.getElementById("mods-installed-only") as HTMLInputElement | null)?.checked ?? false;
        const shown = this.webModCatalog.filter(m =>
            (!cat || m.category === cat) &&
            (!installedOnly || this.webModsInstalled.has(m.id)) &&
            (!q || [m.name, m.description, m.author, m.category, ...(m.tags ?? [])]
                .some(s => (s || "").toLowerCase().includes(q))));

        const scroll = list.scrollTop;
        list.querySelectorAll(".mod-item").forEach(el => el.remove());
        const count = document.getElementById("mods-count");
        if (count) count.textContent = this.t("mods_count", [
            String(shown.length), String(this.webModCatalog.length), String(this.webModsInstalled.size)]);
        if (empty) {
            empty.textContent = this.webModCatalog.length === 0 ? this.t("mod_no_remote") : this.t("mods_no_match");
            empty.style.display = shown.length === 0 ? "" : "none";
        }
        // Website data is remote: build rows with textContent only.
        for (const m of shown) list.insertBefore(this.buildWebModRow(m), empty);
        list.scrollTop = scroll;
    }

    private buildWebModRow(m: WebMod): HTMLElement {
        const installed = this.webModsInstalled.has(m.id);
        const el = elText("div", installed ? "mod-item installed" : "mod-item");
        const header = elText("div", "mod-item-header");
        header.append(elText("span", "mod-item-name", m.name));
        header.append(elText("span", "mod-item-id", `MOD${String(m.id).padStart(4, "0")}`));
        if (installed) header.append(elText("span", "mod-item-badge-installed", this.t("mod_install_ok")));
        if (m.hasDelete) header.append(elText("span", "mod-item-badge-delete", this.t("mods_deletes_badge")));

        const actions = elText("span", "mod-item-actions");
        const installBtn = elText("button", "tab-btn", this.t(installed ? "mods_reinstall" : "mod_install"));
        installBtn.addEventListener("click", async () => {
            const format = (document.getElementById("mods-format") as HTMLSelectElement | null)?.value === "pack" ? "pack" : "it";
            installBtn.disabled = true;
            installBtn.textContent = this.t("mod_installing");
            try {
                const saved = await invoke("install_web_mod", {
                    packUrl: this.modPackUrl(), id: m.id, name: m.name, format,
                }) as string;
                this.webModsInstalled.add(m.id);
                this.log(this.t("log_mods_web_installed", [m.name, saved]), "info");
                this.renderRemoteMods();
            } catch (e) {
                installBtn.disabled = false;
                installBtn.textContent = this.t(installed ? "mods_reinstall" : "mod_install");
                this.log(this.t("log_mods_install_failed", [String(e)]), "error");
            }
        });
        actions.append(installBtn);
        if (installed) {
            const removeBtn = elText("button", "tab-btn", this.t("mods_remove"));
            removeBtn.addEventListener("click", async () => {
                removeBtn.disabled = true;
                try {
                    await invoke("remove_web_mod", { id: m.id });
                    this.webModsInstalled.delete(m.id);
                    this.log(this.t("log_mods_web_removed", [m.name]), "info");
                    this.renderRemoteMods();
                } catch (e) {
                    removeBtn.disabled = false;
                    this.log(this.t("log_mods_install_failed", [String(e)]), "error");
                }
            });
            actions.append(removeBtn);
        }
        header.append(actions);

        const byline: string[] = [];
        if (m.version) byline.push(`v${m.version}`);
        if (m.author) byline.push(m.author);
        if (typeof m.files === "number") byline.push(this.t("mod_file_count", [String(m.files)]));
        const meta = elText("div", "mod-item-meta", byline.join(" · "));
        if (m.category) meta.append(elText("span", "mod-tag", m.category));
        for (const tag of m.tags ?? []) meta.append(elText("span", "mod-tag", tag));
        el.append(header, meta);
        // The site's descriptions often just repeat the name; skip those.
        if (m.description && m.description !== m.name) el.append(elText("div", "mod-item-desc", m.description));
        return el;
    }

    private async applyModFromDashboard(modFilePath: string) {
        try {
            const { open } = await import("./platform/dialog");
            const archivePath = await open({
                title: this.t("dlg_select_target_archive"),
                filters: [{ name: this.t("dlg_filter_archive"), extensions: ["it", "pack"] }],
            });
            if (!archivePath) return;
            const archStr = typeof archivePath === "string" ? archivePath : (archivePath as any).path ?? (archivePath as any[])[0];
            const toml = await invoke("load_mod_file", { path: modFilePath }) as string;
            const modDir = modFilePath.replace(/[\\/][^\\/]+$/, "");
            const result = await invoke("apply_mod", {
                modToml: toml,
                archive: archStr,
                key: null,
                modDir,
            }) as any;
            alert(this.t("mod_applied_summary", [String(result.name), String(result.replaced), String(result.deleted), String(result.patched)]));
        } catch (err) { alert(this.t("mod_apply_failed", [String(err)])); }
    }

    private setupModsActions() {
        document.getElementById("btn-open-mods-dir")?.addEventListener("click", async () => {
            try {
                const dir = await invoke("get_mods_dir") as string;
                await invoke("execute_terminal_command", { command: `explorer "${dir}"` });
                this.log(this.t("log_mods_opened_dir", [dir]), "info");
            } catch (e) { this.log(this.t("log_mods_open_dir_failed", [String(e)]), "error"); }
        });
        document.getElementById("btn-new-mod-template")?.addEventListener("click", async () => {
            try {
                const tmpl = await invoke("get_mod_template") as string;
                const dir  = await invoke("get_mods_dir") as string;
                const dest = dir + "\\new_mod.mod";
                await writeTextFile(dest, tmpl);
                await invoke("execute_terminal_command", { command: `explorer /select,"${dest}"` });
                this.log(this.t("log_mods_template_created", [dest]), "info");
            } catch (e) { this.log(this.t("log_mods_template_failed", [String(e)]), "error"); }
        });

        // Local / Online (website) view toggle
        const setView = (mode: 'local' | 'remote') => {
            if (this.modBrowserMode === mode) return;
            this.modBrowserMode = mode;
            this.refreshModsList();
        };
        document.getElementById("btn-mods-view-local")?.addEventListener("click", () => setView('local'));
        document.getElementById("btn-mods-view-online")?.addEventListener("click", () => setView('remote'));
        document.getElementById("btn-mods-refresh")?.addEventListener("click", () => {
            if (this.modBrowserMode === 'remote') this.refreshRemoteMods(true);
            else this.refreshModsList();
        });
        document.getElementById("mods-search")?.addEventListener("input", () => this.renderRemoteMods());
        document.getElementById("mods-category")?.addEventListener("change", () => this.renderRemoteMods());
        document.getElementById("mods-installed-only")?.addEventListener("change", () => this.renderRemoteMods());
    }

    // ── VFS editing ─────────────────────────────────────────────────────────────

    private vfsPending: Array<{op: string; [k: string]: any}> = [];

    // Tree selection (keys "f:<entry name>" for files, "d:<folder path>" for folders)
    private vfsSel = new Set<string>();
    private vfsSelAnchor: string | null = null;
    // Pointer-based row drag (HTML5 DnD is swallowed by Tauri's native drop handler)
    private vfsDrag: {
        key: string; x: number; y: number; pointerId: number; active: boolean;
        ghost: HTMLElement | null; target: { folder: string; row: HTMLElement | null } | null;
    } | null = null;
    private vfsSuppressClick = false;

    private setupVfsEditing() {
        const tree = document.getElementById("file-tree")!;
        const toolbar = document.getElementById("vfs-toolbar")!;

        // Files dragged in from Explorer arrive as tauri://drag-* events (with paths and a
        // physical-pixel position), not as HTML5 drop events: highlight the hovered folder.
        listen("tauri://drag-enter", (event) => this.vfsExternalHover((event.payload as any)?.position));
        listen("tauri://drag-over", (event) => this.vfsExternalHover((event.payload as any)?.position));
        listen("tauri://drag-leave", () => this.vfsExternalHover(null));

        // Selection: click = single, Ctrl+click = toggle, Shift+click = range
        tree.addEventListener("click", (e) => {
            if (this.vfsSuppressClick) { e.stopPropagation(); e.preventDefault(); return; }
            const t = e.target as HTMLElement;
            if (t.closest("input")) return;
            const row = t.closest<HTMLElement>(".tree-row.folder, .tree-item");
            const key = row ? this.vfsRowKey(row) : null;
            if (!key) return;
            if (e.ctrlKey || e.metaKey) {
                if (this.vfsSel.has(key)) this.vfsSel.delete(key); else this.vfsSel.add(key);
                this.vfsSelAnchor = key;
                this.vfsPaintSelection();
                e.stopPropagation(); e.preventDefault();
                return;
            }
            if (e.shiftKey && this.vfsSelAnchor) {
                const rows = this.vfsVisibleRows();
                const keys = rows.map(r => this.vfsRowKey(r));
                const a = keys.indexOf(this.vfsSelAnchor), b = keys.indexOf(key);
                if (a >= 0 && b >= 0) {
                    this.vfsSel = new Set(keys.slice(Math.min(a, b), Math.max(a, b) + 1).filter((k): k is string => !!k));
                    this.vfsPaintSelection();
                    e.stopPropagation(); e.preventDefault();
                    return;
                }
            }
            this.vfsSel = new Set([key]);
            this.vfsSelAnchor = key;
            this.vfsPaintSelection();
        }, true);

        // Row dragging: move inside the tree, or drag out of the window to extract
        tree.addEventListener("pointerdown", (e) => {
            if (e.button !== 0 || this.loadedEntries.length === 0) return;
            const t = e.target as HTMLElement;
            if (t.closest("input")) return;
            const row = t.closest<HTMLElement>(".tree-row.folder, .tree-item");
            const key = row ? this.vfsRowKey(row) : null;
            if (!key) return;
            this.vfsDrag = { key, x: e.clientX, y: e.clientY, pointerId: e.pointerId, active: false, ghost: null, target: null };
        });
        document.addEventListener("pointermove", (e) => {
            const d = this.vfsDrag;
            if (!d) return;
            if (!(e.buttons & 1)) { this.vfsEndDrag(); return; }
            if (!d.active) {
                if (Math.hypot(e.clientX - d.x, e.clientY - d.y) < 6) return;
                d.active = true;
                if (!this.vfsSel.has(d.key)) { this.vfsSel = new Set([d.key]); this.vfsSelAnchor = d.key; this.vfsPaintSelection(); }
                try { tree.setPointerCapture(d.pointerId); } catch { /* capture is best-effort */ }
                const ghost = document.createElement("div");
                ghost.className = "vfs-drag-ghost";
                ghost.textContent = this.t("vfs_drag_items", [String(this.vfsSelectionItems().length)]);
                document.body.appendChild(ghost);
                d.ghost = ghost;
            }
            if (d.ghost) { d.ghost.style.left = `${e.clientX + 14}px`; d.ghost.style.top = `${e.clientY + 10}px`; }
            if (e.clientX <= 0 || e.clientY <= 0 || e.clientX >= window.innerWidth - 1 || e.clientY >= window.innerHeight - 1) {
                this.vfsStartDragOut();
                return;
            }
            d.target = this.vfsDropTargetAt(document.elementFromPoint(e.clientX, e.clientY));
            this.vfsHighlightTarget(d.target);
        });
        // Leaving the viewport with the button held hands the drag to the OS (drag-out)
        document.documentElement.addEventListener("pointerleave", () => {
            if (this.vfsDrag?.active) this.vfsStartDragOut();
        });
        document.addEventListener("pointerup", () => {
            const d = this.vfsDrag;
            if (!d) return;
            const target = d.active ? d.target : null;
            const wasActive = d.active;
            this.vfsEndDrag();
            if (wasActive) {
                this.vfsSuppressClick = true;
                setTimeout(() => { this.vfsSuppressClick = false; }, 0);
            }
            if (target) this.vfsMoveSelectionTo(target.folder);
        });

        // Delete = queue delete, F2 = rename, Esc = cancel a row drag
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && this.vfsDrag) { this.vfsEndDrag(); return; }
            if (e.key !== "Delete" && e.key !== "F2") return;
            if (!document.getElementById("list")?.classList.contains("active")) return;
            const t = e.target as HTMLElement;
            if (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable) return;
            if (!document.getElementById("conflict-dialog")?.classList.contains("hidden")) return;
            if (this.vfsSel.size === 0 || !this.vfsCanEdit()) return;
            e.preventDefault();
            if (e.key === "Delete") this.vfsDeleteSelection();
            else this.vfsRenameSelection();
        });

        // Right-click on tree items → unified context menu
        tree.addEventListener("contextmenu", (e) => {
            if (!this.currentArchive) return;
            const row = (e.target as HTMLElement).closest<HTMLElement>(".tree-item, .tree-row");
            if (!row) return;
            e.preventDefault();
            const path = row.dataset.path ?? "";
            const rowKey = this.vfsRowKey(row);
            if (rowKey && !this.vfsSel.has(rowKey)) {
                this.vfsSel = new Set([rowKey]);
                this.vfsSelAnchor = rowKey;
                this.vfsPaintSelection();
            }
            // Build a synthetic entry so showContextMenu can work
            const syntheticEntry = this.loadedEntries.find(en => en.name === path) ?? {
                name: path, source_archive: this.currentArchive, salt_used: "",
                entries_salt_used: "", original_size: 0, raw_size: 0,
                offset: 0, checksum: 0, flags: 0, key: [], iv0: 0, h_off: 0, mode: ""
            } as AggregateEntry;
            this.showContextMenu(e, syntheticEntry);
            // Selection-aware actions (folders and multi-select)
            const isFolder = row.classList.contains("folder");
            const extractBtn = document.getElementById("menu-extract");
            if (extractBtn && isFolder) extractBtn.style.display = "none";
            const extractSel = document.getElementById("menu-extract-sel");
            if (extractSel) {
                extractSel.style.display = "block";
                extractSel.onclick = () => this.vfsExtractSelection();
            }
            const canEdit = this.vfsCanEdit();
            const renameBtn = document.getElementById("menu-rename");
            const deleteBtn = document.getElementById("menu-delete");
            if (renameBtn) {
                renameBtn.style.display = canEdit && this.vfsSel.size === 1 ? "block" : "none";
                renameBtn.onclick = () => this.vfsRenameSelection();
            }
            if (deleteBtn) {
                deleteBtn.style.display = canEdit ? "block" : "none";
                deleteBtn.onclick = () => this.vfsDeleteSelection();
            }
        });

        // Merge archive button
        document.getElementById("btn-vfs-merge")?.addEventListener("click", async () => {
            if (!this.vfsCanEdit()) return;
            try {
                const { open } = await import("./platform/dialog");
                const chosen = await open({ filters: [{ name: this.t("dlg_filter_archive"), extensions: ["it", "pack"] }] });
                if (!chosen) return;
                const srcPath = typeof chosen === "string" ? chosen : (chosen as any).path ?? chosen[0];
                await this.vfsQueueMerge(srcPath);
            } catch (err) {
                this.log(this.t("log_vfs_merge_error", [String(err)]), "error");
            }
        });

        // Apply button
        document.getElementById("btn-vfs-apply")?.addEventListener("click", async () => {
            if (!this.currentArchive || this.vfsPending.length === 0) return;
            const btn = document.getElementById("btn-vfs-apply")!;
            btn.textContent = this.t("vfs_applying");
            btn.setAttribute("disabled", "true");
            this.log(this.t("log_vfs_applying", [String(this.vfsPending.length), this.currentArchive]), "info");
            try {
                const result = await invoke("apply_vfs_changes", {
                    archive: this.currentArchive,
                    key: null,
                    changes: this.vfsPending,
                }) as any;
                this.vfsPending = [];
                this.renderVfsPending();
                this.log(this.t("log_vfs_applied", [String(result.changes), JSON.stringify(result.stats)]), "info");
                // Reload the archive listing
                await this.listArchive(this.currentArchive);
            } catch (err) {
                this.log(this.t("log_vfs_apply_failed", [String(err)]), "error");
            }
            btn.textContent = this.t("btn_vfs_apply");
            btn.removeAttribute("disabled");
        });

        // Reset button
        document.getElementById("btn-vfs-reset")?.addEventListener("click", () => {
            const count = this.vfsPending.length;
            this.vfsPending = [];
            this.renderVfsPending();
            // Re-render tree without pending overlays
            const items = document.querySelectorAll<HTMLElement>(".tree-item, .tree-row");
            items.forEach(i => { i.classList.remove("vfs-delete", "vfs-add", "vfs-rename"); });
            this.log(this.t("log_vfs_reset", [String(count)]), "info");
        });

        // Show toolbar only when an archive is loaded
        const showToolbar = () => {
            if (this.currentArchive) toolbar.classList.remove("hidden");
        };
        document.getElementById("btn-browse-list")?.addEventListener("click", showToolbar);
    }

    /** Fire-and-forget: persist vfsPending to <archive>.pending.json. */
    private savePendingChanges() {
        if (!this.currentArchive) return;
        invoke("save_pending_changes", {
            archive: this.currentArchive,
            changes: this.vfsPending,
        }).catch((e: unknown) => console.warn("[VFS] Could not persist pending changes:", e));
    }

    private renderVfsPending() {
        const badge = document.getElementById("vfs-pending-badge");
        if (badge) badge.textContent = this.t("vfs_pending_count", [String(this.vfsPending.length)]);
        // Persist to disk (fire-and-forget)
        this.savePendingChanges();
        // Overlay tree items with pending-change decorations
        const tree = document.getElementById("file-tree")!;
        // Reset existing overlays
        tree.querySelectorAll<HTMLElement>(".tree-item, .tree-row").forEach(r => {
            r.classList.remove("vfs-delete", "vfs-add", "vfs-rename");
        });
        for (const ch of this.vfsPending) {
            if (ch.op === "delete") {
                const el = tree.querySelector<HTMLElement>(`[data-path="${ch.path}"]`);
                if (el) el.classList.add("vfs-delete");
            } else if (ch.op === "rename") {
                const el = tree.querySelector<HTMLElement>(`[data-path="${ch.from}"]`);
                if (el) el.classList.add("vfs-rename");
            }
        }
        // Show "add" badges at the bottom of the tree
        const existing = tree.querySelectorAll(".vfs-add-item");
        existing.forEach(e => e.remove());
        for (const ch of this.vfsPending) {
            if (ch.op === "add") {
                const row = document.createElement("div");
                row.className = "tree-item vfs-add vfs-add-item";
                row.textContent = `+ ${ch.dest}`;
                tree.appendChild(row);
            }
        }
    }

    // ── VFS tree helpers (selection, drag & drop, moves) ─────────────────────────

    /** Archive paths use `/`, `\` or the regional `¥`/`₩` separators; compare with `/`. */
    private vfsNorm(p: string): string { return p.replace(/[\\¥₩]/g, "/").replace(/^\/+/, ""); }
    private vfsKey(p: string): string { return this.vfsNorm(p).toLowerCase(); }
    private vfsBase(p: string): string { const n = this.vfsNorm(p).replace(/\/+$/, ""); return n.slice(n.lastIndexOf("/") + 1); }
    /** Parent folder with a trailing `/`, or "" at the root. */
    private vfsParent(p: string): string { const n = this.vfsNorm(p).replace(/\/+$/, ""); const i = n.lastIndexOf("/"); return i < 0 ? "" : n.slice(0, i + 1); }

    /** Editing needs a single .it/.pack (not a full-sequence folder view). */
    private vfsCanEdit(): boolean {
        const a = this.currentArchive.toLowerCase();
        return a.endsWith(".it") || a.endsWith(".pack");
    }

    private vfsKeyOf(e: AggregateEntry): string | null {
        return e.source_archive ? (e.salt_used === "N/A" || e.salt_used === "Search/Default" || !e.salt_used ? null : e.salt_used) : null;
    }

    private vfsRowKey(row: HTMLElement): string | null {
        if (row.classList.contains("vfs-add-item")) return null;
        const p = row.dataset.path;
        if (p === undefined || p === "") return null;
        return (row.classList.contains("folder") ? "d:" : "f:") + p;
    }

    private vfsVisibleRows(): HTMLElement[] {
        const tree = document.getElementById("file-tree");
        if (!tree) return [];
        return Array.from(tree.querySelectorAll<HTMLElement>(".tree-row.folder, .tree-item"))
            .filter(r => !r.classList.contains("vfs-add-item") && r.offsetParent !== null);
    }

    private vfsPaintSelection() {
        const tree = document.getElementById("file-tree");
        if (!tree) return;
        tree.querySelectorAll<HTMLElement>(".tree-row.folder, .tree-item").forEach(r => {
            const k = this.vfsRowKey(r);
            r.classList.toggle("vfs-sel", !!k && this.vfsSel.has(k));
        });
    }

    /** Selected entries, each with the path it keeps relative to its parent folder
     *  (a selected folder brings everything under it, under the folder's own name). */
    private vfsSelectionItems(): Array<{ entry: AggregateEntry; rel: string; folder: string | null }> {
        const out = new Map<string, { entry: AggregateEntry; rel: string; folder: string | null }>();
        const keys = Array.from(this.vfsSel);
        const folders = keys.filter(k => k.startsWith("d:")).map(k => k.slice(2)).sort((a, b) => a.length - b.length);
        for (const f of folders) {
            const prefix = this.vfsKey(f).replace(/\/?$/, "/");
            const name = this.vfsBase(f);
            for (const e of this.loadedEntries) {
                const k = this.vfsKey(e.name);
                if (!k.startsWith(prefix) || out.has(e.name)) continue;
                out.set(e.name, { entry: e, rel: name + "/" + this.vfsNorm(e.name).slice(prefix.length), folder: f });
            }
        }
        const fileKeys = keys.filter(k => k.startsWith("f:"));
        const byName = fileKeys.length ? new Map(this.loadedEntries.map(e => [e.name, e] as const)) : new Map<string, AggregateEntry>();
        for (const k of fileKeys) {
            const e = byName.get(k.slice(2));
            if (e && !out.has(e.name)) out.set(e.name, { entry: e, rel: this.vfsBase(e.name), folder: null });
        }
        return Array.from(out.values());
    }

    /** Folder (with trailing `/`, "" = root) under an element of the tree, or null outside the tree. */
    private vfsDropTargetAt(el: Element | null): { folder: string; row: HTMLElement | null } | null {
        const tree = document.getElementById("file-tree");
        if (!el || !tree || !tree.contains(el)) return null;
        const row = el.closest<HTMLElement>(".tree-row.folder, .tree-item");
        if (row && row.classList.contains("folder") && row.dataset.path) {
            return { folder: this.vfsNorm(row.dataset.path) + "/", row };
        }
        if (row && row.dataset.path && !row.classList.contains("vfs-add-item")) {
            const parentRow = row.closest(".tree-node")?.querySelector<HTMLElement>(":scope > .tree-row.folder") ?? null;
            return { folder: this.vfsParent(row.dataset.path), row: parentRow };
        }
        return { folder: "", row: null };
    }

    private vfsHighlightTarget(target: { folder: string; row: HTMLElement | null } | null) {
        const tree = document.getElementById("file-tree");
        if (!tree) return;
        tree.querySelectorAll(".vfs-drop-target").forEach(r => r.classList.remove("vfs-drop-target"));
        tree.classList.toggle("vfs-drop-active", !!target);
        if (target?.row) target.row.classList.add("vfs-drop-target");
    }

    private vfsEndDrag() {
        const d = this.vfsDrag;
        this.vfsDrag = null;
        if (!d) return;
        d.ghost?.remove();
        try { document.getElementById("file-tree")?.releasePointerCapture(d.pointerId); } catch { /* not captured */ }
        this.vfsHighlightTarget(null);
    }

    /** Explorer drag hover: Tauri reports physical pixels, the DOM wants CSS pixels. */
    private vfsExternalHover(pos: { x: number; y: number } | null | undefined) {
        const listVisible = document.getElementById("list")?.classList.contains("active");
        if (!pos || !listVisible || !this.vfsCanEdit()) { this.vfsHighlightTarget(null); return; }
        const dpr = window.devicePixelRatio || 1;
        this.vfsHighlightTarget(this.vfsDropTargetAt(document.elementFromPoint(pos.x / dpr, pos.y / dpr)));
    }

    /** Explorer drop onto the tree: queue adds (and merges). Returns false when the
     *  drop is not for the List tab tree, so the caller opens the file as before. */
    private async vfsHandleExternalDrop(paths: string[], pos: { x: number; y: number } | undefined): Promise<boolean> {
        this.vfsHighlightTarget(null);
        if (!pos || !document.getElementById("list")?.classList.contains("active") || !this.vfsCanEdit()) return false;
        const dpr = window.devicePixelRatio || 1;
        const target = this.vfsDropTargetAt(document.elementFromPoint(pos.x / dpr, pos.y / dpr));
        if (!target) return false;
        const toAdd: string[] = [];
        for (const p of paths) {
            const lp = p.toLowerCase();
            if (lp.endsWith(".it") || lp.endsWith(".pack")) {
                const name = p.split(/[\\/]/).pop() || p;
                const merge = await ask(this.t("vfs_drop_archive_prompt", [name]), {
                    title: this.t("vfs_drop_archive_title"),
                    okLabel: this.t("vfs_drop_merge"),
                    cancelLabel: this.t("vfs_drop_add_file"),
                });
                if (merge) { await this.vfsQueueMerge(p); continue; }
            }
            toAdd.push(p);
        }
        if (toAdd.length === 0) return true;
        let items: Array<{ local: string; rel: string; size: number; mtime: number }>;
        try {
            items = await invoke("vfs_stat_paths", { paths: toAdd }) as typeof items;
        } catch (err) {
            this.log(this.t("msg_error_fmt", [String(err)]), "error");
            return true;
        }
        const cands = items.map(it => ({
            destPath: target.folder + it.rel, srcSize: it.size, srcMtime: it.mtime, srcLabel: it.local, localPath: it.local,
        }));
        const resolved = await this.resolveConflicts(cands);
        if (!resolved) { this.log(this.t("log_vfs_cancelled"), "info"); return true; }
        const ok = await this.vfsValidatePaths(resolved.map(r => r.destPath));
        let n = 0;
        resolved.forEach((r, i) => {
            if (!ok[i]) return;
            this.vfsPending.push({ op: "add", dest: r.destPath, local_src: r.localPath, size: r.srcSize, mtime: r.srcMtime });
            n++;
        });
        if (n > 0) this.renderVfsPending();
        this.log(this.t("log_vfs_queued_add", [String(n), target.folder || "/"]), "info");
        return true;
    }

    /** Validate destination entry paths with the core rules; logs and returns per-path ok. */
    private async vfsValidatePaths(paths: string[]): Promise<boolean[]> {
        if (paths.length === 0) return [];
        try {
            const errs = await invoke("vfs_validate_entry_paths", { paths }) as Array<string | null>;
            return errs.map((err) => {
                if (err) this.log(this.t("log_vfs_invalid_path", [err]), "error");
                return !err;
            });
        } catch (err) {
            this.log(this.t("msg_error_fmt", [String(err)]), "error");
            return paths.map(() => false);
        }
    }

    /** Queue a rename, folding it into an earlier pending rename of the same entry. */
    private vfsPushRename(from: string, to: string) {
        const k = this.vfsKey(from);
        const prev = this.vfsPending.find(ch => ch.op === "rename" && this.vfsKey(ch.from) === k);
        if (prev) prev.to = to;
        else this.vfsPending.push({ op: "rename", from, to });
    }

    /** Move the selected rows into `folder` ("" = root, else trailing `/`). */
    private async vfsMoveSelectionTo(folder: string) {
        if (!this.vfsCanEdit()) return;
        const items = this.vfsSelectionItems();
        const fk = folder.toLowerCase();
        for (const k of this.vfsSel) {
            if (k.startsWith("d:") && fk.startsWith(this.vfsKey(k.slice(2)) + "/")) {
                this.log(this.t("log_vfs_move_into_self"), "error");
                return;
            }
        }
        const archMtime = await this.vfsArchiveMtime();
        const cands = items
            .map(it => ({ destPath: folder + it.rel, srcSize: it.entry.original_size, srcMtime: archMtime, srcLabel: it.entry.name, from: it.entry.name }))
            .filter(c => this.vfsKey(c.destPath) !== this.vfsKey(c.from));
        if (cands.length === 0) return;
        const moving = new Set(cands.map(c => this.vfsKey(c.from)));
        const resolved = await this.resolveConflicts(cands, moving);
        if (!resolved) { this.log(this.t("log_vfs_cancelled"), "info"); return; }
        const ok = await this.vfsValidatePaths(resolved.map(r => r.destPath));
        let n = 0;
        resolved.forEach((r, i) => { if (ok[i]) { this.vfsPushRename(r.from, r.destPath); n++; } });
        if (n > 0) this.renderVfsPending();
        this.log(this.t("log_vfs_queued_move", [String(n), folder || "/"]), "info");
    }

    private vfsDeleteSelection() {
        if (!this.vfsCanEdit()) return;
        const items = this.vfsSelectionItems();
        for (const it of items) {
            const k = this.vfsKey(it.entry.name);
            this.vfsPending = this.vfsPending.filter(ch => !(ch.op === "rename" && this.vfsKey(ch.from) === k));
            if (!this.vfsPending.some(ch => ch.op === "delete" && this.vfsKey(ch.path) === k)) {
                this.vfsPending.push({ op: "delete", path: it.entry.name });
            }
        }
        if (items.length > 0) this.renderVfsPending();
        this.log(this.t("log_vfs_queued_delete", [String(items.length)]), "info");
    }

    /** F2 / context menu rename: a file gets a new full path, a folder a new folder path. */
    private async vfsRenameSelection() {
        if (!this.vfsCanEdit() || this.vfsSel.size !== 1) return;
        const key = Array.from(this.vfsSel)[0];
        const isFolder = key.startsWith("d:");
        const oldPath = this.vfsNorm(key.slice(2));
        const input = prompt(this.t(isFolder ? "prompt_rename_folder" : "prompt_rename_path"), oldPath);
        if (!input) return;
        const newPath = this.vfsNorm(input.trim()).replace(/\/+$/, "");
        if (!newPath || this.vfsKey(newPath) === this.vfsKey(oldPath)) return;
        const archMtime = await this.vfsArchiveMtime();
        let cands: Array<{ destPath: string; srcSize: number; srcMtime: number; srcLabel: string; from: string }>;
        if (isFolder) {
            const prefix = this.vfsKey(oldPath) + "/";
            if ((this.vfsKey(newPath) + "/").startsWith(prefix)) { this.log(this.t("log_vfs_move_into_self"), "error"); return; }
            cands = this.loadedEntries
                .filter(e => this.vfsKey(e.name).startsWith(prefix))
                .map(e => ({ destPath: newPath + "/" + this.vfsNorm(e.name).slice(prefix.length), srcSize: e.original_size, srcMtime: archMtime, srcLabel: e.name, from: e.name }));
        } else {
            const e = this.loadedEntries.find(en => en.name === key.slice(2));
            if (!e) return;
            cands = [{ destPath: newPath, srcSize: e.original_size, srcMtime: archMtime, srcLabel: e.name, from: e.name }];
        }
        const resolved = await this.resolveConflicts(cands, new Set(cands.map(c => this.vfsKey(c.from))));
        if (!resolved) { this.log(this.t("log_vfs_cancelled"), "info"); return; }
        const ok = await this.vfsValidatePaths(resolved.map(r => r.destPath));
        let n = 0;
        resolved.forEach((r, i) => { if (ok[i]) { this.vfsPushRename(r.from, r.destPath); n++; } });
        if (n > 0) this.renderVfsPending();
    }

    private vfsExtractRequest(items: Array<{ entry: AggregateEntry; rel: string }>) {
        return items.map(it => ({
            archive: it.entry.source_archive || this.currentArchive,
            entry: it.entry.name,
            rel: it.rel,
            key: this.vfsKeyOf(it.entry),
        }));
    }

    /** "Extract selected…": write the selection (folders keep their structure) into a chosen folder. */
    private async vfsExtractSelection() {
        const items = this.vfsSelectionItems();
        if (items.length === 0) return;
        const dest = await open({ directory: true });
        if (!dest || Array.isArray(dest)) return;
        try {
            const n = await invoke("vfs_extract_entries", { items: this.vfsExtractRequest(items), dest }) as number;
            this.log(this.t("log_vfs_extracted_sel", [String(n), dest]), "success");
        } catch (err) {
            this.log(this.t("msg_error_fmt", [String(err)]), "error");
        }
    }

    /** The row drag left the window: extract the selection to temp and start a native OS drag. */
    private vfsStartDragOut() {
        const d = this.vfsDrag;
        if (!d?.active) return;
        this.vfsEndDrag();
        const items = this.vfsSelectionItems();
        if (items.length === 0) return;
        this.log(this.t("log_vfs_drag_out", [String(items.length)]), "info");
        invoke("vfs_drag_out", { items: this.vfsExtractRequest(items) })
            .catch((err: unknown) => this.log(this.t("log_vfs_drag_out_failed", [String(err)]), "error"));
    }

    /** The open archive's modified time (ms). Archive entries carry no timestamps. */
    private async vfsArchiveMtime(path: string = this.currentArchive): Promise<number> {
        try {
            const st = await invoke("vfs_stat_paths", { paths: [path] }) as Array<{ mtime: number }>;
            return st[0]?.mtime ?? 0;
        } catch { return 0; }
    }

    /** Queue a merge of another archive, asking about each entry that already exists. */
    private async vfsQueueMerge(srcPath: string) {
        if (!this.vfsCanEdit()) return;
        let res: PackListResponse;
        try {
            res = await invoke("list_pack_contents", { input: srcPath, key: null }) as PackListResponse;
        } catch (err) {
            this.log(this.t("log_vfs_merge_error", [String(err)]), "error");
            return;
        }
        const srcMtime = await this.vfsArchiveMtime(srcPath);
        const cands = res.entries.map(e => ({
            destPath: this.vfsNorm(e.name), srcSize: e.original_size, srcMtime, srcLabel: e.name, srcName: e.name,
        }));
        const resolved = await this.resolveConflicts(cands);
        if (!resolved) { this.log(this.t("log_vfs_cancelled"), "info"); return; }
        const ok = await this.vfsValidatePaths(resolved.map(r => r.destPath));
        const kept = new Set<string>();
        const rename: Record<string, string> = {};
        resolved.forEach((r, i) => {
            if (!ok[i]) return;
            kept.add(r.srcName);
            if (this.vfsKey(r.destPath) !== this.vfsKey(r.srcName)) rename[this.vfsNorm(r.srcName)] = r.destPath;
        });
        const skip = cands.filter(c => !kept.has(c.srcName)).map(c => this.vfsNorm(c.srcName));
        this.vfsPending.push({ op: "merge", src_archive: srcPath, skip, rename });
        this.renderVfsPending();
        this.log(this.t("log_vfs_queued_merge", [srcPath, this.currentArchive]), "info");
        if (skip.length > 0 || Object.keys(rename).length > 0) {
            this.log(this.t("log_vfs_merge_decisions", [String(skip.length), String(Object.keys(rename).length)]), "info");
        }
    }

    // ── VFS Conflict Resolution ──────────────────────────────────────────────────

    /** Entries as they will be after the pending changes (key → path/size/mtime). */
    private vfsVirtualEntries(archMtime: number): Map<string, { path: string; size: number; mtime: number }> {
        const m = new Map<string, { path: string; size: number; mtime: number }>();
        for (const e of this.loadedEntries) m.set(this.vfsKey(e.name), { path: this.vfsNorm(e.name), size: e.original_size, mtime: archMtime });
        for (const ch of this.vfsPending) {
            if (ch.op === "delete") m.delete(this.vfsKey(ch.path));
            else if (ch.op === "rename") {
                const v = m.get(this.vfsKey(ch.from));
                m.delete(this.vfsKey(ch.from));
                m.set(this.vfsKey(ch.to), { path: this.vfsNorm(ch.to), size: v?.size ?? 0, mtime: v?.mtime ?? archMtime });
            } else if (ch.op === "add") {
                m.set(this.vfsKey(ch.dest), { path: this.vfsNorm(ch.dest), size: Number(ch.size ?? 0), mtime: Number(ch.mtime ?? 0) });
            }
        }
        return m;
    }

    /** "name (1).ext" not yet taken in the destination folder. */
    private vfsSuggestName(destPath: string, taken: (k: string) => boolean): string {
        const folder = this.vfsParent(destPath);
        const base = this.vfsBase(destPath);
        const dot = base.indexOf(".", 1);
        const stem = dot > 0 ? base.slice(0, dot) : base;
        const ext = dot > 0 ? base.slice(dot) : "";
        for (let i = 1; ; i++) {
            const name = `${stem} (${i})${ext}`;
            if (!taken(this.vfsKey(folder + name))) return name;
        }
    }

    /** FileZilla-style "Target file already exists" handling. Candidates whose
     *  destination is free pass through; for collisions the user picks overwrite /
     *  overwrite if newer / overwrite if size differs / rename / skip, optionally for
     *  the rest of the queue. Returns the candidates to apply (renamed ones carry the
     *  new destPath), or null when the user cancels the whole operation.
     *  `leaving` are entries that move away in this same operation. */
    private async resolveConflicts<T extends { destPath: string; srcSize?: number; srcMtime?: number; srcLabel?: string }>(
        candidates: T[], leaving: Set<string> = new Set()
    ): Promise<T[] | null> {
        const archMtime = await this.vfsArchiveMtime();
        const virt = this.vfsVirtualEntries(archMtime);
        leaving.forEach(k => virt.delete(k));
        const batch = new Map<string, { path: string; size: number; mtime: number }>();
        const existing = (k: string) => batch.get(k) ?? virt.get(k);
        const taken = (k: string) => !!existing(k);
        const total = candidates.filter(c => taken(this.vfsKey(c.destPath))).length;
        let seen = 0;
        let always: VfsConflictAction | null = null;
        const result: T[] = [];

        for (const c of candidates) {
            let cur: T = c;
            for (;;) {
                const k = this.vfsKey(cur.destPath);
                const tgt = existing(k);
                const claim = () => { batch.set(this.vfsKey(cur.destPath), { path: cur.destPath, size: cur.srcSize ?? 0, mtime: cur.srcMtime ?? 0 }); result.push(cur); };
                if (!tgt) { claim(); break; }
                if (cur === c) seen++;
                let action: VfsConflictAction | null = always;
                let newName: string | undefined;
                if (!action) {
                    const choice = await this.showConflictDialog({
                        destPath: cur.destPath,
                        srcLabel: cur.srcLabel ?? cur.destPath,
                        srcSize: cur.srcSize, srcMtime: cur.srcMtime,
                        tgtSize: tgt.size, tgtMtime: tgt.mtime,
                        suggested: this.vfsSuggestName(cur.destPath, taken),
                        hasMore: total - seen > 0,
                    });
                    if (choice.action === "cancel") return null;
                    action = choice.action;
                    newName = choice.newName;
                    if (choice.applyAll) always = action;
                }
                if (action === "overwrite") { claim(); break; }
                if (action === "newer") { if ((cur.srcMtime ?? 0) > tgt.mtime) claim(); break; }
                if (action === "size") { if ((cur.srcSize ?? -1) !== tgt.size) claim(); break; }
                if (action === "rename") {
                    const name = (newName && newName.trim()) || this.vfsSuggestName(cur.destPath, taken);
                    cur = { ...cur, destPath: this.vfsParent(cur.destPath) + this.vfsNorm(name) };
                    continue; // re-check: a typed name may collide too
                }
                break; // skip
            }
        }
        return result;
    }

    /** Show the conflict dialog for one file and wait for the user's choice. */
    private showConflictDialog(info: {
        destPath: string; srcLabel: string; srcSize?: number; srcMtime?: number;
        tgtSize: number; tgtMtime: number; suggested: string; hasMore: boolean;
    }): Promise<{ action: VfsConflictAction | "cancel"; newName?: string; applyAll: boolean }> {
        return new Promise((resolve) => {
            const ctrl = new AbortController();
            const { signal } = ctrl;

            const overlay     = document.getElementById("conflict-dialog")!;
            const applyAllRow = document.getElementById("conflict-apply-all-row") as HTMLElement;
            const applyAllCb  = document.getElementById("conflict-apply-all") as HTMLInputElement;
            const renameInput = document.getElementById("conflict-rename-input") as HTMLInputElement;
            const btnOk       = document.getElementById("conflict-btn-ok")!;
            const btnCancel   = document.getElementById("conflict-btn-cancel")!;
            const radios      = Array.from(overlay.querySelectorAll<HTMLInputElement>('input[name="conflict-action"]'));

            const fmtDate = (ms?: number) => ms ? new Date(ms).toLocaleString() : this.t("conflict_unknown");
            const fmtSize = (n?: number) => n === undefined ? this.t("conflict_unknown") : `${this.formatBytes(n)} (${n.toLocaleString()})`;
            document.getElementById("conflict-filename")!.textContent = info.destPath;
            document.getElementById("conflict-src-name")!.textContent = info.srcLabel;
            document.getElementById("conflict-src-info")!.textContent = `${fmtSize(info.srcSize)} · ${fmtDate(info.srcMtime)}`;
            document.getElementById("conflict-tgt-name")!.textContent = info.destPath;
            document.getElementById("conflict-tgt-info")!.textContent = `${fmtSize(info.tgtSize)} · ${fmtDate(info.tgtMtime)}`;

            renameInput.value = info.suggested;
            // Keep the previously chosen action selected, like FileZilla
            if (!radios.some(r => r.checked)) radios[0].checked = true;
            const syncRename = () => {
                renameInput.classList.toggle("conflict-dim", !radios.some(r => r.checked && r.value === "rename"));
            };
            syncRename();
            applyAllRow.classList.toggle("hidden", !info.hasMore);
            applyAllCb.checked = false;

            overlay.classList.remove("hidden");
            btnOk.focus();

            const finish = (action: VfsConflictAction | "cancel") => {
                ctrl.abort();
                overlay.classList.add("hidden");
                const newName = action === "rename" ? (renameInput.value.trim() || info.suggested) : undefined;
                // "Always rename" auto-numbers the rest, so a typed name only applies once
                resolve({ action, newName, applyAll: action !== "cancel" && applyAllCb.checked });
            };
            const selected = (): VfsConflictAction => (radios.find(r => r.checked)?.value as VfsConflictAction) ?? "overwrite";

            radios.forEach(r => r.addEventListener("change", syncRename, { signal }));
            renameInput.addEventListener("focus", () => {
                const r = radios.find(x => x.value === "rename");
                if (r) { r.checked = true; syncRename(); }
            }, { signal });
            btnOk.addEventListener("click", () => finish(selected()), { signal });
            btnCancel.addEventListener("click", () => finish("cancel"), { signal });
            overlay.addEventListener("keydown", (e: KeyboardEvent) => {
                if (e.key === "Enter") { e.preventDefault(); finish(selected()); }
                else if (e.key === "Escape") { e.preventDefault(); finish("cancel"); }
            }, { signal });
        });
    }

    private async listArchive(archivePath: string) {
        // Helper: re-run the list command for the given archive and rebuild tree
        const listInput = document.getElementById("list-input") as HTMLInputElement | null;
        if (listInput) listInput.value = archivePath;
        // Simulate clicking list (trigger the existing list flow)
        document.getElementById("tab-list")?.click();
        // Trigger the existing load flow by dispatching a fake event on the list input
        listInput?.dispatchEvent(new Event("list-reload", { bubbles: true }));
    }

    // ── Job queue tab ────────────────────────────────────────────────────────────

    private jobs: JobEntry[] = [];
    private jobsRunning = false;

    private setupJobQueue() {
        document.getElementById("btn-jobs-add")?.addEventListener("click", () => this.jobsAdd());
        document.getElementById("btn-jobs-run-all")?.addEventListener("click", () => this.jobsRunAll());
        document.getElementById("btn-jobs-clear-done")?.addEventListener("click", () => this.jobsClearDone());

        const updateJobHints = (type: string) => {
            const inp = document.getElementById("jobs-input") as HTMLInputElement;
            const out = document.getElementById("jobs-output") as HTMLInputElement;
            const hints: Record<string, [string, string]> = {
                "extract":   ["features_archive_label",  "jobs_hint_output_folder"],
                "pack":      ["jobs_hint_source_folder", "jobs_hint_output_archive"],
                "differ":    ["jobs_hint_base_archive",  "jobs_hint_modified_archive"],
                "merge":     ["jobs_hint_source_folder", "jobs_hint_output_archive"],
                "apply-mod": ["jobs_hint_mod_file",      "jobs_hint_target_archive"],
            };
            const [h1, h2] = hints[type] ?? ["jobs_input_placeholder", "jobs_output_placeholder"];
            if (inp) { inp.placeholder = this.t(h1); inp.dataset.i18nPlaceholder = h1; }
            if (out) { out.placeholder = this.t(h2); out.dataset.i18nPlaceholder = h2; }
        };
        const typeSelect = document.getElementById("jobs-type-select") as HTMLSelectElement;
        typeSelect?.addEventListener("change", () => updateJobHints(typeSelect.value));
        updateJobHints(typeSelect?.value ?? "extract");

        document.getElementById("btn-jobs-browse-input")?.addEventListener("click", async () => {
            const { open } = await import("./platform/dialog");
            const type = (document.getElementById("jobs-type-select") as HTMLSelectElement).value;
            const archiveFilter = { name: this.t("dlg_filter_archives"), extensions: ["it", "pack"] };
            const modFilter = { name: this.t("dlg_filter_mod_files"), extensions: ["mod"] };
            let selected: string | string[] | null = null;
            if (type === "extract" || type === "differ") {
                selected = await open({ filters: [archiveFilter] });
            } else if (type === "apply-mod") {
                selected = await open({ filters: [modFilter] });
            } else {
                selected = await open({ directory: true });
            }
            if (selected && !Array.isArray(selected)) {
                (document.getElementById("jobs-input") as HTMLInputElement).value = selected as string;
            }
        });

        document.getElementById("btn-jobs-browse-output")?.addEventListener("click", async () => {
            const { open, save } = await import("./platform/dialog");
            const type = (document.getElementById("jobs-type-select") as HTMLSelectElement).value;
            let path: string | null = null;
            if (type === "pack" || type === "merge") {
                path = await save({ filters: [{ name: this.t("dlg_filter_archives"), extensions: ["it"] }] });
            } else if (type === "differ") {
                path = await save({ filters: [{ name: this.t("dlg_filter_patch"), extensions: ["patch"] }] });
            } else {
                const sel = await open({ directory: true });
                path = (sel && !Array.isArray(sel)) ? sel as string : null;
            }
            if (path) (document.getElementById("jobs-output") as HTMLInputElement).value = path;
        });
    }

    private jobsAdd() {
        const type = (document.getElementById("jobs-type-select") as HTMLSelectElement).value as JobEntry["type"];
        const input = (document.getElementById("jobs-input") as HTMLInputElement).value.trim();
        const output = (document.getElementById("jobs-output") as HTMLInputElement).value.trim();
        const key = (document.getElementById("jobs-key") as HTMLInputElement).value.trim() || undefined;

        if (!input || !output) return;

        this.log(this.t("log_jobs_added", [this.t(`job_type_${type.replace("-","_")}`), input, output]), "info");
        const job: JobEntry = {
            id: Date.now() + Math.random(),
            type,
            input,
            output,
            key,
            status: "pending",
            progress: 0,
            log: "",
        };
        this.jobs.push(job);
        this.renderJob(job);
        document.getElementById("jobs-empty-msg")?.classList.add("hidden");
        const badge = document.getElementById("jobs-count-badge")!;
        badge.textContent = `(${this.jobs.length})`;

        // Clear inputs
        (document.getElementById("jobs-input") as HTMLInputElement).value = "";
        (document.getElementById("jobs-output") as HTMLInputElement).value = "";
    }

    private renderJob(job: JobEntry) {
        const list = document.getElementById("jobs-list")!;
        const row = document.createElement("div");
        row.className = "job-row";
        row.id = `job-${job.id}`;
        const typeLabel = this.t(`job_type_${job.type.replace("-","_")}`) || job.type;
        const fname = job.input.split(/[\\/]/).pop() ?? job.input;
        row.innerHTML = `
            <div class="job-header">
                <span class="job-type-badge ${job.type}">${typeLabel}</span>
                <span class="job-path" title="${job.input}">${fname}</span>
                <span class="job-status" id="job-status-${job.id}">${this.t("status_pending") || "pending"}</span>
                <div class="job-actions">
                    <button class="tab-btn" data-job-run="${job.id}">${this.t("btn_run") || "Run"}</button>
                    <button class="tab-btn" data-job-remove="${job.id}">✕</button>
                </div>
            </div>
            <div class="job-progress-bar"><div class="job-progress-fill" id="job-prog-${job.id}" style="width:0%"></div></div>
            <div class="job-log" id="job-log-${job.id}"></div>`;

        row.querySelector(`[data-job-run="${job.id}"]`)?.addEventListener("click", () => this.runJob(job));
        row.querySelector(`[data-job-remove="${job.id}"]`)?.addEventListener("click", () => {
            this.jobs = this.jobs.filter(j => j.id !== job.id);
            row.remove();
            const badge = document.getElementById("jobs-count-badge")!;
            badge.textContent = `(${this.jobs.length})`;
            if (this.jobs.length === 0) document.getElementById("jobs-empty-msg")?.classList.remove("hidden");
        });

        list.appendChild(row);
    }

    private async runJob(job: JobEntry) {
        if (job.status === "running") return;
        job.status = "running";
        this.updateJobUI(job, "running", 0, this.t("patcher_starting"));

        const row = document.getElementById(`job-${job.id}`)!;
        row.className = "job-row running";

        // Listen for progress events from this operation
        const progressHandler = (payload: any) => {
            if (payload?.total > 0) {
                const pct = Math.round((payload.current / payload.total) * 100);
                this.updateJobUI(job, "running", pct, payload.msg || "");
            }
        };

        try {
            const { listen } = await import("./platform/event");
            const unlisten = await listen("progress", (e) => progressHandler(e.payload));

            if (job.type === "extract") {
                await invoke("extract_pack_to", {
                    input: job.input, output: job.output,
                    key: job.key || null, filters: [] as string[],
                });
            } else if (job.type === "pack" || job.type === "merge") {
                await invoke("create_archive", {
                    input: job.input, output: job.output,
                    key: job.key || "", wrapData: false,
                });
            } else if (job.type === "differ") {
                // input = base archive, output = modified archive, patch = base + ".patch"
                const patchOut = job.input.replace(/\.(it|pack)$/i, ".patch");
                await invoke("create_patch", {
                    base: job.input, modified: job.output,
                    output: patchOut, key: job.key || "",
                });
            } else if (job.type === "apply-mod") {
                // job.input is a path to a .mod file; apply_mod needs its raw
                // TOML text (mod_toml), not a path — load it first.
                const modToml = await invoke("load_mod_file", { path: job.input }) as string;
                await invoke("apply_mod", {
                    modToml, archive: job.output,
                    key: job.key || null,
                });
            }

            unlisten();
            job.status = "done";
            this.updateJobUI(job, "done", 100, this.t("jobs_completed"));
            row.className = "job-row done";
            this.log(this.t("log_jobs_completed", [this.t(`job_type_${job.type.replace("-","_")}`), job.input]), "info");
        } catch (e: any) {
            job.status = "error";
            this.updateJobUI(job, "error", 0, this.t("msg_error_fmt", [String(e)]));
            row.className = "job-row error";
            this.log(this.t("log_jobs_failed", [this.t(`job_type_${job.type.replace("-","_")}`), String(e)]), "error");
        }
    }

    private updateJobUI(job: JobEntry, status: string, pct: number, log: string) {
        const statusEl = document.getElementById(`job-status-${job.id}`);
        const progEl = document.getElementById(`job-prog-${job.id}`);
        const logEl = document.getElementById(`job-log-${job.id}`);
        if (statusEl) statusEl.textContent = this.t(`status_${status}`);
        if (progEl) {
            progEl.style.width = `${pct}%`;
            progEl.className = `job-progress-fill ${status === "done" ? "done" : status === "error" ? "error" : ""}`;
        }
        if (logEl) logEl.textContent = log;
    }

    private async jobsRunAll() {
        if (this.jobsRunning) return;
        this.jobsRunning = true;
        const pending = this.jobs.filter(j => j.status === "pending");
        this.log(this.t("log_jobs_run_all", [String(pending.length)]), "info");
        const LIMIT = 4;
        let running = 0, idx = 0;
        await new Promise<void>(resolve => {
            const next = () => {
                while (running < LIMIT && idx < pending.length) {
                    running++;
                    this.runJob(pending[idx++]).finally(() => {
                        running--;
                        if (idx < pending.length) next();
                        else if (running === 0) resolve();
                    });
                }
                if (idx >= pending.length && running === 0) resolve();
            };
            next();
        });
        this.jobsRunning = false;
    }

    private jobsClearDone() {
        const done = this.jobs.filter(j => j.status === "done" || j.status === "error");
        for (const job of done) {
            document.getElementById(`job-${job.id}`)?.remove();
        }
        this.jobs = this.jobs.filter(j => j.status !== "done" && j.status !== "error");
        const badge = document.getElementById("jobs-count-badge")!;
        badge.textContent = `(${this.jobs.length})`;
        if (this.jobs.length === 0) document.getElementById("jobs-empty-msg")?.classList.remove("hidden");
    }

    // ── Features editor tab ─────────────────────────────────────────────────────

    private featuresData: any | null = null;
    private featuresModified = false;

    private setupFeaturesEditor() {
        document.getElementById("btn-features-browse")?.addEventListener("click", async () => {
            const { open } = await import("./platform/dialog");
            const file = await open({ filters: [{ name: this.t("dlg_filter_archives"), extensions: ["it", "pack"] }] });
            if (file && !Array.isArray(file)) {
                (document.getElementById("features-archive") as HTMLInputElement).value = file as string;
            }
        });

        document.getElementById("btn-features-load")?.addEventListener("click", () => this.loadFeatures());
        document.getElementById("btn-features-save")?.addEventListener("click", () => this.saveFeatures());

        document.getElementById("features-search")?.addEventListener("input", (e) => {
            this.filterFeaturesList((e.target as HTMLInputElement).value.trim().toLowerCase());
        });
    }

    private async loadFeatures() {
        const archive = (document.getElementById("features-archive") as HTMLInputElement).value.trim();
        const keyEl = (document.getElementById("features-key") as HTMLInputElement).value.trim();
        const key = keyEl || null;
        if (!archive) { this.setFeaturesStatus(this.t("features_select_archive"), "error"); return; }

        this.setFeaturesStatus(this.t("preview_loading"), "busy");
        const btn = document.getElementById("btn-features-load") as HTMLButtonElement;
        btn.disabled = true;

        this.log(this.t("log_features_loading", [archive]), "info");
        try {
            const data = await invoke("get_features_from_archive", { archive, key }) as any;
            this.featuresData = data;
            this.featuresModified = false;
            this.renderFeatures();
            const loadedMsg = this.t("features_loaded", [String(data.features.length), String(data.servers.length)]);
            this.setFeaturesStatus(loadedMsg, "ok");
            this.log(`${this.t("log_tag_features")} ${loadedMsg}`, "info");
            document.getElementById("btn-features-save")?.classList.remove("hidden");
        } catch (e: any) {
            this.setFeaturesStatus(this.t("features_load_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_features")} ${this.t("features_load_failed", [String(e)])}`, "error");
        } finally {
            btn.disabled = false;
        }
    }

    private async saveFeatures() {
        if (!this.featuresData) return;
        if (this.featuresModified) {
            document.getElementById("btn-features-save")?.classList.remove("unsaved");
        }
        const archive = (document.getElementById("features-archive") as HTMLInputElement).value.trim();
        const keyEl = (document.getElementById("features-key") as HTMLInputElement).value.trim();
        const key = keyEl || null;

        this.log(this.t("log_features_saving", [archive]), "info");
        this.setFeaturesStatus(this.t("features_saving"), "busy");
        const btn = document.getElementById("btn-features-save") as HTMLButtonElement;
        btn.disabled = true;

        try {
            const result = await invoke("save_features_to_archive", {
                archive,
                key,
                featuresJson: JSON.stringify(this.featuresData),
            }) as any;
            this.featuresModified = false;
            const savedMsg = this.t("features_saved", [String(result.features), String(result.bytes)]);
            this.setFeaturesStatus(savedMsg, "ok");
            this.log(`${this.t("log_tag_features")} ${savedMsg}`, "info");
        } catch (e: any) {
            this.setFeaturesStatus(this.t("features_save_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_features")} ${this.t("features_save_failed", [String(e)])}`, "error");
        } finally {
            btn.disabled = false;
        }
    }

    private renderFeatures() {
        if (!this.featuresData) return;

        // Servers
        const serversCard = document.getElementById("features-servers-card")!;
        const serversList = document.getElementById("features-servers-list")!;
        serversCard.classList.remove("hidden");
        serversList.innerHTML = "";
        for (const s of this.featuresData.servers) {
            const row = document.createElement("div");
            row.className = "features-server-row";
            row.innerHTML = `<span>ID ${s.server_id}</span><b>${s.name}</b><span>${s.region}</span><span>${this.t("features_channel_short", [String(s.channel)])}</span>`;
            serversList.appendChild(row);
        }

        // Features
        const listCard = document.getElementById("features-list-card")!;
        listCard.classList.remove("hidden");
        const badge = document.getElementById("features-count-badge")!;
        badge.textContent = `(${this.featuresData.features.length})`;
        this.renderFeatureRows(this.featuresData.features);
    }

    private renderFeatureRows(features: any[]) {
        const list = document.getElementById("features-list")!;
        list.innerHTML = "";
        for (let fi = 0; fi < features.length; fi++) {
            const f = features[fi];
            const row = document.createElement("div");
            row.className = "feature-row";
            row.dataset.featureIdx = String(fi);

            const hashSpan = document.createElement("span");
            hashSpan.className = "feature-hash";
            hashSpan.textContent = f.hash_hex;
            row.appendChild(hashSpan);

            // Readable name from the embedded feature-name list, when the hash is known.
            const nameSpan = document.createElement("span");
            nameSpan.className = "feature-name";
            nameSpan.textContent = f.name ?? "";
            if (f.name) nameSpan.title = f.name;
            row.appendChild(nameSpan);

            const condsDiv = document.createElement("div");
            condsDiv.className = "feature-conds";

            if (f.conditions.length === 0) {
                const empty = document.createElement("span");
                empty.style.cssText = "opacity:.3;font-size:11px;";
                empty.textContent = this.t("features_no_conditions");
                condsDiv.appendChild(empty);
            } else {
                for (let ci = 0; ci < f.conditions.length; ci++) {
                    const cond = f.conditions[ci];
                    if (!cond) continue;
                    const tag = document.createElement("span");
                    tag.className = "feature-cond-tag";
                    tag.textContent = cond;
                    tag.title = this.t("features_toggle_cond", [String(ci)]);
                    tag.dataset.featureIdx = String(fi);
                    tag.dataset.condIdx = String(ci);
                    tag.addEventListener("click", () => this.toggleFeatureCondition(fi, ci, tag));
                    condsDiv.appendChild(tag);
                }
            }
            row.appendChild(condsDiv);
            list.appendChild(row);
        }
    }

    private toggleFeatureCondition(featureIdx: number, condIdx: number, tag: HTMLElement) {
        if (!this.featuresData) return;
        const feature = this.featuresData.features[featureIdx];
        const cond = feature.conditions[condIdx];
        if (tag.classList.contains("removed")) {
            // Restore: cond was cleared, restore original
            const original = tag.dataset.original || cond;
            feature.conditions[condIdx] = original;
            tag.textContent = original;
            tag.classList.remove("removed");
        } else {
            // Remove: clear the condition string
            tag.dataset.original = cond;
            feature.conditions[condIdx] = "";
            tag.classList.add("removed");
        }
        this.featuresModified = true;
        // Update save button to indicate unsaved changes
        const saveBtn = document.getElementById("btn-features-save");
        if (saveBtn) saveBtn.classList.add("unsaved");
    }

    private filterFeaturesList(query: string) {
        if (!this.featuresData) return;
        if (!query) {
            this.renderFeatureRows(this.featuresData.features);
            return;
        }
        const filtered = this.featuresData.features.filter((f: any) =>
            f.hash_hex.includes(query) ||
            (f.name ?? "").toLowerCase().includes(query) ||
            f.conditions.some((c: string) => c.toLowerCase().includes(query))
        );
        this.renderFeatureRows(filtered);
        const badge = document.getElementById("features-count-badge")!;
        badge.textContent = `(${filtered.length} / ${this.featuresData.features.length})`;
    }

    private setFeaturesStatus(msg: string, type: "ok" | "error" | "busy" | "idle") {
        const el = document.getElementById("features-status")!;
        el.textContent = msg;
        el.classList.remove("hidden");
        const colours: Record<string, string> = { ok: "#4ade80", error: "#f87171", busy: "#facc15", idle: "#9ca3af" };
        el.style.color = colours[type] ?? colours.idle;
    }

    // ── Launcher tab ────────────────────────────────────────────────────────────

    private launcherSession: { access_token: string; g_access_token: string; session_token: string; hashed_user_id: string; tpa?: boolean; [k: string]: any } | null = null;
    /** Pending MFA challenge from an email/password login (submit the code with launcher_login_otp). */
    private pendingMfaKey: string | null = null;
    /** Legacy localStorage key of the full session (secrets): only read once to migrate
     *  it into the profile store, then removed. The session now lives in memory. */
    private readonly LAUNCHER_SESSION_KEY = "nexon_session";

    /** Keep a session the backend refreshed in place (401 → autologin), if it returned one.
     *  A refresh also renews the NxLSession: store it on the active profile with its new expiry. */
    private keepRefreshedSession(session: any): void {
        if (!session || !this.launcherSession) return;
        const expiresIn = session.refreshed_expires_in;
        if (expiresIn) {
            // Persist once; don't send the marker back on later calls.
            delete session.refreshed_expires_in;
            if (this.activeProfileId && session.session_token) {
                invoke("launcher_update_profile_session", {
                    id: this.activeProfileId,
                    sessionToken: session.session_token,
                    expiresIn,
                }).catch(() => {});
                this.noteProfileExpiry(this.activeProfileId, expiresIn);
            }
        }
        this.launcherSession = session;
    }
    private launcherProfiles: any[] = [];
    private activeProfileId: string | null = null;
    private activeProfileLoginIp: string = "";
    private activeProfileLoginPort: number = 0;
    private activeProfileIsOfficial: boolean = true;
    private profileEditorMode: "new" | "edit" | null = null;
    private workerBars: Map<number, HTMLElement> = new Map();

    private setupLauncher() {
        // Move a session older versions kept in localStorage into the profile store,
        // then load profiles from the backend.
        this.migrateLegacySession().finally(() => this.loadProfiles());

        // Login / logout / launch
        document.getElementById("btn-launcher-login")?.addEventListener("click", () => this.launcherDoLogin());
        document.getElementById("btn-launcher-logout")?.addEventListener("click", () => this.launcherDoLogout());
        document.getElementById("btn-launcher-launch")?.addEventListener("click", () => this.launcherDoLaunch());
        document.getElementById("btn-launcher-import-session")?.addEventListener("click", () => this.launcherImportSession());
        document.getElementById("btn-launcher-import-browser")?.addEventListener("click", () => this.launcherImportBrowser());
        document.getElementById("btn-launcher-import-kanan")?.addEventListener("click", () => this.launcherImportKanan());
        document.getElementById("btn-launcher-import-hyddwn")?.addEventListener("click", () => this.launcherImportHyddwn());
        document.getElementById("btn-launcher-installs")?.addEventListener("click", () => this.checkAllInstalls("launcher-installs-panel"));

        document.getElementById("btn-launcher-check-update")?.addEventListener("click", async () => {
            const statusEl = document.getElementById("launcher-update-status")!;
            statusEl.textContent = this.t("patcher_checking");
            statusEl.className = "launcher-update-status";
            statusEl.classList.remove("hidden");
            try {
                const info = await invoke("get_mabi_version_from_launcher_cache") as {
                    cached_version: number | null;
                    cached_manifest_url: string | null;
                    local_manifest_hash: string | null;
                    cdn_manifest_hash: string | null;
                    update_available: boolean | null;
                };
                if (info.cached_version) {
                    if (info.update_available === true) {
                        statusEl.textContent = this.t("launcher_ver_update_available", [String(info.cached_version)]);
                        statusEl.className = "launcher-update-status error";
                        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_vercheck_update", [String(info.cached_version)])}`, "warn");
                    } else if (info.update_available === false) {
                        statusEl.textContent = this.t("launcher_ver_up_to_date", [String(info.cached_version)]);
                        statusEl.className = "launcher-update-status up-to-date";
                        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_vercheck_uptodate", [String(info.cached_version)])}`, "info");
                    } else {
                        statusEl.textContent = this.t("launcher_ver_cached", [String(info.cached_version)]);
                        statusEl.className = "launcher-update-status up-to-date";
                        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_vercheck_cached", [String(info.cached_version)])}`, "info");
                    }
                } else {
                    statusEl.textContent = this.t("launcher_ver_not_found");
                    statusEl.className = "launcher-update-status error";
                    this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_vercheck_none")}`, "warn");
                }
            } catch (e) {
                statusEl.textContent = this.t("patcher_check_failed", [String(e)]);
                statusEl.className = "launcher-update-status error";
                this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_vercheck_failed", [String(e)])}`, "error");
            }
        });

        // Profile selector change (Settings > Launcher sub-tab)
        document.getElementById("launcher-profile-select")?.addEventListener("change", (e) => {
            const id = (e.target as HTMLSelectElement).value;
            this.selectProfile(id);
        });

        // Profile quick-select on main Launcher page
        document.getElementById("launcher-page-profile-select")?.addEventListener("change", (e) => {
            const sel = e.target as HTMLSelectElement;
            const id = sel.value;
            if (id === App.NEW_PROFILE_OPTION) {
                sel.value = this.activeProfileId || "";
                this.openProfileManager(true);
                return;
            }
            this.selectProfile(id);
            // Mirror selection to settings dropdown
            const settingsSel = document.getElementById("launcher-profile-select") as HTMLSelectElement;
            if (settingsSel) settingsSel.value = id;
        });
        document.getElementById("btn-launcher-manage-profiles")?.addEventListener("click", () => this.openProfileManager(false));

        // Profile buttons
        document.getElementById("btn-profile-detect")?.addEventListener("click", () => this.detectLauncherProfiles());
        document.getElementById("btn-profile-new")?.addEventListener("click", () => this.openProfileEditor("new"));
        document.getElementById("btn-profile-delete")?.addEventListener("click", () => this.deleteActiveProfile());
        document.getElementById("btn-profile-save")?.addEventListener("click", () => this.saveProfileEditor());
        document.getElementById("btn-profile-cancel")?.addEventListener("click", () => this.closeProfileEditor());
        document.getElementById("btn-profile-save-after-launch")?.addEventListener("click", () => this.saveCurrentSettingsToProfile());

        // Custom server toggle in profile editor
        document.getElementById("launcher-profile-custom-server")?.addEventListener("change", (e) => {
            const checked = (e.target as HTMLInputElement).checked;
            const serverFields = document.getElementById("launcher-profile-server-fields");
            if (serverFields) serverFields.style.display = checked ? "block" : "none";
        });

        // Browse buttons
        document.getElementById("btn-launcher-browse")?.addEventListener("click", async () => {
            const { open } = await import("./platform/dialog");
            const dir = await open({ directory: true });
            if (dir && !Array.isArray(dir)) {
                (document.getElementById("launcher-client-dir") as HTMLInputElement).value = dir as string;
            }
        });
        document.getElementById("btn-profile-browse")?.addEventListener("click", async () => {
            const { open } = await import("./platform/dialog");
            const dir = await open({ directory: true });
            if (dir && !Array.isArray(dir)) {
                (document.getElementById("launcher-profile-client-dir") as HTMLInputElement).value = dir as string;
            }
        });
    }

    /** One-time migration: a full session in localStorage (older versions) is used for
     *  this run, saved to the selected profile (if that has none stored), and removed
     *  from localStorage once a profile holds it. */
    private async migrateLegacySession(): Promise<void> {
        let saved: string | null = null;
        try { saved = localStorage.getItem(this.LAUNCHER_SESSION_KEY); } catch { return; }
        if (!saved) return;
        const drop = () => { try { localStorage.removeItem(this.LAUNCHER_SESSION_KEY); } catch {} };
        let session: any;
        try { session = JSON.parse(saved); } catch { drop(); return; }
        if (!session?.session_token) { drop(); return; }
        if (!this.launcherSession) {
            this.launcherSession = session;
            this.updateLauncherUI(true);
            this.fetchLauncherVersion();
        }
        try {
            const result = await invoke("launcher_list_profiles") as { profiles: any[], active_id: string } | any[];
            const profiles: any[] = Array.isArray(result) ? result : (result.profiles || []);
            const activeId = (Array.isArray(result) ? "" : result.active_id) || profiles[0]?.id || "";
            const profile = profiles.find(p => p.id === activeId);
            if (!profile) return; // no profile yet: migrate on a later start
            // A profile that already stores a session keeps it (it may be newer).
            if (!profile.has_session) {
                await invoke("launcher_save_profile_session", { id: profile.id, session, expiresIn: 0 });
            }
            drop();
        } catch (e) {
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_save_to_profile_failed", [String(e)])}`, "warn");
        }
    }

    private async loadProfiles() {
        try {
            const result = await invoke("launcher_list_profiles") as { profiles: any[], active_id: string } | any[];
            let profiles: any[];
            let storedActiveId = "";
            if (Array.isArray(result)) {
                profiles = result;
            } else {
                profiles = result.profiles || [];
                storedActiveId = result.active_id || "";
            }
            this.launcherProfiles = profiles;

            // Prefer stored active_id, fall back to previously selected, then first profile
            const activeId = storedActiveId || this.activeProfileId || this.launcherProfiles[0]?.id || "";
            const active = this.launcherProfiles.find(p => p.id === activeId) || this.launcherProfiles[0];
            if (active) this.activeProfileId = active.id;

            this.renderProfileSelect();
            this.promptIfNoUsableProfile();

            if (active) {
                this.applyProfileToUI(active);
                if (await this.handleExpiredAutologin(active)) {
                    // expired: re-login prompt shown instead of a doomed autologin
                } else if (active.auto_login && active.session_valid) {
                    await this.autologinProfile(active.id);
                }
            } else {
                // No profiles — try to auto-fill client dir from registry
                try {
                    const info = await invoke("get_mabi_version_local") as { client_dir?: string } | null;
                    if (info?.client_dir) {
                        const el = document.getElementById("launcher-client-dir") as HTMLInputElement;
                        if (el && !el.value) el.value = info.client_dir;
                    }
                } catch (_) {}
            }
        } catch {
            // No profiles yet or backend not available — silent
        }
    }

    private renderProfileSelect() {
        const selIds = ["launcher-profile-select", "launcher-page-profile-select"];
        for (const selId of selIds) {
            const sel = document.getElementById(selId) as HTMLSelectElement;
            if (!sel) continue;
            sel.innerHTML = "";
            if (this.launcherProfiles.length === 0) {
                const none = document.createElement("option");
                none.value = "";
                none.dataset.i18n = "launcher_no_profiles";
                none.textContent = this.t("launcher_no_profiles");
                sel.appendChild(none);
                continue;
            }
            for (const p of this.launcherProfiles) {
                const opt = document.createElement("option");
                opt.value = p.id;
                opt.textContent = this.profileOptionLabel(p);
                if (p.id === this.activeProfileId) opt.selected = true;
                sel.appendChild(opt);
            }
        }
        // Launcher page: a last entry that opens the profile editor.
        const pageSel = document.getElementById("launcher-page-profile-select") as HTMLSelectElement | null;
        if (pageSel) {
            const add = document.createElement("option");
            add.value = App.NEW_PROFILE_OPTION;
            add.dataset.i18n = "launcher_profile_new_option";
            add.textContent = this.t("launcher_profile_new_option");
            pageSel.appendChild(add);
        }
        this.startProfileExpiryTimer();
    }

    /** Profile list entry: name, email, type, session badge and session time left. */
    private profileOptionLabel(p: any): string {
        const expired = this.profileSessionExpired(p);
        const sessionBadge = p.session_valid && !expired ? " ✓" : p.has_session ? " ⚠" : "";
        const typeBadge = p.profile_type && p.profile_type !== "nexon" ? ` [${p.profile_type}]` : "";
        const emailPart = p.email ? ` (${p.email})` : "";
        const left = p.has_session ? this.formatExpiry(p.session_expires_at) : "";
        return `${p.name}${emailPart}${typeBadge}${sessionBadge}${left ? ` · ${left}` : ""}`;
    }

    /** Session time left until `expiresAt` (unix seconds): "29d 4h", "2h 15m", "45m",
     *  "Expired" (localized); "" when unknown. Same rules as profile::format_expiry. */
    private formatExpiry(expiresAt: number | undefined): string {
        if (!expiresAt) return "";
        const left = Math.floor(expiresAt - Date.now() / 1000);
        if (left <= 0) return this.t("launcher_expiry_expired");
        const d = Math.floor(left / 86400), h = Math.floor((left % 86400) / 3600), m = Math.floor((left % 3600) / 60);
        if (d > 0) return this.t("launcher_expiry_dh", [String(d), String(h)]);
        if (h > 0) return this.t("launcher_expiry_hm", [String(h), String(m)]);
        if (m > 0) return this.t("launcher_expiry_m", [String(m)]);
        return this.t("launcher_expiry_lt1m");
    }

    /** True when the profile's stored session is past its recorded expiry (unknown = no). */
    private profileSessionExpired(p: any): boolean {
        return !!p?.has_session && !!p.session_expires_at && p.session_expires_at <= Date.now() / 1000;
    }

    private profileExpiryTimer: number | null = null;

    /** Refresh the profile list's countdowns every 60 s (labels only; the selection stays). */
    private startProfileExpiryTimer() {
        if (this.profileExpiryTimer !== null) return;
        this.profileExpiryTimer = window.setInterval(() => {
            for (const selId of ["launcher-profile-select", "launcher-page-profile-select"]) {
                const sel = document.getElementById(selId) as HTMLSelectElement | null;
                if (!sel) continue;
                for (const opt of Array.from(sel.options)) {
                    const p = this.launcherProfiles.find(x => x.id === opt.value);
                    if (p) opt.textContent = this.profileOptionLabel(p);
                }
            }
        }, 60_000);
    }

    /** Record a new session expiry for a profile locally (the backend persisted it). */
    private noteProfileExpiry(id: string | null, expiresIn: number) {
        const p = id ? this.launcherProfiles.find(x => x.id === id) : null;
        if (!p || !(expiresIn > 0)) return;
        p.session_expires_at = Math.floor(Date.now() / 1000) + expiresIn;
        p.has_session = true;
        p.session_valid = true;
        for (const selId of ["launcher-profile-select", "launcher-page-profile-select"]) {
            const opt = Array.from((document.getElementById(selId) as HTMLSelectElement | null)?.options ?? []).find(o => o.value === p.id);
            if (opt) opt.textContent = this.profileOptionLabel(p);
        }
    }

    /** Auto-login is on but the stored session already expired: skip the doomed
     *  network round trip and go straight to the re-login prompt. */
    private async handleExpiredAutologin(p: any): Promise<boolean> {
        if (!p?.auto_login || !this.profileSessionExpired(p) || p.is_official === false) return false;
        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_session_expired_skip", [p.name])}`, "warn");
        await this.promptRelogin();
        return true;
    }

    /** Settings > Launcher (profile list); `newProfile` also opens a blank profile editor. */
    private openProfileManager(newProfile: boolean) {
        document.getElementById("tab-settings")?.click();
        setTimeout(() => {
            (document.querySelector("[data-stab='launcher']") as HTMLElement)?.click();
            if (newProfile) this.openProfileEditor("new");
        }, 50);
    }

    /** A profile can launch: official needs a game folder; a custom server also needs its login IP. */
    private profileUsable(p: any): boolean {
        if (!p?.client_dir) return false;
        return p.is_official !== false || !!p.login_ip;
    }

    /** Once per app run: when no saved profile can launch, open the profile manager,
     *  scan for installed launchers and start a new profile. */
    private noUsableProfilePrompted = false;
    private promptIfNoUsableProfile() {
        if (this.noUsableProfilePrompted || this.launcherProfiles.some(p => this.profileUsable(p))) return;
        this.noUsableProfilePrompted = true;
        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_no_usable_profile")}`, "warn");
        this.openProfileManager(true);
        void this.detectLauncherProfiles();
    }

    private applyProfileToUI(profile: any) {
        if (profile.client_dir) {
            (document.getElementById("launcher-client-dir") as HTMLInputElement).value = profile.client_dir;
        }
        if (profile.email) {
            (document.getElementById("launcher-email") as HTMLInputElement).value = profile.email;
            // Clear password when switching profiles so user gets a clean login form
            (document.getElementById("launcher-password") as HTMLInputElement).value = "";
        }
        // Track active profile server settings for launch
        this.activeProfileLoginIp = profile.login_ip || "";
        this.activeProfileLoginPort = profile.login_port || 0;
        this.activeProfileIsOfficial = profile.is_official !== false;
        // Re-apply login state now that activeProfileIsOfficial is set
        this.updateLauncherUI(!!this.launcherSession);

        const isCustom = !this.activeProfileIsOfficial;
        // Show login card only for official profiles; custom servers launch directly
        const loginCard = document.getElementById("launcher-login-card");
        const sessionCard = document.getElementById("launcher-session-card");
        if (loginCard) loginCard.style.display = isCustom ? "none" : "";
        if (sessionCard && isCustom) sessionCard.style.display = "none";

        // Update badge on launcher page
        const badge = document.getElementById("launcher-profile-badge");
        if (badge) {
            if (isCustom) {
                badge.textContent = this.t("launcher_badge_custom", [`${profile.login_ip}:${profile.login_port || 11000}`, profile.client_dir || this.t("launcher_no_game_dir")]);
            } else {
                const dir = profile.client_dir ? ` — ${profile.client_dir}` : "";
                badge.textContent = this.t("launcher_badge_official") + dir;
            }
        }
    }

    private async selectProfile(id: string) {
        this.activeProfileId = id;
        const profile = this.launcherProfiles.find(p => p.id === id);
        if (!profile) return;
        this.applyProfileToUI(profile);
        try { await invoke("launcher_set_active_profile", { id }); } catch {}
        if (await this.handleExpiredAutologin(profile)) return;
        if (profile.auto_login && profile.session_valid) {
            await this.autologinProfile(id);
        }
    }

    private async autologinProfile(profileId: string) {
        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_autologin_attempt", [profileId])}`, "info");
        try {
            const data = await invoke("launcher_load_profile", { id: profileId }) as any;
            const token = data.session_token_for_autologin;
            if (!token) { this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_autologin_no_token")}`, "warn"); return; }
            this.setLauncherStatus(this.t("launcher_autologging"), "busy");
            const result = await invoke("launcher_autologin", { sessionToken: token, profileId }) as any;
            if (!result.session) throw new Error(this.t("launcher_err_session_refresh"));
            this.launcherSession = result.session;
            this.updateLauncherUI(true);
            this.setLauncherStatus(this.t("launcher_autologged"), "ok");
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_autologin_ok")}`, "info");
            this.fetchLauncherVersion();
            // Update session expiry in profile
            await invoke("launcher_update_profile_session", {
                id: profileId,
                sessionToken: result.session.session_token,
                expiresIn: result.expiresIn || 86400,
            }).catch(() => {});
            this.noteProfileExpiry(profileId, result.expiresIn || 86400);
        } catch (e: any) {
            this.setLauncherStatus(this.t("launcher_autologin_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_autologin_failed", [String(e)])}`, "error");
        }
    }

    private openProfileEditor(mode: "new" | "edit") {
        this.profileEditorMode = mode;
        const editor = document.getElementById("launcher-profile-editor")!;
        editor.classList.remove("hidden");
        if (mode === "new") {
            (document.getElementById("launcher-profile-name") as HTMLInputElement).value = "";
            (document.getElementById("launcher-profile-email") as HTMLInputElement).value = "";
            (document.getElementById("launcher-profile-client-dir") as HTMLInputElement).value =
                (document.getElementById("launcher-client-dir") as HTMLInputElement)?.value || "";
            (document.getElementById("launcher-profile-autologin") as HTMLInputElement).checked = false;
            (document.getElementById("launcher-profile-custom-server") as HTMLInputElement).checked = false;
            const sf = document.getElementById("launcher-profile-server-fields");
            if (sf) sf.style.display = "none";
        } else {
            const profile = this.launcherProfiles.find(p => p.id === this.activeProfileId);
            if (profile) {
                (document.getElementById("launcher-profile-name") as HTMLInputElement).value = profile.name;
                (document.getElementById("launcher-profile-email") as HTMLInputElement).value = profile.email || "";
                (document.getElementById("launcher-profile-client-dir") as HTMLInputElement).value = profile.client_dir || "";
                (document.getElementById("launcher-profile-autologin") as HTMLInputElement).checked = !!profile.auto_login;
                const hasCustom = !!(profile.login_ip || profile.login_port);
                (document.getElementById("launcher-profile-custom-server") as HTMLInputElement).checked = hasCustom;
                const sf = document.getElementById("launcher-profile-server-fields");
                if (sf) sf.style.display = hasCustom ? "block" : "none";
                if (hasCustom) {
                    (document.getElementById("launcher-profile-login-ip") as HTMLInputElement).value = profile.login_ip || "";
                    (document.getElementById("launcher-profile-login-port") as HTMLInputElement).value = String(profile.login_port || "");
                    (document.getElementById("launcher-profile-chat-ip") as HTMLInputElement).value = profile.chat_ip || "";
                    (document.getElementById("launcher-profile-chat-port") as HTMLInputElement).value = String(profile.chat_port || "");
                }
            }
        }
    }

    private closeProfileEditor() {
        this.profileEditorMode = null;
        document.getElementById("launcher-profile-editor")?.classList.add("hidden");
    }

    private async saveProfileEditor() {
        const name = (document.getElementById("launcher-profile-name") as HTMLInputElement).value.trim();
        const clientDir = (document.getElementById("launcher-profile-client-dir") as HTMLInputElement).value.trim();
        const autoLogin = (document.getElementById("launcher-profile-autologin") as HTMLInputElement).checked;
        const emailEl = document.getElementById("launcher-profile-email") as HTMLInputElement;
        const email = emailEl?.value.trim() ||
            (document.getElementById("launcher-email") as HTMLInputElement)?.value.trim() ||
            this.launcherProfiles.find(p => p.id === this.activeProfileId)?.email || "";
        const useCustom = (document.getElementById("launcher-profile-custom-server") as HTMLInputElement)?.checked;
        const loginIp = useCustom ? (document.getElementById("launcher-profile-login-ip") as HTMLInputElement)?.value.trim() || null : null;
        const loginPort = useCustom ? (parseInt((document.getElementById("launcher-profile-login-port") as HTMLInputElement)?.value) || null) : null;
        const chatIp = useCustom ? (document.getElementById("launcher-profile-chat-ip") as HTMLInputElement)?.value.trim() || null : null;
        const chatPort = useCustom ? (parseInt((document.getElementById("launcher-profile-chat-port") as HTMLInputElement)?.value) || null) : null;

        if (!name) { this.setLauncherStatus(this.t("launcher_profile_name_required"), "error"); return; }

        const id = this.profileEditorMode === "edit" ? this.activeProfileId : null;

        try {
            const newId = await invoke("launcher_save_profile", {
                id, name, email, clientDir, autoLogin,
                profileType: useCustom ? "hyddwn" : "nexon",
                loginIp, loginPort, chatIp, chatPort,
                isOfficial: !useCustom,
            }) as string;
            this.activeProfileId = newId;
            (document.getElementById("launcher-client-dir") as HTMLInputElement).value = clientDir;
            await this.loadProfiles();
            this.closeProfileEditor();
            this.setLauncherStatus(this.t("launcher_profile_saved", [name]), "ok");
            this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_profile_saved", [name])}`, "info");
        } catch (e: any) {
            this.setLauncherStatus(this.t("features_save_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_profile_save_failed", [String(e)])}`, "error");
        }
    }

    private async detectLauncherProfiles() {
        const statusEl = document.getElementById("profile-detect-status");
        const areaEl = document.getElementById("detected-profiles-area");
        const listEl = document.getElementById("detected-profiles-list");
        if (statusEl) statusEl.textContent = this.t("launcher_scanning");
        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_scanning")}`, "info");
        try {
            const detected = await invoke("detect_launcher_profiles") as Array<{
                source: string; name: string; client_dir: string;
                login_ip: string; login_port: number;
                chat_ip: string; chat_port: number;
                is_official: boolean;
                profiles_path?: string;
            }>;
            if (!detected || detected.length === 0) {
                if (statusEl) statusEl.textContent = this.t("launcher_none_detected");
                if (areaEl) areaEl.style.display = "none";
                this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_none_detected")}`, "warn");
                return;
            }
            if (statusEl) statusEl.textContent = this.t("launcher_found_n", [String(detected.length)]);
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_detected", [String(detected.length), detected.map(d => d.name).join(", ")])}`, "info");
            if (areaEl) areaEl.style.display = "block";
            if (listEl) {
                listEl.innerHTML = "";
                for (const d of detected) {
                    const row = document.createElement("div");
                    row.style.cssText = "display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border-glass)";
                    const badge = d.is_official ? this.t("launcher_badge_official_short") : d.source.toUpperCase();
                    const info = d.is_official
                        ? `${d.name}${d.client_dir ? " — " + d.client_dir : ""}`
                        : `${d.name}${d.login_ip ? " — " + d.login_ip + ":" + d.login_port : ""}`;
                    // Kanan accounts import under their own email, so match any kanan profile.
                    const alreadyImported = this.launcherProfiles.some(
                        p => p.profile_type === d.source && (d.source === "kanan" ? !!p.email : p.name === d.name)
                    );
                    row.innerHTML = `
                        <span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px;background:var(--accent-cyan);color:#000">${badge}</span>
                        <span style="flex:1;font-size:12px">${info}</span>
                        <button class="tab-btn" style="font-size:11px;padding:2px 8px" ${alreadyImported ? "disabled" : ""}>${alreadyImported ? this.t("launcher_imported_check") : this.t("launcher_import")}</button>
                    `;
                    const importBtn = row.querySelector("button")!;
                    const detected_copy = d;
                    importBtn.addEventListener("click", async () => {
                        // Kanan entries carry accounts (profiles.dat): import those, not a blank profile.
                        if (detected_copy.source === "kanan" && detected_copy.profiles_path) {
                            await this.launcherImportKanan(detected_copy.profiles_path);
                            return;
                        }
                        try {
                            await invoke("launcher_save_profile", {
                                id: null,
                                name: detected_copy.name,
                                email: "",
                                clientDir: detected_copy.client_dir,
                                autoLogin: false,
                                profileType: detected_copy.source,
                                loginIp: detected_copy.login_ip || null,
                                loginPort: detected_copy.login_port || null,
                                chatIp: detected_copy.chat_ip || null,
                                chatPort: detected_copy.chat_port || null,
                                isOfficial: detected_copy.is_official,
                            });
                            await this.loadProfiles();
                            importBtn.textContent = this.t("launcher_imported");
                            importBtn.disabled = true;
                            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_imported", [detected_copy.name])}`, "info");
                        } catch (e: any) {
                            importBtn.textContent = this.t("status_error");
                            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_import_failed", [String(e)])}`, "error");
                        }
                    });
                    listEl.appendChild(row);
                }
            }
        } catch (e: any) {
            if (statusEl) statusEl.textContent = this.t("launcher_detect_failed", [String(e)]);
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_detect_failed", [String(e)])}`, "error");
        }
    }

    private async deleteActiveProfile() {
        if (!this.activeProfileId) return;
        const profile = this.launcherProfiles.find(p => p.id === this.activeProfileId);
        if (!profile) return;
        if (!confirm(this.t("confirm_delete_profile", [profile.name]))) return;
        const profileName = profile.name;
        try {
            await invoke("launcher_delete_profile", { id: this.activeProfileId });
            this.activeProfileId = null;
            await this.loadProfiles();
            this.setLauncherStatus(this.t("launcher_profile_deleted"), "idle");
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_profile_deleted", [profileName])}`, "info");
        } catch (e: any) {
            this.setLauncherStatus(this.t("launcher_delete_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_profile_delete_failed", [String(e)])}`, "error");
        }
    }

    private async saveCurrentSettingsToProfile() {
        const clientDir = (document.getElementById("launcher-client-dir") as HTMLInputElement).value.trim();
        if (this.activeProfileId && this.launcherSession) {
            try {
                const profile = this.launcherProfiles.find(p => p.id === this.activeProfileId);
                await invoke("launcher_save_profile", {
                    id: this.activeProfileId,
                    name: profile?.name || "Profile",
                    email: profile?.email || "",
                    clientDir,
                    autoLogin: profile?.auto_login || false,
                });
                if (this.launcherSession.session_token) {
                    await invoke("launcher_update_profile_session", {
                        id: this.activeProfileId,
                        sessionToken: this.launcherSession.session_token,
                        expiresIn: 86400,
                    });
                }
                await this.loadProfiles();
                this.setLauncherStatus(this.t("launcher_saved_to_profile"), "ok");
                this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_saved_session")}`, "info");
            } catch (e: any) {
                this.setLauncherStatus(this.t("features_save_failed", [String(e)]), "error");
                this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_save_to_profile_failed", [String(e)])}`, "error");
            }
        } else {
            // No active profile — open editor to create one
            this.openProfileEditor("new");
        }
    }

    private async launcherDoLogin() {
        const emailEl = document.getElementById("launcher-email") as HTMLInputElement;
        const pwEl = document.getElementById("launcher-password") as HTMLInputElement;
        const rememberEl = document.getElementById("launcher-remember") as HTMLInputElement;
        const email = emailEl.value.trim();
        const password = pwEl.value;
        if (!email || !password) { this.setLauncherStatus(this.t("launcher_email_pw_required"), "error"); return; }

        const btn = document.getElementById("btn-launcher-login") as HTMLButtonElement;
        btn.disabled = true;
        this.setLauncherStatus(this.t("launcher_logging_in"), "busy");

        try {
            let result: any;
            if ((this.config as any).launcher_legacy_auth) {
                // Email/password. 206 → emailed/authenticator code via launcher_login_otp.
                const vcodeEl = document.getElementById("launcher-verification") as HTMLInputElement;
                const code = vcodeEl ? vcodeEl.value.trim() : "";
                if (this.pendingMfaKey && code) {
                    result = await invoke("launcher_login_otp", {
                        mfaKey: this.pendingMfaKey, otp: code, profileId: this.activeProfileId || null, email,
                    }) as any;
                    this.pendingMfaKey = null;
                    if (vcodeEl) vcodeEl.value = "";
                } else {
                    if (!email || !password) { this.setLauncherStatus(this.t("launcher_email_pw_required"), "error"); btn.disabled = false; return; }
                    result = await invoke("launcher_login", {
                        username: email, password, remember: rememberEl.checked, profileId: this.activeProfileId || null,
                    }) as any;
                }
                if (result.mfa_required) {
                    this.pendingMfaKey = result.mfa_key;
                    const group = document.getElementById("launcher-verification-group");
                    if (group) group.style.display = "block";
                    vcodeEl?.focus();
                    this.setLauncherStatus(this.t("launcher_enter_mfa_code", [String(result.mfa_type || "email")]), "busy");
                    this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_mfa_requested")}`, "info");
                    return;
                }
                if (result.captcha_required) {
                    this.setLauncherStatus(this.t("launcher_captcha_required"), "error");
                    this.log(`[Launcher] ${result.message}`, "warn");
                    return;
                }
            } else {
                // Browser / SSO login: NxLSession or TpaSession → exchange.
                this.setLauncherStatus(this.t("launcher_login_popup"), "busy");
                result = await invoke("nexon_login_webview", { profileId: this.activeProfileId || null }) as any;
            }
            this.launcherSession = result.session;
            if (rememberEl.checked) {
                // Save session to active profile (the backend store; never localStorage)
                if (this.activeProfileId && result.session.session_token) {
                    await invoke("launcher_save_profile_session", {
                        id: this.activeProfileId,
                        session: result.session,
                        expiresIn: result.expiresIn || 86400,
                    }).catch(() => {});
                    await this.loadProfiles();
                }
            }
            pwEl.value = "";
            this.updateLauncherUI(true);
            this.setLauncherStatus(this.t("launcher_status_ok"), "ok");
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_logged_in_as", [email])}`, "info");
            this.fetchLauncherVersion();
        } catch (e: any) {
            this.setLauncherStatus(this.t("launcher_login_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_login_failed", [String(e)])}`, "error");
        } finally {
            btn.disabled = false;
        }
    }

    private launcherDoLogout() {
        this.launcherSession = null;
        try { localStorage.removeItem(this.LAUNCHER_SESSION_KEY); } catch {}
        this.updateLauncherUI(false);
        this.setLauncherStatus(this.t("launcher_status_idle"), "idle");
        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_logged_out")}`, "info");
        (document.getElementById("launcher-version-value") as HTMLElement).textContent = "—";
        (document.getElementById("launcher-maintenance-value") as HTMLElement).textContent = "—";
    }

    private async launcherImportSession() {
        const btn = document.getElementById("btn-launcher-import-session") as HTMLButtonElement;
        if (btn) btn.disabled = true;
        this.setLauncherStatus(this.t("launcher_importing_session"), "busy");
        try {
            const result = await invoke("launcher_import_session", { profileId: this.activeProfileId || null }) as { session: any };
            await this.adoptImportedSession(result.session);
            this.setLauncherStatus(this.t("launcher_session_imported"), "ok");
            this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_session_imported")}`, "info");
            this.fetchLauncherVersion();
        } catch (e) {
            this.setLauncherStatus(this.t("launcher_import_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_session_import_failed", [String(e)])}`, "error");
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    /** Use an imported session: keep it, and save it into the selected profile. */
    private async adoptImportedSession(session: any) {
        this.launcherSession = session;
        if (this.activeProfileId && session?.session_token) {
            await invoke("launcher_save_profile_session", { id: this.activeProfileId, session, expiresIn: 86400 })
                .catch((e) => this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_save_to_profile_failed", [String(e)])}`, "warn"));
            await this.loadProfiles();
        }
        this.updateLauncherUI(true);
    }

    /** Import saved accounts from Kanan's profiles.dat (asks for the Kanan master password). */
    private async launcherImportKanan(knownPath?: string) {
        const { importFromKanan } = await import("./kananImport");
        try {
            await importFromKanan({
                t: (k, a) => this.t(k, a ?? []),
                log: (m, l) => this.log(m, l),
                reloadProfiles: () => this.loadProfiles(),
            }, knownPath);
        } catch (e) {
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_kanan_import_failed", [String(e)])}`, "error");
        }
    }

    /** Import HyddwnLauncher's saved accounts (one profile + login each). */
    private async launcherImportHyddwn() {
        const { importFromHyddwn } = await import("./kananImport");
        try {
            await importFromHyddwn({
                t: (k, a) => this.t(k, a ?? []),
                log: (m, l) => this.log(m, l),
                reloadProfiles: () => this.loadProfiles(),
            });
        } catch (e) {
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_kanan_import_failed", [String(e)])}`, "error");
        }
    }

    /** Import a session from the user's installed browsers (Firefox, Chrome, Edge, Brave). */
    private async launcherImportBrowser() {
        const btn = document.getElementById("btn-launcher-import-browser") as HTMLButtonElement | null;
        if (btn) btn.disabled = true;
        this.setLauncherStatus(this.t("launcher_importing_browser"), "busy");
        try {
            const r = await invoke("launcher_import_browser", { profileId: this.activeProfileId || null }) as {
                session?: any; browser?: string; v20_found: boolean; notes: string[];
            };
            if (r.session) {
                await this.adoptImportedSession(r.session);
                const msg = this.t("launcher_browser_imported", [r.browser || "?"]);
                this.setLauncherStatus(msg, "ok");
                this.log(`${this.t("log_tag_launcher")} ${msg}`, "info");
                this.fetchLauncherVersion();
            } else {
                const msg = r.v20_found ? this.t("launcher_browser_v20") : this.t("launcher_browser_none");
                this.setLauncherStatus(msg, "error");
                this.log(`${this.t("log_tag_launcher")} ${msg}`, "warn");
            }
        } catch (e) {
            this.setLauncherStatus(this.t("launcher_import_failed", [String(e)]), "error");
            this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_import_failed", [String(e)])}`, "error");
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    /** Backend marker on errors meaning the Nexon session expired and could not be refreshed. */
    private static readonly RELOGIN_MARKER = "[RELOGIN]";

    /** True when an error from launch/patch/update-check means "log in again": the backend's
     *  marker, or an explicit HTTP 401. */
    private isReloginError(e: unknown): boolean {
        const s = String(e ?? "");
        if (s.includes(App.RELOGIN_MARKER)) return true;
        return /\b(?:HTTP|status(?: code)?)\s*:?\s*401\b|\(401\)|\b401 Unauthorized\b/i.test(s);
    }

    /** A command error carrying a session the backend refreshed before failing
     *  (`{ message, session }`): keep that session and return the message. */
    private errWithSession(e: any): any {
        if (e && typeof e === "object" && typeof e.message === "string" && e.session) {
            this.keepRefreshedSession(e.session);
            return e.message;
        }
        return e;
    }

    /** Error text without the backend's re-login marker. */
    private cleanErr(e: unknown): string {
        return String(e ?? "").split(App.RELOGIN_MARKER).join("").trim();
    }

    /** The session could not be refreshed: offer to log in again. */
    private async promptRelogin() {
        this.setLauncherStatus(this.t("launcher_session_expired"), "error");
        this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_session_expired")}`, "warn");
        const again = await ask(this.t("launcher_relogin_prompt"), { title: this.t("launcher_relogin_title"), kind: "warning" });
        // Keep the session unless the user chose to log in again.
        if (!again) return;
        this.launcherDoLogout();
        document.querySelector('.nav-item[data-tab="launcher"]')?.dispatchEvent(new Event('click'));
        if ((this.config as any).launcher_legacy_auth) {
            (document.getElementById("launcher-password") as HTMLInputElement | null)?.focus();
            this.setLauncherStatus(this.t("launcher_relogin_enter_pw"), "idle");
        } else {
            await this.launcherDoLogin();
        }
    }

    private async launcherDoLaunch() {
        const isCustomServer = !this.activeProfileIsOfficial;
        if (!isCustomServer && !this.launcherSession) {
            this.setLauncherStatus(this.t("launcher_login_first"), "error");
            return;
        }
        if (!isCustomServer) {
            const active = this.launcherProfiles.find(p => p.id === this.activeProfileId);
            if (this.profileSessionExpired(active)) {
                // The stored session is past its expiry: a launch could only fail with 401.
                this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_session_expired_skip", [active.name])}`, "warn");
                await this.promptRelogin();
                return;
            }
        }
        const clientDir = (document.getElementById("launcher-client-dir") as HTMLInputElement).value.trim();
        if (!clientDir) { this.setLauncherStatus(this.t("launcher_folder_required"), "error"); return; }

        const btn = document.getElementById("btn-launcher-launch") as HTMLButtonElement;
        btn.disabled = true;
        this.setLauncherStatus(this.t("launcher_launching"), "busy");

        await this.loadSharedConfig();
        const preLaunchCmd = this.sharedConfig.hooks.before_launch?.trim() || "";
        const postLaunchCmd = this.sharedConfig.hooks.after_launch?.trim() || "";
        const launchCmdOverride = (document.getElementById("launch-cmd-override") as HTMLTextAreaElement)?.value?.trim() || "";
        const useNexonLauncher = (document.getElementById("launch-use-nexon-launcher") as HTMLInputElement)?.checked ?? false;

        this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_launching_from", [clientDir])}${isCustomServer ? " " + this.t("log_launcher_custom_server_suffix", [this.activeProfileLoginIp]) : ""}`, "info");
        if (preLaunchCmd) this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_pre_launch", [preLaunchCmd])}`, "info");

        try {
            const r = await invoke("launcher_launch", {
                session: this.launcherSession || null,
                clientDir,
                // Don't pass loginIp for official Nexon servers — use OAuth passport flow instead
                loginIp: (this.activeProfileIsOfficial ? null : this.activeProfileLoginIp) || null,
                loginPort: (this.activeProfileIsOfficial ? null : this.activeProfileLoginPort) || null,
                preLaunchCmd: preLaunchCmd || null,
                postLaunchCmd: postLaunchCmd || null,
                launchCmdOverride: launchCmdOverride || null,
                useNexonLauncher,
                profileId: this.activeProfileId || null,
                profileName: this.activeProfileName() || null,
            }) as any;
            if (r.relogin_required) {
                this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_launch_failed", [String(r.error ?? "")])}`, "warn");
                btn.disabled = false;
                await this.promptRelogin();
                return;
            }
            if (r.session) {
                // The launch may have refreshed an expired AToken (401 → autologin) — keep it
                // (and persist the renewed NxLSession expiry on the active profile).
                if (r.sessionExpiresIn && !r.session.refreshed_expires_in) r.session.refreshed_expires_in = r.sessionExpiresIn;
                this.keepRefreshedSession(r.session);
            }
            const result = document.getElementById("launcher-launch-result")!;
            result.textContent = this.t("launcher_launched_exe", [String(r.executable), String(r.argumentCount)]) + (r.patchAvailable ? " — " + this.t("launcher_update_available_suffix") : "");
            result.className = "launcher-launch-result success";
            result.classList.remove("hidden");
            this.setLauncherStatus(this.t("launcher_launched"), "ok");
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_launched", [String(r.executable), String(r.argumentCount)])}`, "info");
            if (postLaunchCmd) this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_post_launch", [postLaunchCmd])}`, "info");
        } catch (e: any) {
            e = this.errWithSession(e);
            // Any failed token refresh means the stored session is dead: offer a fresh login.
            if (this.isReloginError(e)) {
                this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_launch_failed", [this.cleanErr(e)])}`, "warn");
                btn.disabled = false;
                await this.promptRelogin();
                return;
            }
            const result = document.getElementById("launcher-launch-result")!;
            result.textContent = this.t("launcher_launch_failed", [String(e)]);
            result.className = "launcher-launch-result error";
            result.classList.remove("hidden");
            this.setLauncherStatus(this.t("launcher_launch_error", [String(e)]), "error");
            this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_launch_failed", [String(e)])}`, "error");
        } finally {
            btn.disabled = false;
        }
    }

    private async fetchLauncherVersion() {
        if (!this.launcherSession) return;

        // Version check: CDN first, fall back to local patchdata
        let verStr = "—";
        try {
            const res = await invoke("launcher_get_version", { session: this.launcherSession }) as { version: number; session?: any };
            this.keepRefreshedSession(res.session);
            const ver = res.version;
            verStr = ver > 0 ? String(ver) : "—";
        } catch {
            try {
                const gp = (this.config as any)?.patcher_game_path;
                if (gp) {
                    const pv = await invoke("check_patch_version", { gamePath: gp, session: this.launcherSession }) as any;
                    this.keepRefreshedSession(pv.session);
                    const ver = (pv.remote_version ?? pv.local_version) as number | null;
                    if (ver && ver > 0) verStr = String(ver);
                }
            } catch {}
        }
        (document.getElementById("launcher-version-value") as HTMLElement).textContent = verStr;
        this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_version_label")} ${verStr}`, "info");

        // Maintenance check is independent of version check
        try {
            const maint = await invoke("launcher_check_maintenance", { session: this.launcherSession }) as boolean;
            const maintText = maint ? this.t("label_yes") : this.t("label_no");
            (document.getElementById("launcher-maintenance-value") as HTMLElement).textContent = maintText;
            this.log(`${this.t("log_tag_launcher")} ${this.t("launcher_maintenance_label")} ${maintText}`, "info");
        } catch (e) {
            this.log(`${this.t("log_tag_launcher")} ${this.t("log_launcher_maint_failed", [String(e)])}`, "warn");
        }
    }

    private updateLauncherUI(loggedIn: boolean) {
        const group = document.getElementById("launcher-verification-group");
        if (group) { group.style.display = (this.config as any).launcher_legacy_auth ? "block" : "none"; }
        
        // Only touch login/session cards if we're in official-server mode
        const isCustom = !this.activeProfileIsOfficial;
        if (!isCustom) {
            document.getElementById("launcher-login-card")?.classList.toggle("hidden", loggedIn);
            document.getElementById("launcher-session-card")?.classList.toggle("hidden", !loggedIn);
        }
        if (loggedIn && this.launcherSession) {
            const token = this.launcherSession.session_token;
            const preview = token ? token.substring(0, 12) + "…" : "—";
            (document.getElementById("launcher-session-preview") as HTMLElement).textContent = preview;
        }
        const dot = document.getElementById("launcher-status-dot");
        if (dot) dot.style.background = loggedIn ? "var(--green, #4ade80)" : "var(--yellow, #facc15)";
        const statusText = document.getElementById("launcher-status-text");
        if (statusText && !loggedIn) statusText.textContent = this.t("launcher_status_idle");
        if (statusText && loggedIn) statusText.textContent = this.t("launcher_status_ok");
    }

    private setLauncherStatus(msg: string, type: "ok" | "error" | "busy" | "idle") {
        const el = document.getElementById("launcher-status-text");
        if (el) el.textContent = msg;
        const dot = document.getElementById("launcher-status-dot");
        if (dot) {
            const colours: Record<string, string> = { ok: "#4ade80", error: "#f87171", busy: "#facc15", idle: "#6b7280" };
            dot.style.background = colours[type] ?? colours.idle;
        }
    }

    private addActivity(message: string) {
        const list = document.getElementById("activity-list");
        if (!list) return;
        list.querySelector(".no-activity")?.remove();
        const item = document.createElement("div");
        item.className = "activity-item";
        const time = new Date().toLocaleTimeString();
        item.innerHTML = `<span class="activity-time">${time}</span> <span class="activity-text">${message}</span>`;
        list.prepend(item);
        if (list.children.length > 10) list.lastElementChild?.remove();
    }

    private setupNavigation() {
        document.querySelectorAll(".nav-item").forEach(item => {
            item.addEventListener("click", () => {
                const tab = item.getAttribute("data-tab");
                if (!tab) return;

                document.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
                item.classList.add("active");

                document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
                document.getElementById(tab)?.classList.add("active");
            });
        });

        // Settings sub-tab switching
        document.querySelectorAll(".settings-stab").forEach(btn => {
            btn.addEventListener("click", () => {
                document.querySelectorAll(".settings-stab").forEach(b => b.classList.remove("active"));
                document.querySelectorAll(".settings-stab-content").forEach(c => c.classList.remove("active"));
                btn.classList.add("active");
                const stab = btn.getAttribute("data-stab");
                if (stab) document.getElementById("stab-" + stab)?.classList.add("active");
            });
        });

        document.getElementById("sidebar-toggle")?.addEventListener("click", () => {
            const sidebar = document.querySelector(".sidebar") as HTMLElement;
            const btn = document.getElementById("sidebar-toggle")!;
            sidebar.classList.toggle("collapsed");
            btn.textContent = sidebar.classList.contains("collapsed") ? "▶" : "◀";
        });
    }

    private setupResizableList() {
        const handle = document.getElementById("list-split-handle");
        const leftPane = document.querySelector(".file-list-pane") as HTMLElement | null;
        if (!handle || !leftPane) return;

        const saved = localStorage.getItem("list-split-px");
        if (saved) leftPane.style.flex = `0 0 ${saved}px`;

        let dragging = false;
        let startX = 0;
        let startWidth = 0;

        handle.addEventListener("mousedown", (e) => {
            dragging = true;
            startX = (e as MouseEvent).clientX;
            startWidth = leftPane.getBoundingClientRect().width;
            handle.classList.add("dragging");
            document.body.style.cursor = "col-resize";
            document.body.style.userSelect = "none";
            e.preventDefault();
        });
        document.addEventListener("mousemove", (e) => {
            if (!dragging) return;
            const delta = (e as MouseEvent).clientX - startX;
            const w = Math.max(150, Math.min(700, startWidth + delta));
            leftPane.style.flex = `0 0 ${w}px`;
        });
        document.addEventListener("mouseup", () => {
            if (!dragging) return;
            dragging = false;
            handle.classList.remove("dragging");
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
            localStorage.setItem("list-split-px", String(Math.round(leftPane.getBoundingClientRect().width)));
        });
    }

    /** Horizontal handle between the tab content and the LOGS console: drag to resize the console. */
    private setupResizableConsole() {
        const handle = document.getElementById("console-split-handle");
        const consoleEl = document.querySelector(".log-container") as HTMLElement | null;
        if (!handle || !consoleEl) return;

        const saved = localStorage.getItem("console-height-px");
        if (saved) consoleEl.style.height = `${saved}px`;

        let dragging = false;
        let startY = 0;
        let startHeight = 0;

        handle.addEventListener("mousedown", (e) => {
            dragging = true;
            startY = (e as MouseEvent).clientY;
            startHeight = consoleEl.getBoundingClientRect().height;
            handle.classList.add("dragging");
            document.body.style.cursor = "row-resize";
            document.body.style.userSelect = "none";
            e.preventDefault();
        });
        document.addEventListener("mousemove", (e) => {
            if (!dragging) return;
            // Dragging up grows the console; keep at least 80px of console and 200px of content.
            const max = Math.max(80, window.innerHeight - 200);
            const h = Math.max(80, Math.min(max, startHeight - ((e as MouseEvent).clientY - startY)));
            consoleEl.style.height = `${h}px`;
        });
        document.addEventListener("mouseup", () => {
            if (!dragging) return;
            dragging = false;
            handle.classList.remove("dragging");
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
            localStorage.setItem("console-height-px", String(Math.round(consoleEl.getBoundingClientRect().height)));
        });
        handle.addEventListener("dblclick", () => {
            consoleEl.style.height = "";
            localStorage.removeItem("console-height-px");
        });
    }

    /** `.menu-btn` dropdowns: the toggle opens its list; picking an item or clicking elsewhere closes it. */
    private setupMenuButtons() {
        const closeAll = (except?: Element) => document.querySelectorAll(".menu-btn.open").forEach(m => {
            if (m === except) return;
            m.classList.remove("open");
            m.querySelector(".menu-btn-toggle")?.setAttribute("aria-expanded", "false");
        });
        document.querySelectorAll(".menu-btn").forEach(menu => {
            const toggle = menu.querySelector(".menu-btn-toggle");
            toggle?.addEventListener("click", (e) => {
                e.stopPropagation();
                closeAll(menu);
                const open = menu.classList.toggle("open");
                toggle.setAttribute("aria-expanded", String(open));
            });
            menu.querySelectorAll(".menu-btn-item").forEach(item => item.addEventListener("click", () => closeAll()));
        });
        document.addEventListener("click", () => closeAll());
        document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAll(); });
    }

    private setup3dPreviewResize() {
        const handle = document.getElementById("preview-3d-resize-handle");
        const viewport = document.getElementById("three-viewport");
        if (!handle || !viewport) return;

        // The viewport flexes to the available height (min 240px, see styles.css). A
        // dragged height becomes its preferred size but may still shrink to fit.
        const MIN_H = 240;
        const setPreferred = (h: number) => { viewport.style.flex = `0 1 ${Math.max(MIN_H, h)}px`; };
        let saved: string | null = null;
        try { saved = localStorage.getItem("preview-3d-height"); } catch { /* storage unavailable */ }
        if (saved && !isNaN(parseInt(saved, 10))) setPreferred(parseInt(saved, 10));
        // Keep the renderer in step with layout changes (window resize, flex changes).
        if (typeof ResizeObserver !== "undefined") {
            new ResizeObserver(() => (window as any).__threeResizeFn?.()).observe(viewport);
        }

        let dragging = false;
        let startY = 0;
        let startH = 0;

        handle.addEventListener("mousedown", (e) => {
            dragging = true;
            startY = (e as MouseEvent).clientY;
            startH = viewport.getBoundingClientRect().height;
            document.body.style.cursor = "ns-resize";
            document.body.style.userSelect = "none";
            (e as MouseEvent).preventDefault();
        });
        document.addEventListener("mousemove", (e) => {
            if (!dragging) return;
            const delta = (e as MouseEvent).clientY - startY;
            setPreferred(startH + delta);
            // Notify three.js of resize if renderer is registered
            (window as any).__threeResizeFn?.();
        });
        document.addEventListener("mouseup", () => {
            if (!dragging) return;
            dragging = false;
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
            try { localStorage.setItem("preview-3d-height", String(Math.round(viewport.getBoundingClientRect().height))); } catch { /* storage unavailable */ }
        });
    }

    private setupForms() {
        // Browse Buttons
        document.getElementById("btn-browse-extract-in")?.addEventListener("click", async () => {
            const isFullSeq = (document.getElementById("extract-full-sequence") as HTMLInputElement).checked;
            const path = isFullSeq
                ? await open({ directory: true })
                : await open({ filters: [{ name: this.t("dlg_filter_mabi_archive"), extensions: ["it", "pack"] }] });
            if (path && !Array.isArray(path)) {
                (document.getElementById("extract-input") as HTMLInputElement).value = path;
                this.handlePathAutoFill("extract-input", path);
            }
        });
        document.getElementById("btn-browse-extract-out")?.addEventListener("click", async () => {
            const path = await open({ directory: true });
            if (path && !Array.isArray(path)) (document.getElementById("extract-output") as HTMLInputElement).value = path;
        });
        document.getElementById("btn-browse-pack-in")?.addEventListener("click", async () => {
            const path = await open({ directory: true });
            if (path && !Array.isArray(path)) {
                (document.getElementById("pack-input") as HTMLInputElement).value = path;
                this.handlePathAutoFill("pack-input", path);
            }
        });
        document.getElementById("btn-browse-pack-out")?.addEventListener("click", async () => {
            const path = await save({ filters: [{ name: this.t("dlg_filter_mabi_archive"), extensions: ["it"] }] });
            if (path) (document.getElementById("pack-output") as HTMLInputElement).value = path;
        });
        document.getElementById("btn-browse-list")?.addEventListener("click", async () => {
            const isFullSeq = (document.getElementById("list-full-sequence") as HTMLInputElement).checked;
            const path = isFullSeq
                ? await open({ directory: true })
                : await open({ filters: [{ name: this.t("dlg_filter_mabi_archive"), extensions: ["it", "pack"] }] });
            if (path && !Array.isArray(path)) {
                (document.getElementById("list-input") as HTMLInputElement).value = path;
                this.runList();
            }
        });
        document.getElementById("list-input")?.addEventListener("keydown", (e) => {
            if ((e as KeyboardEvent).key === "Enter") this.runList();
        });
        document.getElementById("btn-browse-differ-old")?.addEventListener("click", async () => {
            const path = await open({ directory: true });
            if (path && !Array.isArray(path)) (document.getElementById("differ-old") as HTMLInputElement).value = path;
        });
        document.getElementById("btn-browse-differ-new")?.addEventListener("click", async () => {
            const path = await open({ directory: true });
            if (path && !Array.isArray(path)) (document.getElementById("differ-new") as HTMLInputElement).value = path;
        });
        document.getElementById("btn-browse-differ-out")?.addEventListener("click", async () => {
            const path = await save({ filters: [{ name: this.t("dlg_filter_mabi_archive"), extensions: ["it"] }] });
            if (path) (document.getElementById("differ-output") as HTMLInputElement).value = path;
        });

        // Run Buttons
        document.getElementById("extract-run")?.addEventListener("click", () => this.runExtract());
        document.getElementById("pack-run")?.addEventListener("click", () => this.runPack());
        document.getElementById("differ-run")?.addEventListener("click", () => this.runDiffer());

        // Settings
        document.getElementById("settings-theme")?.addEventListener("change", (e) => {
            this.config.theme = (e.target as HTMLSelectElement).value;
            this.applyTheme();
            this.saveConfig();
        });
        document.getElementById("settings-lang")?.addEventListener("change", async (e) => {
            this.config.locale = (e.target as HTMLSelectElement).value;
            this.translateUI();
            await this.saveConfig();
            // Re-register shell verbs so context menu labels match the new language
            if (this.config.associate_it || this.config.associate_pack || this.config.associate_dds || this.config.associate_pmg || this.config.associate_xmlcompiled) {
                try {
                    await invoke("register_associations", {
                        it: this.config.associate_it,
                        pack: this.config.associate_pack,
                        itFull: this.config.associate_it_full,
                        itDesc: this.t("shell_open_it"),
                        packDesc: this.t("shell_open_pack"),
                        itFullDesc: this.t("shell_open_full"),
                        dds: this.config.associate_dds,
                        pmg: this.config.associate_pmg,
                        xmlcompiled: this.config.associate_xmlcompiled
                    });
                } catch (_) { /* silent — not admin, will be applied next time btn_admin is clicked */ }
            }
        });
        document.getElementById("settings-log")?.addEventListener("change", (e) => {
            this.config.log_level = (e.target as HTMLSelectElement).value;
            this.saveConfig();
        });
        document.getElementById("settings-region-key")?.addEventListener("input", (e) => {
            this.config.region_key = (e.target as HTMLInputElement).value;
            this.saveConfig();
        });
        document.getElementById("settings-write-salt")?.addEventListener("input", (e) => {
            this.config.write_salt = (e.target as HTMLInputElement).value;
            this.saveConfig();
        });
        document.getElementById("settings-pack-v1-version")?.addEventListener("change", (e) => {
            const v = parseInt((e.target as HTMLInputElement).value, 10);
            if (v > 0) { this.config.pack_v1_version = v; this.saveConfig(); }
        });
        document.getElementById("settings-sequence-ignore")?.addEventListener("input", (e) => {
            const lines = (e.target as HTMLTextAreaElement).value
                .split('\n').map(s => s.trim()).filter(s => s.length > 0);
            this.config.sequence_ignore_list = lines;
            this.saveConfig();
        });

        const toggleIds = [
            { id: "settings-assoc-it", prop: "associate_it" },
            { id: "settings-assoc-pack", prop: "associate_pack" },
            { id: "settings-assoc-it-full", prop: "associate_it_full" },
            { id: "settings-assoc-dds", prop: "associate_dds" },
            { id: "settings-assoc-pmg", prop: "associate_pmg" },
            { id: "settings-assoc-xmlcompiled", prop: "associate_xmlcompiled" },
            { id: "settings-auto-png", prop: "auto_convert_png" },
            { id: "settings-auto-dds", prop: "auto_convert_dds" },
            { id: "settings-auto-features", prop: "auto_convert_features" },
            { id: "settings-auto-pmg", prop: "auto_convert_pmg" },
            { id: "extract-auto-png", prop: "auto_convert_png" },
            { id: "pack-auto-dds", prop: "auto_convert_dds" },
            { id: "settings-startup-extract", prop: "startup_auto_extract" },
            { id: "settings-startup-switch", prop: "startup_auto_switch" },
            { id: "list-full-sequence", prop: "list_full_sequence" },
            { id: "extract-full-sequence", prop: "list_full_sequence" },
            { id: "settings-list-auto-expand", prop: "list_auto_expand" },
            { id: "audio-autoplay", prop: "audio_autoplay" },
            { id: "settings-audio-autoplay", prop: "audio_autoplay" },
            { id: "audio-loop", prop: "audio_loop" },
            { id: "settings-audio-loop", prop: "audio_loop" },
        ];

        toggleIds.forEach(t => {
            const el = document.getElementById(t.id) as HTMLInputElement;
            if (el) {
                el.addEventListener("change", (e) => {
                    (this.config as any)[t.prop] = (e.target as HTMLInputElement).checked;
                    this.saveConfig();
                    this.syncSettingsUI();
                });
            }
        });

        // Radio group for auto-select mode
        document.querySelectorAll('input[name="list-auto-select"]').forEach(radio => {
            radio.addEventListener("change", (e) => {
                const val = (e.target as HTMLInputElement).value as "none" | "first" | "all";
                this.config.list_auto_select = val;
                this.saveConfig();
            });
        });

        ["extract", "pack", "differ"].forEach(p => this.setupSaltCombo(p));

        document.getElementById("btn_admin")?.addEventListener("click", async () => {
            try {
                await invoke("register_associations", {
                    it: this.config.associate_it,
                    pack: this.config.associate_pack,
                    itFull: this.config.associate_it_full,
                    itDesc: this.t("shell_open_it"),
                    packDesc: this.t("shell_open_pack"),
                    itFullDesc: this.t("shell_open_full"),
                    dds: this.config.associate_dds,
                    pmg: this.config.associate_pmg,
                    xmlcompiled: this.config.associate_xmlcompiled
                });
                this.log(this.t("log_registry_updated"), "success");
            } catch (e) { this.log(this.t("log_registry_error", [String(e)]), "error"); }
        });

        document.getElementById("btn_wipe")?.addEventListener("click", () => this.wipeHistory());

        // Config path / portable mode controls
        const refreshConfigPath = async () => {
            const p = await invoke<string>("get_config_path_str");
            const el = document.getElementById("config-path-display") as HTMLInputElement | null;
            if (el) el.value = p;
        };
        const refreshPortableToggle = async () => {
            const portable = await invoke<boolean>("is_portable_mode");
            const el = document.getElementById("settings-portable-mode") as HTMLInputElement | null;
            if (el) el.checked = portable;
        };
        refreshConfigPath();
        refreshPortableToggle();

        const parallelEl = document.getElementById("settings-parallel-ops") as HTMLInputElement | null;
        if (parallelEl) parallelEl.checked = this.config.parallel_ops ?? true;
        parallelEl?.addEventListener("change", () => { this.config.parallel_ops = parallelEl.checked; this.saveConfig(); });

        const trayEl = document.getElementById("settings-minimize-to-tray") as HTMLInputElement | null;
        if (trayEl) trayEl.checked = this.config.minimize_to_tray ?? false;
        trayEl?.addEventListener("change", () => { this.config.minimize_to_tray = trayEl.checked; this.saveConfig(); });

        // Start with Windows: a quoted HKCU Run entry with --minimized (starts in the tray).
        const autoStartEl = document.getElementById("settings-start-with-windows") as HTMLInputElement | null;
        if (!navigator.userAgent.includes("Windows")) {
            document.getElementById("settings-start-with-windows-row")?.remove();
        } else if (autoStartEl) {
            invoke("get_start_with_windows").then(v => { autoStartEl.checked = !!v; }).catch(() => {});
            autoStartEl.addEventListener("change", async () => {
                try {
                    await invoke("set_start_with_windows", { enabled: autoStartEl.checked });
                } catch (e) {
                    autoStartEl.checked = !autoStartEl.checked;
                    this.log(this.t("log_start_with_windows_failed", [String(e)]), "error");
                }
            });
        }

        // In-app REST API (same server as `mabi-patcher serve`, loopback only).
        const apiChk = document.getElementById("settings-api-enabled") as HTMLInputElement | null;
        const apiPortEl = document.getElementById("settings-api-port") as HTMLInputElement | null;
        if (apiChk) apiChk.checked = this.config.api_enabled ?? false;
        if (apiPortEl) apiPortEl.value = String(this.config.api_port ?? 7331);
        const applyApi = async () => {
            const port = Math.min(65535, Math.max(1, parseInt(apiPortEl?.value ?? "7331", 10) || 7331));
            if (apiPortEl) apiPortEl.value = String(port);
            this.config.api_enabled = apiChk?.checked ?? false;
            this.config.api_port = port;
            this.saveConfig();
            try {
                if (this.config.api_enabled) {
                    const bound = await invoke<number>("api_start", { port });
                    this.log(this.t("log_api_started", [String(bound)]));
                } else {
                    await invoke("api_stop");
                    this.log(this.t("log_api_stopped"));
                }
            } catch (err) {
                this.log(this.t("log_api_start_failed", [String(err)]), "error");
                if (apiChk) apiChk.checked = false;
                this.config.api_enabled = false;
                this.saveConfig();
            }
            await this.refreshApiBadge();
        };
        apiChk?.addEventListener("change", applyApi);
        apiPortEl?.addEventListener("change", () => { if (apiChk?.checked) applyApi(); else { this.config.api_port = parseInt(apiPortEl.value, 10) || 7331; this.saveConfig(); } });
        this.refreshApiBadge();

        document.getElementById("settings-portable-mode")?.addEventListener("change", async (e) => {
            const enable = (e.target as HTMLInputElement).checked;
            try {
                await invoke("set_portable_mode", { enable });
                await refreshConfigPath();
            } catch (err) {
                alert(this.t("msg_portable_switch_failed", [String(err)]));
                await refreshPortableToggle(); // revert toggle
            }
        });
        document.getElementById("btn_open_config_dir")?.addEventListener("click", async () => {
            const p = await invoke<string>("get_config_path_str");
            // Use /select to highlight the file in Explorer; works on both / and \ paths
            await invoke("execute_terminal_command", { command: `explorer /select,"${p}"` });
        });
        document.getElementById("btn_reset_config")?.addEventListener("click", async () => {
            if (!confirm(this.t("confirm_reset_config"))) return;
            await invoke("reset_config");
            location.reload();
        });
        document.getElementById("btn_wipe_assoc")?.addEventListener("click", async () => {
            if (!confirm(this.t("confirm_wipe_assoc"))) return;
            await invoke("wipe_registry_associations");
            alert(this.t("msg_wipe_assoc_done"));
        });

        // List tab additional actions
        document.getElementById("ctxConvIt")?.addEventListener("click", () => this.convertTo("it"));
        document.getElementById("ctxConvPack")?.addEventListener("click", () => this.convertTo("pack"));
        document.getElementById("extractSelected")?.addEventListener("click", () => this.extractSelected());
        document.getElementById("extractAll")?.addEventListener("click", () => this.extractAll());

        // File Search
        document.getElementById("file-search-filter")?.addEventListener("input", (e) => {
            const filter = (e.target as HTMLInputElement).value.toLowerCase();
            this.renderTree(filter);
        });

        // Terminal handling
        document.getElementById("terminal-input")?.addEventListener("keydown", (e) => {
            if ((e as KeyboardEvent).key === "Enter") {
                const input = e.target as HTMLInputElement;
                this.handleTerminalCommand(input.value);
                input.value = "";
            }
        });

        // Preview Tab switching
        document.querySelectorAll(".preview-tab-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const target = btn.getAttribute("data-ptab");
                if (!target) return;

                document.querySelectorAll(".preview-tab-btn").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");

                document.querySelectorAll(".preview-tab-content").forEach(c => c.classList.remove("active"));
                // "visual" tab restores the actual preview container (audio/3d/visual)
                const actualId = (target === "visual") ? this._activePreviewContainer : `preview-${target}`;
                document.getElementById(actualId)?.classList.add("active");
            });
        });
    }

    private handlePathAutoFill(sourceId: string, path: string) {
        if (sourceId === "extract-input") {
            const outInput = document.getElementById("extract-output") as HTMLInputElement;
            if (!outInput.value) {
                const lastSep = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
                outInput.value = lastSep !== -1 ? path.substring(0, lastSep) : path;
            }
        } else if (sourceId === "pack-input") {
            const outInput = document.getElementById("pack-output") as HTMLInputElement;
            if (!outInput.value) {
                const cleanPath = path.replace(/[/\\]$/, "");
                const lastSep = Math.max(cleanPath.lastIndexOf("\\"), cleanPath.lastIndexOf("/"));
                const folderName = lastSep !== -1 ? cleanPath.substring(lastSep + 1) : cleanPath;
                const parentDir = lastSep !== -1 ? cleanPath.substring(0, lastSep) : cleanPath;
                outInput.value = `${parentDir}${path.includes("\\") ? "\\" : "/"}${folderName}.it`;
            }
        }
    }

    private async saveConfig() {
        try {
            await invoke("set_config", { config: this.config });
        } catch (e) { console.error("Save config error", e); }
    }

    private log(message: string, level: string = "info", fromRust: boolean = false) {
        const logView = document.getElementById("log-view");
        if (!logView) return;

        const entry = document.createElement("div");
        entry.className = `log-entry ${level}`;
        const time = new Date().toLocaleTimeString();
        entry.textContent = `[${time}] ${message}`;
        logView.appendChild(entry);
        logView.scrollTop = logView.scrollHeight;

        // Forward JS-originated messages to log.txt (Rust messages are already written by the file logger)
        if (!fromRust) {
            const fileLevel = level === "success" ? "info" : level;
            invoke("log_to_file", { level: fileLevel, message }).catch(() => {});
        }
    }

    private async runExtract() {
        if (this._taskStartTime !== null) {
            await message(this.t("msg_task_running"), { title: this.t("dlg_task_in_progress"), kind: "warning" });
            return;
        }
        const input = (document.getElementById("extract-input") as HTMLInputElement).value;
        const output = (document.getElementById("extract-output") as HTMLInputElement).value;
        const key = (document.getElementById("extract-key") as HTMLInputElement).value || null;
        const filterStr = (document.getElementById("extract-filters") as HTMLInputElement).value;
        const filters = filterStr.split(',').map(f => f.trim()).filter(f => f.length > 0);

        if (!input || !output) {
            await message(this.t("msg_extract_missing_fields"), { title: this.t("dlg_missing_fields"), kind: "error" });
            return;
        }
        this._taskStartTime = Date.now();
        this.updateProgress(0, this.t("msg_extracting"));
        try {
            await invoke("extract_pack_to", { input, output, key, filters });
            this.log(this.t("extract_success", [input]), "success");
            this.addActivity(this.t("extract_success", [input]));
        } catch (e) {
            this._taskStartTime = null;
            this.updateProgress(0, "");
            this.log(this.t("msg_error_fmt", [String(e)]), "error");
        }
    }

    private async runPack() {
        if (this._taskStartTime !== null) {
            await message(this.t("msg_task_running"), { title: this.t("dlg_task_in_progress"), kind: "warning" });
            return;
        }
        const input = (document.getElementById("pack-input") as HTMLInputElement).value;
        const output = (document.getElementById("pack-output") as HTMLInputElement).value;
        const key = (document.getElementById("pack-key") as HTMLInputElement).value;
        const formatsStr = (document.getElementById("pack-formats") as HTMLInputElement).value;
        const formats = formatsStr.split(',').map(f => f.trim()).filter(f => f.length > 0);
        const ivVal = parseInt((document.getElementById("pack-iv") as HTMLInputElement).value) || 0;

        if (!input || !output || !key) {
            await message(this.t("msg_pack_missing_fields"), { title: this.t("dlg_missing_fields"), kind: "error" });
            return;
        }

        this._taskStartTime = Date.now();
        this.updateProgress(0, this.t("msg_packing"));
        let pathPrefix: string | null = null;
        try {
            const hasDataFolder = await invoke("check_data_folder", { path: input }) as boolean;
            if (!hasDataFolder && this.config.pack_wrap_mode !== "none") {
                const doWrap = await ask(this.t("dataWrapPrompt"), {
                    title: this.t("dataWrapTitle"),
                    kind: 'warning'
                });
                if (doWrap) {
                    pathPrefix = await this.resolveWrapPrefix(input);
                }
            }

            await invoke("create_archive", {
                input,
                output,
                key,
                formats,
                iv: ivVal,
                pathPrefix
            });
            this.log(this.t("pack_success", [output]), "success");
            this.addActivity(this.t("pack_success", [output]));
        } catch (e) {
            this._taskStartTime = null;
            this.updateProgress(0, "");
            this.log(this.t("msg_error_fmt", [String(e)]), "error");
        }
    }

    private async resolveWrapPrefix(sourcePath: string): Promise<string> {
        const mode = this.config.pack_wrap_mode;
        if (mode === "structure") {
            const detected = await invoke("detect_data_prefix", { path: sourcePath }) as string | null;
            return detected ?? "data";
        }
        if (mode === "data") {
            return "data";
        }
        // "ask" — detect and offer second dialog
        const detected = await invoke("detect_data_prefix", { path: sourcePath }) as string | null;
        let useStructure = false;
        if (detected && detected !== "data") {
            useStructure = await ask(
                this.t("dataStructurePrompt", [detected]),
                { title: this.t("dataStructureTitle"), okLabel: this.t("dataStructureYes"), cancelLabel: this.t("dataStructureNo") }
            );
        }
        const prefix = useStructure ? detected! : "data";
        // Offer to remember
        const remember = await ask(this.t("dataRememberPrompt"), { title: this.t("dataRememberTitle") });
        if (remember) {
            this.config.pack_wrap_mode = useStructure ? "structure" : "data";
            await invoke("set_config", { config: this.config });
        }
        return prefix;
    }

    private async runList(forceFullSeq = false) {
        const input = (document.getElementById("list-input") as HTMLInputElement).value;
        if (!input) return;

        const isFullSeq = forceFullSeq || (document.getElementById("list-full-sequence") as HTMLInputElement).checked;

        this.updateProgress(0, this.t("preview_loading"), true);
        let res: PackListResponse;
        try {
            if (isFullSeq) {
                // If input is a file, get parent directory; if it's already a directory, use it directly
                const isFile = input.toLowerCase().endsWith(".it") || input.toLowerCase().endsWith(".pack");
                const lastIdx = Math.max(input.lastIndexOf("/"), input.lastIndexOf("\\"));
                const dir = isFile ? (lastIdx !== -1 ? input.substring(0, lastIdx) : ".") : input;
                this.log(this.t("log_loading_sequence", [dir]));
                this._taskStartTime = Date.now();
                res = await invoke("list_sequence_contents", { folder: dir, key: null }) as PackListResponse;
                this.loadedEntries = res.entries;
                this.currentArchive = dir;
            } else {
                res = await invoke("list_pack_contents", { input, key: null }) as PackListResponse;
                this.loadedEntries = res.entries;
                this.currentArchive = input;
            }
            this.previewCache.clear();
            this._taskStartTime = null;
            this.updateProgress(100, "");
            setTimeout(() => this.updateProgress(0, ""), 600);
            this.renderTree();
            // Restore any deferred pending changes saved from a previous session
            try {
                const saved = await invoke("load_pending_changes", { archive: this.currentArchive }) as Array<{op: string; [k: string]: string}>;
                this.vfsPending = saved;
                if (saved.length > 0) {
                    this.log(this.t("log_vfs_restored", [String(saved.length)]), "info");
                }
            } catch (_e) {
                this.vfsPending = [];
            }
            this.renderVfsPending();
            document.getElementById("vfs-toolbar")?.classList.remove("hidden");
            this.log(this.t("filesLoaded", [this.loadedEntries.length.toString()]), "success");
            // Fill in the discovered salt so the user can see what key was used
            const detailSalt = res.details.salt;
            if (detailSalt && detailSalt !== "SEQUENCE" && detailSalt !== "UNENCRYPTED" && detailSalt !== "N/A") {
                const keyField = document.getElementById("extract-key") as HTMLInputElement;
                if (keyField) keyField.value = detailSalt;
            }
            const hasDataFolder = this.loadedEntries.some(e => {
                const first = e.name.split(/[\\/]/)[0].toLowerCase();
                return first === "data";
            });
            if (!hasDataFolder && this.loadedEntries.length > 0) {
                this.log(this.t("archiveNoDataWarn"), "warn");
            }
        } catch (e) {
            this._taskStartTime = null;
            this.updateProgress(0, "");
            this.log(this.t("msg_error_fmt", [String(e)]), "error");
        }
    }
    private async runDiffer() {
        const base = (document.getElementById("differ-old") as HTMLInputElement).value;
        const modified = (document.getElementById("differ-new") as HTMLInputElement).value;
        const output = (document.getElementById("differ-output") as HTMLInputElement).value;
        const key = (document.getElementById("differ-key") as HTMLInputElement).value;

        if (!base || !modified || !output || !key) {
            await message(this.t("msg_differ_missing_fields"), { title: this.t("dlg_missing_fields"), kind: "error" });
            return;
        }

        try {
            await invoke("create_patch", { base, modified, output, key });
            this.log(this.t("diff_success", [output]), "success");
        } catch (e) { this.log(this.t("msg_error_fmt", [String(e)]), "error"); }
    }

    private renderTree(filter: string = "") {
        const tree = document.getElementById("file-tree")!;
        tree.innerHTML = "";

        if (this.loadedEntries.length === 0) {
            const emptyEl = document.createElement("div");
            emptyEl.id = "file-tree-empty";
            emptyEl.className = "tree-empty-state";
            emptyEl.textContent = this.t("tree_empty");
            tree.appendChild(emptyEl);
            return;
        }

        const autoExpand = !!filter && this.config.list_auto_expand;
        const selectMode = filter ? (this.config.list_auto_select || "none") : "none";
        const firstMatch = { row: null as HTMLElement | null, entry: null as AggregateEntry | null };
        const allMatchRows: Array<{ row: HTMLElement; entry: AggregateEntry }> = [];

        const filtered = filter ? this.loadedEntries.filter(e => e.name.toLowerCase().includes(filter)) : this.loadedEntries;

        // Group by folder
        const root: any = { nodes: {}, files: [] };
        filtered.forEach(e => {
            const parts = e.name.split(/[\\/¥₩]/);
            let curr = root;
            for (let i = 0; i < parts.length - 1; i++) {
                if (!curr.nodes[parts[i]]) curr.nodes[parts[i]] = { nodes: {}, files: [] };
                curr = curr.nodes[parts[i]];
            }
            curr.files.push(e);
        });

        const buildNode = (name: string, node: any, path: string) => {
            const container = document.createElement("div");
            container.className = "tree-node";
            container.style.marginLeft = path ? "15px" : "0";

            const row = document.createElement("div");
            row.className = "tree-row folder";
            row.dataset.path = path.replace(/\/$/, "");
            row.style.display = "flex";
            row.style.alignItems = "center";

            const fcb = document.createElement("input");
            fcb.type = "checkbox";
            fcb.className = "tree-cb tree-cb-folder";
            fcb.onclick = (ev) => {
                ev.stopPropagation();
                sub.querySelectorAll<HTMLInputElement>(".tree-cb").forEach(c => { c.checked = fcb.checked; });
            };

            const icon = document.createElement("span");
            icon.className = "tree-icon";
            icon.textContent = "[+] ";
            icon.style.fontFamily = "monospace";
            icon.style.whiteSpace = "pre";

            const label = document.createElement("span");
            label.textContent = name;

            row.appendChild(fcb);
            row.appendChild(icon);
            row.appendChild(label);
            container.appendChild(row);

            const sub = document.createElement("div");
            sub.className = "tree-sub";
            sub.style.display = autoExpand ? "block" : "none";
            if (autoExpand) icon.textContent = "[-] ";

            row.onclick = () => {
                const isOpen = sub.style.display !== "none";
                sub.style.display = isOpen ? "none" : "block";
                icon.textContent = isOpen ? "[+] " : "[-] ";
            };

            for (const n in node.nodes) {
                sub.appendChild(buildNode(n, node.nodes[n], path + n + "/"));
            }

            node.files.sort((a: any, b: any) => a.name.localeCompare(b.name)).forEach((f: AggregateEntry) => {
                const frow = document.createElement("div");
                frow.className = "tree-item";
                frow.dataset.path = f.name;
                frow.style.marginLeft = "20px";
                frow.style.display = "flex";
                frow.style.alignItems = "center";
                frow.style.padding = "2px 5px";
                frow.style.cursor = "pointer";

                const cb = document.createElement("input");
                cb.type = "checkbox";
                cb.className = "tree-cb";
                cb.dataset.path = f.name;
                cb.onclick = (ev) => ev.stopPropagation();

                const flabel = document.createElement("span");
                const fname = f.name.split(/[\\/¥₩]/).pop() || f.name;
                flabel.textContent = fname;
                flabel.style.flex = "1";

                frow.appendChild(cb);
                frow.appendChild(flabel);
                
                frow.onclick = () => this.selectFile(f, frow);
                frow.oncontextmenu = (ev) => {
                    ev.preventDefault();
                    this.showContextMenu(ev, f);
                };

                if (!firstMatch.row) { firstMatch.row = frow; firstMatch.entry = f; }
                allMatchRows.push({ row: frow, entry: f });
                sub.appendChild(frow);
            });

            container.appendChild(sub);
            return container;
        };

        for (const n in root.nodes) tree.appendChild(buildNode(n, root.nodes[n], ""));
        root.files.forEach((f: AggregateEntry) => {
            const frow = document.createElement("div");
            frow.className = "tree-item";
            frow.innerHTML = `<input type="checkbox" class="tree-cb" data-path="${f.name}"> <span>${f.name}</span>`;
            frow.dataset.path = f.name;
            frow.onclick = () => this.selectFile(f, frow);
            frow.oncontextmenu = (ev) => {
                ev.preventDefault();
                this.showContextMenu(ev, f);
            };
            if (!firstMatch.row) { firstMatch.row = frow; firstMatch.entry = f; }
            allMatchRows.push({ row: frow, entry: f });
            tree.appendChild(frow);
        });

        if (selectMode === "first" && firstMatch.row && firstMatch.entry) {
            this.selectFile(firstMatch.entry, firstMatch.row);
            firstMatch.row.scrollIntoView({ block: "nearest" });
        } else if (selectMode === "all" && allMatchRows.length > 0) {
            // Highlight all matches; open preview for first
            allMatchRows.forEach(m => m.row.style.background = "color-mix(in srgb, var(--accent-cyan) 12%, transparent)");
            this.selectFile(allMatchRows[0].entry, allMatchRows[0].row);
            allMatchRows[0].row.scrollIntoView({ block: "nearest" });
        }
        this.vfsPaintSelection();
    }

    private showContextMenu(ev: MouseEvent, entry: AggregateEntry) {
        const menu = document.getElementById("custom-menu")!;
        menu.style.display = "block";
        menu.style.left = `${ev.pageX}px`;
        menu.style.top = `${ev.pageY}px`;

        const extractBtn    = document.getElementById("menu-extract")!;
        const copyNameBtn   = document.getElementById("menu-copy-name")!;
        const copyKeyBtn    = document.getElementById("menu-copy-key")!;
        const convPngBtn    = document.getElementById("menu-conv-png")!;
        const convDdsBtn    = document.getElementById("menu-conv-dds")!;
        const renameBtn     = document.getElementById("menu-rename")!;
        const deleteBtn     = document.getElementById("menu-delete")!;
        const renameDiv     = document.getElementById("menu-divider-rename")!;
        const convXmlBtn    = document.getElementById("menu-conv-xml")!;
        const convObjBtn    = document.getElementById("menu-conv-obj")!;
        // Folder/multi-select actions are enabled by the tree's own contextmenu handler
        const extractSelBtn = document.getElementById("menu-extract-sel");
        if (extractSelBtn) extractSelBtn.style.display = "none";
        extractBtn.style.display = "block";

        const closeMenu = () => {
            menu.style.display = "none";
            document.removeEventListener("click", closeMenu);
            document.removeEventListener("contextmenu", closeMenu as any);
        };
        setTimeout(() => {
            document.addEventListener("click", closeMenu);
            document.addEventListener("contextmenu", closeMenu as any);
        }, 10);

        extractBtn.onclick = async () => {
            const fileName = entry.name.split(/[\\/¥₩]/).pop() || "extracted_file";
            const dest = await save({ defaultPath: fileName });
            if (dest) {
                const skey = (entry.salt_used === "N/A" || entry.salt_used === "Search/Default") ? null : entry.salt_used;
                try {
                    await invoke("extract_file_to", {
                        archive: entry.source_archive,
                        entry: entry.name,
                        dest: dest,
                        key: skey
                    });
                    this.log(this.t("extract_success", [dest]), "success");
                } catch(e) { this.log(this.t("msg_error_fmt", [String(e)]), "error"); }
            }
        };

        copyNameBtn.onclick = () => {
            navigator.clipboard.writeText(entry.name);
            this.log(this.t("log_name_copied"));
        };
        copyKeyBtn.onclick = () => {
            navigator.clipboard.writeText(entry.salt_used);
            this.log(this.t("log_salt_copied"));
        };

        // Rename / Delete — only when archive is loaded in edit mode
        const canEdit = !!this.currentArchive;
        renameDiv.style.display  = canEdit ? "block" : "none";
        renameBtn.style.display  = canEdit ? "block" : "none";
        deleteBtn.style.display  = canEdit ? "block" : "none";

        renameBtn.onclick = () => {
            const newName = prompt(this.t("prompt_rename_path"), entry.name);
            if (!newName || newName === entry.name) return;
            this.vfsPending.push({ op: "rename", from: entry.name, to: newName });
            this.renderVfsPending();
        };
        deleteBtn.onclick = () => {
            this.vfsPending.push({ op: "delete", path: entry.name });
            this.renderVfsPending();
        };

        // Conversion options — by file extension
        const lname = entry.name.toLowerCase();
        const isDds = lname.endsWith(".dds");
        const isPng = lname.endsWith(".png");
        const isXmlCompiled = lname.endsWith(".xml.compiled");
        const isPmg = lname.endsWith(".pmg");

        convPngBtn.style.display = isDds ? "block" : "none";
        convDdsBtn.style.display = isPng ? "block" : "none";
        convXmlBtn.style.display = isXmlCompiled ? "block" : "none";
        convObjBtn.style.display = isPmg ? "block" : "none";

        convPngBtn.onclick = async () => {
            try {
                const out = await save({ defaultPath: entry.name.replace(/\.dds$/i, ".png") });
                if (out) {
                    await invoke("run_convert", { input: entry.source_archive, output: out, key: entry.salt_used, wrapData: false });
                    this.log(this.t("log_converted_png", [out]), "success");
                }
            } catch(e) { this.log(this.t("patcher_failed", [String(e)]), "error"); }
        };

        convDdsBtn.onclick = async () => {
            try {
                const out = await save({ defaultPath: entry.name.replace(/\.png$/i, ".dds") });
                if (out) {
                    await invoke("run_convert", { input: entry.source_archive, output: out, key: entry.salt_used, wrapData: false });
                    this.log(this.t("log_converted_dds", [out]), "success");
                }
            } catch(e) { this.log(this.t("patcher_failed", [String(e)]), "error"); }
        };

        convXmlBtn.onclick = async () => {
            try {
                const xml = await invoke("convert_xml_compiled", {
                    archivePath: entry.source_archive,
                    entryPath: entry.name,
                    key: entry.salt_used || null,
                }) as string;
                // Show in a save dialog
                const baseName = entry.name.replace(/\.compiled$/i, "");
                const out = await save({ defaultPath: baseName });
                if (out) {
                    await writeTextFile(out, xml);
                    this.log(this.t("log_decompiled_xml", [out]), "success");
                }
            } catch(e) { this.log(this.t("log_decompile_failed", [String(e)]), "error"); }
        };

        convObjBtn.onclick = async () => {
            try {
                const obj = await invoke("export_pmg_obj", {
                    archivePath: entry.source_archive,
                    entryPath: entry.name,
                    key: entry.salt_used || null,
                }) as string;
                const baseName = entry.name.replace(/\.pmg$/i, ".obj");
                const out = await save({ defaultPath: baseName });
                if (out) {
                    await writeTextFile(out, obj);
                    this.log(this.t("log_exported_obj", [out]), "success");
                }
            } catch(e) { this.log(this.t("log_obj_export_failed", [String(e)]), "error"); }
        };
    }

    private xmlPrettyPrint(xml: string): string {
        const tab = "  ";
        let result = "";
        let indent = 0;
        const tokens = xml.match(/<!--[\s\S]*?-->|<[^>]+>|[^<]+/g) || [];
        for (const token of tokens) {
            const t = token.trim();
            if (!t) continue;
            if (t.startsWith("<!--")) {
                result += "\n" + tab.repeat(indent) + t;
            } else if (t.startsWith("</")) {
                indent = Math.max(0, indent - 1);
                result += "\n" + tab.repeat(indent) + t;
            } else if (t.startsWith("<?") || t.startsWith("<!")) {
                result += "\n" + tab.repeat(indent) + t;
            } else if (t.startsWith("<") && t.endsWith("/>")) {
                result += "\n" + tab.repeat(indent) + t;
            } else if (t.startsWith("<")) {
                result += "\n" + tab.repeat(indent) + t;
                indent++;
            } else {
                result += "\n" + tab.repeat(indent) + t;
            }
        }
        return result.trim();
    }

    private xmlHighlight(xml: string): string {
        const pretty = this.xmlPrettyPrint(xml);
        const e = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        return pretty.replace(/<!--[\s\S]*?-->|<[^>]*>|[^<]+/g, token => {
            if (token.startsWith("<!--"))
                return `<span class="xc">${e(token)}</span>`;
            if (token.startsWith("<")) {
                // Parse into components first so the attr regex doesn't run on span-wrapped output
                const m = token.match(/^(<\/?)([\w:.-]+)([\s\S]*?)(\/?>)$/);
                if (!m) return e(token);
                const [, open, name, attrs, close] = m;
                const attrHtml = attrs.replace(/\s+([\w:.-]+)(?:="([^"]*)")?/g, (_m, attr, val) =>
                    val !== undefined
                        ? ` <span class="xa">${e(attr)}</span><span class="xb">="</span><span class="xv">${e(val)}</span><span class="xb">"</span>`
                        : ` <span class="xa">${e(attr)}</span>`
                );
                return `<span class="xb">${e(open)}</span><span class="xt">${e(name)}</span>${attrHtml}<span class="xb">${e(close)}</span>`;
            }
            return e(token);
        });
    }

    // --- MML viewer & player ---

    private mmlHighlight(text: string): string {
        const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        // Replace special chars before span injection so escaping works on raw text
        const safe = esc(text);
        // Match MML tokens in order: commands (T/O/L/V + digits), notes (A-G + optional sharp/len/dot),
        // rests (R + optional len/dot), octave shifts (<>), channel separator (,)
        const highlighted = safe.replace(
            /([TOLV]\d+|[A-G][+#\-]?\d*\.?|R\d*\.?|&lt;|&gt;|,)/gi,
            (m) => {
                const ch = m[0].toUpperCase();
                if ("TOLV".includes(ch))
                    return `<span style="color:var(--accent-cyan,#4dd9e4)">${m}</span>`;
                if ("ABCDEFG".includes(ch))
                    return `<span style="color:#ffd700">${m}</span>`;
                if (ch === "R")
                    return `<span style="color:var(--text-muted,#888)">${m}</span>`;
                if (m === "," || m === "&lt;" || m === "&gt;")
                    return `<span style="color:var(--accent-cyan,#4dd9e4)">${m}</span>`;
                return m;
            }
        );
        return `<pre style="margin:0;padding:8px 10px;flex:1;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px;line-height:1.7;box-sizing:border-box">${highlighted}</pre>`;
    }

    private mmlPlayerHtml(): string {
        return `<div id="mml-player" style="flex-shrink:0;padding:5px 8px;border-top:1px solid var(--border,#333);display:flex;gap:8px;align-items:center">
            <button id="mml-play-btn" style="padding:3px 13px;background:var(--accent-cyan,#4dd9e4);color:#000;border:none;border-radius:3px;cursor:pointer;font-size:12px;font-weight:600">&#9654; ${this.t("mml_play")}</button>
            <button id="mml-stop-btn" style="padding:3px 13px;background:var(--bg2,#1e2028);color:var(--text,#ccc);border:1px solid var(--border,#333);border-radius:3px;cursor:pointer;font-size:12px" disabled>&#9632; ${this.t("patcher_stop")}</button>
            <span id="mml-status" style="font-size:11px;color:var(--text-muted,#888)"></span>
        </div>`;
    }

    private initMmlPlayer(mml: string): void {
        const playBtn  = document.getElementById("mml-play-btn")  as HTMLButtonElement | null;
        const stopBtn  = document.getElementById("mml-stop-btn")  as HTMLButtonElement | null;
        const statusEl = document.getElementById("mml-status")    as HTMLElement | null;
        if (!playBtn || !stopBtn) return;

        const doStop = () => {
            this._mmlStopFlag = true;
            if (this._mmlAudioCtx) {
                this._mmlAudioCtx.close().catch(() => {});
                this._mmlAudioCtx = null;
            }
            playBtn.disabled = false;
            stopBtn.disabled = true;
            if (statusEl) statusEl.textContent = this.t("mml_stopped");
        };

        stopBtn.onclick = doStop;

        playBtn.onclick = () => {
            doStop();
            this._mmlStopFlag = false;
            playBtn.disabled = true;
            stopBtn.disabled = false;
            if (statusEl) statusEl.textContent = this.t("mml_playing");

            // Use only the first channel (before the first comma)
            const channel = mml.split(",")[0].replace(/\s+/g, "").toUpperCase();
            const events = this.parseMmlChannel(channel);
            if (events.length === 0) {
                if (statusEl) statusEl.textContent = this.t("mml_no_notes");
                playBtn.disabled = false;
                stopBtn.disabled = true;
                return;
            }

            const ctx = new AudioContext();
            this._mmlAudioCtx = ctx;
            const master = ctx.createGain();
            master.gain.value = 0.4;
            master.connect(ctx.destination);

            let t = ctx.currentTime + 0.05;
            for (const ev of events) {
                if (ev.freq > 0) {
                    const osc  = ctx.createOscillator();
                    const gain = ctx.createGain();
                    osc.connect(gain);
                    gain.connect(master);
                    osc.type = "sine";
                    osc.frequency.value = ev.freq;
                    const vol = ev.volume * 0.9 + 0.1;
                    gain.gain.setValueAtTime(vol, t);
                    gain.gain.exponentialRampToValueAtTime(0.0001, t + ev.dur * 0.88);
                    osc.start(t);
                    osc.stop(t + ev.dur);
                }
                t += ev.dur;
            }

            const totalMs = (t - ctx.currentTime) * 1000 + 150;
            setTimeout(() => {
                if (!this._mmlStopFlag && statusEl) statusEl.textContent = this.t("status_done");
                if (!this._mmlStopFlag) {
                    playBtn.disabled = false;
                    stopBtn.disabled = true;
                    this._mmlAudioCtx = null;
                }
            }, totalMs);
        };
    }

    private parseMmlChannel(mml: string): Array<{ freq: number; dur: number; volume: number }> {
        // semitone offset from C for each note letter
        const semi: Record<string, number> = { C:0, D:2, E:4, F:5, G:7, A:9, B:11 };
        let tempo  = 120;
        let octave = 4;
        let defLen = 4;     // quarter note
        let volume = 8;     // 0-15

        const events: Array<{ freq: number; dur: number; volume: number }> = [];
        let i = 0;

        const readNum = (): number | null => {
            let s = "";
            while (i < mml.length && mml[i] >= "0" && mml[i] <= "9") s += mml[i++];
            return s ? parseInt(s, 10) : null;
        };

        const noteSec = (len: number, dot: boolean) => {
            const base = (60 / tempo) * 4 / len;
            return dot ? base * 1.5 : base;
        };

        while (i < mml.length) {
            const ch = mml[i];

            if (ch === "T") {
                i++; const n = readNum(); if (n !== null && n > 0) tempo = n;
            } else if (ch === "O") {
                i++; const n = readNum(); if (n !== null) octave = Math.min(8, Math.max(1, n));
            } else if (ch === "L") {
                i++; const n = readNum(); if (n !== null && n > 0) defLen = n;
            } else if (ch === "V") {
                i++; const n = readNum(); if (n !== null) volume = Math.min(15, Math.max(0, n));
            } else if (ch === "<") {
                octave = Math.max(1, octave - 1); i++;
            } else if (ch === ">") {
                octave = Math.min(8, octave + 1); i++;
            } else if (ch in semi) {
                i++;
                let s = semi[ch];
                if (i < mml.length && (mml[i] === "+" || mml[i] === "#")) { s++; i++; }
                else if (i < mml.length && mml[i] === "-") { s--; i++; }
                const len = readNum() ?? defLen;
                const dot = i < mml.length && mml[i] === "."; if (dot) i++;
                const freq = 261.6256 * Math.pow(2, (s + (octave - 4) * 12) / 12);
                events.push({ freq, dur: noteSec(len, dot), volume: volume / 15 });
            } else if (ch === "R") {
                i++;
                const len = readNum() ?? defLen;
                const dot = i < mml.length && mml[i] === "."; if (dot) i++;
                events.push({ freq: 0, dur: noteSec(len, dot), volume: 0 });
            } else {
                i++; // skip unknown chars (&, ;, N, etc.)
            }
        }

        return events;
    }

    private async fetchPreview(entry: AggregateEntry): Promise<PreviewData> {
        const key = this.previewKey(entry);
        const cached = this.previewCache.get(key);
        if (cached) return cached;
        const entryKey = (entry.salt_used === "N/A" || entry.salt_used === "Search/Default" || entry.salt_used === "UNENCRYPTED") ? null : entry.salt_used;
        const entriesKey = (entry.entries_salt_used === "N/A" || entry.entries_salt_used === "Search/Default" || entry.entries_salt_used === "UNENCRYPTED") ? null : entry.entries_salt_used;
        const prev = await invoke("get_preview_ext", {
            archivePath: entry.source_archive,
            entryName: entry.name,
            key: entryKey,
            entriesKey,
            iv0: entry.iv0,
            hOff: entry.h_off,
            mode: entry.mode
        }) as PreviewData;
        this.previewCache.set(key, prev);
        return prev;
    }

    private async entryBytes(e: AggregateEntry): Promise<Uint8Array> {
        const clean = (k: string) => (k === "N/A" || k === "Search/Default" || k === "UNENCRYPTED") ? null : k;
        const buf = await invoke<ArrayBuffer>("get_entry_bytes", {
            archivePath: e.source_archive,
            entryName: e.name,
            key: clean(e.salt_used),
            entriesKey: clean(e.entries_salt_used),
            iv0: e.iv0,
            hOff: e.h_off,
            mode: e.mode,
        });
        return new Uint8Array(buf);
    }

    /** Full bytes of the file a preview was built from: an archive entry or a loose file. */
    private async sourceBytes(src: PreviewSource): Promise<Uint8Array> {
        if (src.entry) return this.entryBytes(src.entry);
        if (src.loosePath) return new Uint8Array(await invoke<ArrayBuffer>("read_loose_bytes", { path: src.loosePath }));
        throw new Error("nothing selected");
    }

    /** Finds `<name>.dds` in the loaded archives, or near the opened loose model. */
    private async textureBytes(name: string, src: PreviewSource): Promise<Uint8Array | null> {
        const want = `${name.toLowerCase()}.dds`;
        if (src.entry) {
            const index = this.textureIndexFor();
            const hits = index.get(want);
            if (!hits?.length) return null;
            // Same archive as the model first, otherwise the newest copy (archives load oldest first).
            const hit = hits.find(e => e.source_archive === src.entry!.source_archive) ?? hits[hits.length - 1];
            return this.entryBytes(hit);
        }
        if (src.loosePath) {
            const path = await invoke<string | null>("find_loose_texture", { modelPath: src.loosePath, texture: name });
            return path ? new Uint8Array(await invoke<ArrayBuffer>("read_loose_bytes", { path })) : null;
        }
        return null;
    }

    /** Lower-case `.dds` file name → entries, rebuilt when the loaded entry list changes. */
    private textureIndexFor(): Map<string, AggregateEntry[]> {
        if (this.textureIndex && this.textureIndexSource === this.loadedEntries) return this.textureIndex;
        const index = new Map<string, AggregateEntry[]>();
        for (const e of this.loadedEntries) {
            const base = e.name.toLowerCase().split(/[\\/¥₩]/).pop() || "";
            if (!base.endsWith(".dds")) continue;
            const list = index.get(base);
            if (list) list.push(e); else index.set(base, [e]);
        }
        this.textureIndex = index;
        this.textureIndexSource = this.loadedEntries;
        return index;
    }

    /** Mounts the ported website viewer for pmg/gm/eff; false (after logging) when it can't. */
    private async mount3d(gen: number, kind: "pmg" | "gm" | "eff", prev: PreviewData, src: PreviewSource): Promise<boolean> {
        if (!isTauri()) return false; // the WebUI has no raw-bytes endpoint; use the Rust-parsed preview
        const cont = document.getElementById("three-viewport")!;
        const infoEl = document.getElementById("pmg-info")!;
        try {
            const [bytes, panel, { parseCssColor }] = await Promise.all([
                this.sourceBytes(src),
                import("./preview3d/panel"),
                import("./pmgLoader"),
            ]);
            if (gen !== this.previewGen) return false;
            // The preview tab must be visible before the viewer measures its container.
            document.getElementById("preview-3d")!.classList.add("active");
            infoEl.style.color = "";
            const css = getComputedStyle(document.documentElement);
            const hex = (v: string, d: number) => parseCssColor(css.getPropertyValue(v).trim()) ?? d;
            let mounted: Mounted3d;
            const tr = (key: string, args: string[] = []) => this.t(key, args);
            if (kind === "pmg") {
                mounted = panel.mountPmg({
                    container: cont,
                    t: tr,
                    overlay: document.getElementById("preview-3d")!,
                    name: prev.name.split(/[\\/]/).pop() || prev.name,
                    bytes,
                    accent: hex("--accent-cyan", 0x00d2ff),
                    background: hex("--bg-surface", 0x0d0d1a),
                    textureBytes: n => this.textureBytes(n, src),
                    textureScope: src.entry?.source_archive ?? src.loosePath ?? "",
                    assets: src.entry ? this.assetHost() : undefined,
                    entry: src.entry,
                    save: (name, data) => this.save3dExport(name, data),
                    status: t => { if (gen === this.previewGen) infoEl.textContent = t; },
                });
            } else if (kind === "gm") {
                mounted = panel.mountGm({ container: cont, bytes, t: tr });
            } else {
                const xml = bytes[0] === 0xff && bytes[1] === 0xfe
                    ? new TextDecoder("utf-16le").decode(bytes.subarray(2))
                    : new TextDecoder("utf-8").decode(bytes);
                mounted = panel.mountEffect({ container: cont, xml, t: tr });
            }
            if (gen !== this.previewGen) { mounted.dispose(); return false; }
            this.viewer3d = mounted;
            (window as any).__threeResizeFn = () => this.viewer3d?.resize();
            if (kind !== "pmg") infoEl.textContent = mounted.summary;
            this.log(`[3D] ${prev.name}  ·  ${mounted.summary}`);
            return true;
        } catch (err) {
            if (gen === this.previewGen) document.getElementById("preview-3d")!.classList.remove("active");
            this.log(`[3D] ${prev.name}: ${err}`, "warn");
            return false;
        }
    }

    /** Archive access for the item lookup and region previews (preview3d/worldData). */
    private assetHost(): AssetHost {
        return {
            entries: () => this.loadedEntries,
            bytes: e => this.entryBytes(e as AggregateEntry),
            openEntry: e => { void this.previewAssetEntry(e as AggregateEntry); },
            textureBytes: (name, near) => this.textureBytes(name, near ? { entry: near as AggregateEntry } : {}),
            log: (msg, level) => this.log(msg, level),
            language: () => this.config.locale || "en",
        };
    }

    /** Previews an entry opened from the item search or a region view. */
    private async previewAssetEntry(e: AggregateEntry): Promise<void> {
        this.selectedEntry = e;
        const req = ++this.selectGen;
        try {
            const prev = await this.fetchPreview(e);
            if (req !== this.selectGen) return;
            await this.applyPreviewToPanel(prev, { entry: e });
        } catch (err) {
            if (req === this.selectGen) this.log(this.t("preview_error", [String(err)]), "error");
        }
    }

    /** Map / world view for a .rgn or .area archive entry; false when it can't be shown. */
    private async mountRegionPreview(gen: number, prev: PreviewData, src: PreviewSource): Promise<boolean> {
        if (!isTauri() || !src.entry) return false;
        const cont = document.getElementById("three-viewport")!;
        const infoEl = document.getElementById("pmg-info")!;
        const overlay = document.getElementById("preview-3d")!;
        try {
            const [{ mountRegion }, { parseCssColor }] = await Promise.all([import("./preview3d/worldPanel"), import("./pmgLoader")]);
            if (gen !== this.previewGen) return false;
            overlay.classList.add("active");
            infoEl.style.color = "";
            const css = getComputedStyle(document.documentElement);
            const hex = (v: string, d: number) => parseCssColor(css.getPropertyValue(v).trim()) ?? d;
            const mounted = await mountRegion({
                container: cont,
                overlay,
                t: (key, args = []) => this.t(key, args),
                assets: this.assetHost(),
                entry: src.entry,
                accent: hex("--accent-cyan", 0x00d2ff),
                background: hex("--bg-surface", 0x0d0d1a),
                status: text => { if (gen === this.previewGen) infoEl.textContent = text; },
                current: () => gen === this.previewGen,
            });
            if (!mounted) return false;
            if (gen !== this.previewGen) { mounted.dispose(); return false; }
            this.viewer3d = mounted;
            (window as any).__threeResizeFn = () => this.viewer3d?.resize();
            this.log(`[Map] ${prev.name}  ·  ${mounted.summary}`);
            return true;
        } catch (err) {
            if (gen === this.previewGen) overlay.classList.remove("active");
            this.log(`[Map] ${prev.name}: ${err}`, "warn");
            return false;
        }
    }

    private async save3dExport(defaultName: string, data: Uint8Array | string): Promise<void> {
        try {
            const out = await save({ defaultPath: defaultName });
            if (!out) return;
            if (typeof data === "string") await writeTextFile(out, data); else await writeFile(out, data);
            this.log(`[3D] ${this.t("log_3d_exported", [out])}`, "success");
        } catch (e) {
            this.log(`[3D] ${this.t("log_3d_export_failed", [String(e)])}`, "error");
        }
    }

    private async applyPreviewToPanel(prev: PreviewData, src: PreviewSource = {}): Promise<void> {
        const visual = document.getElementById("preview-visual")!;
        const hex = document.getElementById("preview-hex")!;
        const details = document.getElementById("preview-details")!;
        const audio = document.getElementById("preview-audio")!;
        const threed = document.getElementById("preview-3d")!;

        if (this.pmgViewer) { this.pmgViewer.dispose(); this.pmgViewer = undefined; (window as any).__threeResizeFn = undefined; }
        if (this.viewer3d) { this.viewer3d.dispose(); this.viewer3d = undefined; (window as any).__threeResizeFn = undefined; }
        const gen = ++this.previewGen;
        this._mmlStopFlag = true;
        if (this._mmlAudioCtx) { this._mmlAudioCtx.close().catch(() => {}); this._mmlAudioCtx = null; }
        [visual, hex, details, audio, threed].forEach(el => el.classList.remove("active"));

        let activeContainer = "preview-visual";
        const ext = prev.name.toLowerCase().split('.').pop() || "";

        if (prev.file_type === "error") {
            visual.textContent = prev.content_text || this.t("preview_image_decode_failed");
            visual.className = "preview-tab-content active";
        } else if (prev.file_type === "image" && prev.content_image) {
            visual.innerHTML = `<img src="data:image/png;base64,${prev.content_image}" style="width:100%; height:100%; object-fit:contain; display:block;" />`;
            visual.className = "preview-tab-content active";
        } else if (prev.file_type === "audio") {
            audio.classList.add("active");
            activeContainer = "preview-audio";
            visual.textContent = this.t("preview_no_visual");
            visual.className = "preview-tab-content";
            const fnameEl = document.getElementById("audio-filename")!;
            const audioElem = document.getElementById("audio-elem") as HTMLAudioElement;
            const msgEl = document.getElementById("audio-error-msg")!;
            if (this._audioBlobUrl) { URL.revokeObjectURL(this._audioBlobUrl); this._audioBlobUrl = ""; }
            if (prev.raw_bytes.length === 0 && prev.content_text) {
                fnameEl.textContent = prev.name;
                audioElem.src = "";
                audioElem.removeAttribute("src");
                if (msgEl) msgEl.textContent = "";
                this.log(`[Audio] ${prev.name}: ${prev.content_text}`, "warn");
            } else {
                const mimeMap: Record<string, string> = { wav: "audio/wav", mp3: "audio/mpeg", ogg: "audio/ogg", nxa: "audio/ogg" };
                const mimeType = mimeMap[ext] || "audio/wav";
                const blob = new Blob([new Uint8Array(prev.raw_bytes)], { type: mimeType });
                this._audioBlobUrl = URL.createObjectURL(blob);
                audioElem.src = this._audioBlobUrl;
                fnameEl.textContent = prev.truncated
                    ? `${prev.name}  [${this.t("preview_audio_truncated", [(prev.full_preview_size / 1048576).toFixed(1)])}]`
                    : prev.name;
                if (msgEl) msgEl.textContent = "";
                if (this.config.audio_autoplay) audioElem.play().catch(() => {});
            }
        } else if (ext === "pmg" && await this.mount3d(gen, "pmg", prev, src)) {
            threed.classList.add("active");
            activeContainer = "preview-3d";
            visual.textContent = this.t("preview_no_visual");
            visual.className = "preview-tab-content";
        } else if (gen !== this.previewGen) {
            return;
        } else if ((ext === "gm" || ext === "eff") && await this.mount3d(gen, ext, prev, src)) {
            threed.classList.add("active");
            activeContainer = "preview-3d";
            if (ext === "gm") {
                visual.textContent = this.t("preview_no_visual");
                visual.className = "preview-tab-content";
            } else {
                visual.className = "preview-tab-content xml-view";
                visual.innerHTML = this.xmlHighlight(prev.content_text || "");
            }
        } else if (gen !== this.previewGen) {
            return;
        } else if (ext === "pmg") {
            // Website-style parse failed; fall back to the Rust-parsed single mesh.
            threed.classList.add("active");
            activeContainer = "preview-3d";
            const cont = document.getElementById("three-viewport")!;
            const infoEl = document.getElementById("pmg-info")!;
            const { createPMGViewer } = await import("./pmgLoader");
            this.pmgViewer = createPMGViewer(cont, prev.pmg_geometry);
            (window as any).__threeResizeFn = () => this.pmgViewer?.resize();
            if (prev.pmg_geometry) {
                const g = prev.pmg_geometry;
                this.log(`[PMG] ${g.mesh_name || prev.name}  ·  ${this.t("preview_pmg_counts", [String(g.vertex_count), String(g.face_count)])}`);
                infoEl.textContent = "";
            } else {
                this.log(`[PMG] ${prev.name}  ·  ${this.t("preview_pmg_no_geometry")}`);
                infoEl.textContent = this.t("preview_pmg_no_geometry");
                infoEl.style.color = "var(--text-muted)";
            }
            visual.textContent = this.t("preview_no_visual");
            visual.className = "preview-tab-content";
        } else if ((ext === "rgn" || ext === "area") && await this.mountRegionPreview(gen, prev, src)) {
            threed.classList.add("active");
            activeContainer = "preview-3d";
            visual.textContent = this.t("preview_no_visual");
            visual.className = "preview-tab-content";
        } else if (gen !== this.previewGen) {
            return;
        } else if (prev.file_type === "rgn" || ext === "rgn") {
            // .rgn terrain heightmap canvas renderer
            visual.className = "preview-tab-content active";
            visual.innerHTML = `<div style="padding:12px;box-sizing:border-box;height:100%;overflow:auto;display:flex;flex-direction:column;align-items:center;gap:8px">
                <canvas id="rgn-canvas" style="border:1px solid var(--border,#333);image-rendering:pixelated;max-width:100%"></canvas>
                <div id="rgn-info" style="font-size:11px;color:var(--text-muted,#888);font-family:monospace;text-align:center;padding:0 8px"></div>
            </div>`;
            const rgnCanvas = document.getElementById("rgn-canvas") as HTMLCanvasElement;
            const rgnInfo   = document.getElementById("rgn-info")!;

            if (prev.rgn_data) {
                const { width, height, heights, version, region_id, area_count } = prev.rgn_data;

                // Scale down to max 512×512 for display
                const MAX_DIM = 512;
                const scale = Math.max(1, Math.ceil(Math.max(width, height) / MAX_DIM));
                const dw = Math.ceil(width / scale);
                const dh = Math.ceil(height / scale);

                rgnCanvas.width  = dw;
                rgnCanvas.height = dh;

                const ctx = rgnCanvas.getContext("2d")!;
                const img = ctx.createImageData(dw, dh);
                const d   = img.data;

                for (let py = 0; py < dh; py++) {
                    for (let px = 0; px < dw; px++) {
                        // Sample from source at nearest pixel
                        const sx = Math.min(Math.round(px * scale), width - 1);
                        const sy = Math.min(Math.round(py * scale), height - 1);
                        const v  = Math.round(heights[sy * width + sx] * 255);
                        const i  = (py * dw + px) * 4;
                        d[i] = v; d[i+1] = v; d[i+2] = v; d[i+3] = 255;
                    }
                }
                ctx.putImageData(img, 0, 0);

                const rgnSummary = this.t("preview_rgn_summary", [String(version), String(region_id), String(area_count), `${width}×${height}`]);
                this.log(`[RGN] ${prev.name}  ·  ${rgnSummary}`);
                rgnInfo.textContent = `${rgnSummary} ${this.t("preview_rgn_displayed", [`${dw}×${dh}`])}`;
            } else {
                // Parse failed or file is too small – show a placeholder
                rgnCanvas.width  = 256;
                rgnCanvas.height = 256;
                const ctx = rgnCanvas.getContext("2d")!;
                ctx.fillStyle = "#0f172a";
                ctx.fillRect(0, 0, 256, 256);
                ctx.fillStyle = "#555";
                ctx.font = "13px monospace";
                ctx.textAlign = "center";
                ctx.fillText(prev.content_text || this.t("preview_rgn_parse_failed"), 128, 128);
                rgnInfo.textContent = prev.content_text || this.t("preview_rgn_parse_failed_hint");
                this.log(`[RGN] ${prev.name}: ${prev.content_text || this.t("preview_rgn_parse_failed")}`, "warn");
            }
        } else if (ext === "ttf" || ext === "otf" || ext === "woff" || ext === "woff2") {
            const fontFamily = `PreviewFont_${Date.now()}`;
            const buffer = new Uint8Array(prev.raw_bytes).buffer;
            try {
                const fontFace = new FontFace(fontFamily, buffer);
                await fontFace.load();
                (document as any).fonts.add(fontFace);
                const sample = this.t("preview_font_sample");
                visual.className = "preview-tab-content active";
                visual.innerHTML = `<div style="padding:16px;overflow:auto;height:100%;box-sizing:border-box">
                    <div style="font-size:11px;opacity:0.5;margin-bottom:12px;font-family:monospace">${prev.name} &mdash; ${(prev.size/1024).toFixed(1)} KB</div>
                    <div style="font-size:30px;line-height:1.4;font-family:'${fontFamily}',sans-serif;white-space:pre-wrap;margin-bottom:20px">${sample.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/\n/g,"<br>")}</div>
                    <div style="margin-top:8px">${[8,12,16,20,24,32,48].map(sz => `<div style="margin-bottom:6px;font-size:${sz}px;font-family:'${fontFamily}',sans-serif">${sz}px &mdash; ${sample.split("\n")[0].replace(/&/g,"&amp;").replace(/</g,"&lt;")} 0123456789</div>`).join("")}</div>
                </div>`;
            } catch (_) {
                visual.textContent = this.t("preview_no_visual");
                visual.className = "preview-tab-content";
                hex.classList.add("active");
                activeContainer = "preview-hex";
            }
        } else if (ext === "area") {
            visual.className = "preview-tab-content active";
            visual.innerHTML = `<div style="padding:12px;box-sizing:border-box;height:100%;overflow:auto;display:flex;flex-direction:column;align-items:center;gap:8px">
                <canvas id="area-canvas" width="512" height="512" style="border:1px solid var(--border,#333);image-rendering:pixelated;max-width:100%;background:#0f172a"></canvas>
                <div id="area-info" style="font-size:11px;color:var(--text-muted,#888);font-family:monospace;text-align:center;padding:0 8px"></div>
            </div>`;
            const areaCanvas = document.getElementById("area-canvas") as HTMLCanvasElement;
            const areaInfo   = document.getElementById("area-info")!;
            const ctx = areaCanvas.getContext("2d")!;
            // Background
            ctx.fillStyle = "#0f172a";
            ctx.fillRect(0, 0, 512, 512);
            if (prev.raw_bytes.length === 0) {
                ctx.fillStyle = "#555";
                ctx.font = "13px monospace";
                ctx.textAlign = "center";
                ctx.fillText(this.t("preview_area_empty"), 256, 256);
                areaInfo.textContent = this.t("unit_bytes", ["0"]);
            } else {
                type AreaProp = { id: number; x: number; y: number; z: number };
                type AreaResult = { props: AreaProp[]; format: string };
                let areaResult: AreaResult | null = null;
                try {
                    areaResult = await invoke("parse_area", { bytes: prev.raw_bytes }) as AreaResult;
                } catch (_) { /* parse_area returns Err → caught below */ }

                if (areaResult && areaResult.props.length > 0) {
                    const props = areaResult.props;
                    // Find bounding box using X and Z (horizontal axes in Mabinogi)
                    let minX = Infinity, maxX = -Infinity, minZ = Infinity, maxZ = -Infinity;
                    for (const p of props) {
                        if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
                        if (p.z < minZ) minZ = p.z; if (p.z > maxZ) maxZ = p.z;
                    }
                    const pad   = 20;
                    const W     = 512 - pad * 2;
                    const H     = 512 - pad * 2;
                    const rangeX = maxX - minX || 1;
                    const rangeZ = maxZ - minZ || 1;
                    // Prop color by ID century (IDs in same hundred share a color — rough type grouping)
                    const PALETTE = ["#4ade80","#60a5fa","#fbbf24","#f87171","#c084fc","#34d399","#fb923c","#94a3b8"];
                    for (const p of props) {
                        const cx = Math.round(pad + ((p.x - minX) / rangeX) * W);
                        const cy = Math.round(pad + ((p.z - minZ) / rangeZ) * H);
                        ctx.fillStyle = PALETTE[Math.floor(p.id / 100) % PALETTE.length];
                        ctx.fillRect(cx - 1, cy - 1, 2, 2);
                    }
                    // Axis labels
                    ctx.fillStyle = "rgba(255,255,255,0.25)";
                    ctx.font = "10px monospace";
                    ctx.textAlign = "left";
                    ctx.fillText(`X ${minX.toFixed(0)}`, 2, 510);
                    ctx.textAlign = "right";
                    ctx.fillText(`${maxX.toFixed(0)}`, 510, 510);
                    ctx.textAlign = "left";
                    ctx.fillText(`Z ${minZ.toFixed(0)}`, 2, 12);
                    ctx.textAlign = "right";
                    ctx.fillText(`${maxZ.toFixed(0)}`, 510, 12);
                    areaInfo.textContent = `${this.t("preview_area_props", [props.length.toLocaleString()])}  ·  X ${minX.toFixed(0)}–${maxX.toFixed(0)}  Z ${minZ.toFixed(0)}–${maxZ.toFixed(0)}  ·  ${this.t("preview_area_format", [areaResult.format])}`;
                    if (prev.truncated) {
                        areaInfo.textContent += `  ·  (${this.t("preview_first_kb_of", [(prev.raw_bytes.length/1024).toFixed(0), (prev.full_preview_size/1024).toFixed(0)])})`;
                    }
                } else {
                    // Fallback: unknown format — show message + hex dump of first 32 bytes
                    ctx.fillStyle = "#4a5568";
                    ctx.font = "14px monospace";
                    ctx.textAlign = "center";
                    ctx.fillText(this.t("preview_area_unknown"), 256, 230);
                    const hexPeek = Array.from(prev.raw_bytes.slice(0, 32))
                        .map((b: number) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
                    ctx.fillStyle = "#718096";
                    ctx.font = "10px monospace";
                    const words = hexPeek.match(/.{1,24}/g) || [];
                    words.forEach((w, i) => ctx.fillText(w, 256, 258 + i * 14));
                    areaInfo.textContent = `${this.t("unit_bytes", [prev.raw_bytes.length.toLocaleString()])}  ·  ${this.t("preview_area_no_props")}`;
                }
            }
        } else if (prev.file_type === "set") {
            visual.className = "preview-tab-content active";
            let headerHtml = "";
            try {
                const h = await invoke<{ magic: string; version: number; bone_count: number; frame_count: number; duration_ms: number; is_xml: boolean }>(
                    "parse_set_header", { bytes: prev.raw_bytes }
                );
                if (h.is_xml) {
                    // XML-format .set: decode bytes as text and show with highlighting
                    const xmlText = new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(prev.raw_bytes));
                    visual.className = "preview-tab-content active xml-view";
                    visual.innerHTML = this.xmlHighlight(xmlText);
                    headerHtml = ""; // handled above
                } else {
                    headerHtml = `
                        <p style="margin:0 0 10px;color:var(--accent-cyan,#00d4ff);font-weight:600">
                            ${this.t("preview_set_summary", [String(h.frame_count), String(h.bone_count), String(h.duration_ms)])}
                        </p>
                        <table class="details-table" style="margin-bottom:18px"><tbody>
                            <tr><th>${this.t("preview_set_magic")}</th><td class="mono">${h.magic}</td></tr>
                            <tr><th>${this.t("preview_set_version")}</th><td>${h.version}</td></tr>
                            <tr><th>${this.t("preview_set_bone_count")}</th><td>${h.bone_count}</td></tr>
                            <tr><th>${this.t("preview_set_frame_count")}</th><td>${h.frame_count}</td></tr>
                            <tr><th>${this.t("preview_set_duration")}</th><td>${h.duration_ms} ms</td></tr>
                        </tbody></table>`;
                }
            } catch (_) {
                headerHtml = `<p style="color:var(--text-muted,#718096);margin:0 0 12px">${this.t("preview_set_unknown")}</p>`;
            }
            if (headerHtml) {
                // Binary .set: show header table + hex dump of first 128 bytes
                const hexBytes = prev.raw_bytes.slice(0, 128);
                const hexStr = hexBytes.map((b: number) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
                visual.innerHTML = `<div style="padding:16px;font-family:monospace;overflow:auto;height:100%;box-sizing:border-box">
                    <div style="font-size:11px;opacity:0.5;margin-bottom:14px">${prev.name} &mdash; ${this.t("unit_bytes", [prev.full_preview_size.toLocaleString()])}</div>
                    ${headerHtml}
                    <div style="font-size:10px;opacity:0.5;margin-bottom:6px">${this.t("preview_first_bytes_hex", [String(Math.min(128, prev.raw_bytes.length))])}</div>
                    <pre style="white-space:pre-wrap;font-size:11px;line-height:1.7;word-break:break-all;opacity:0.75;margin:0">${hexStr}</pre>
                </div>`;
            }
        } else if (ext === "anievent") {
            visual.className = "preview-tab-content active";
            visual.innerHTML = `<div style="padding:12px;box-sizing:border-box;height:100%;overflow:auto;display:flex;flex-direction:column;gap:8px">
                <canvas id="anievent-canvas" width="512" height="80" style="border:1px solid var(--border,#333);max-width:100%;background:#0f172a;display:block"></canvas>
                <div id="anievent-legend" style="font-size:11px;color:var(--text-muted,#888);font-family:monospace;line-height:1.6"></div>
                <div id="anievent-info" style="font-size:11px;color:var(--text-muted,#888);font-family:monospace"></div>
                <div id="anievent-table-wrap" style="overflow:auto;flex:1;min-height:0"></div>
            </div>`;
            const aniCanvas = document.getElementById("anievent-canvas") as HTMLCanvasElement;
            const aniLegend = document.getElementById("anievent-legend")!;
            const aniInfo   = document.getElementById("anievent-info")!;
            const aniTable  = document.getElementById("anievent-table-wrap")!;
            const actx = aniCanvas.getContext("2d")!;
            actx.fillStyle = "#0f172a";
            actx.fillRect(0, 0, 512, 80);
            if (prev.raw_bytes.length === 0) {
                actx.fillStyle = "#4a5568";
                actx.font = "13px monospace";
                actx.textAlign = "center";
                actx.fillText(this.t("preview_anievent_empty"), 256, 45);
                aniInfo.textContent = this.t("unit_bytes", ["0"]);
            } else {
                type AniEvt = { frame: number; event_type: string; anim_name: string; params: string };
                type AnieventResult = { set_name: string; animation_count: number; event_count: number; events: AniEvt[] };
                let aniResult: AnieventResult | null = null;
                try {
                    aniResult = await invoke("parse_anievent", { bytes: prev.raw_bytes }) as AnieventResult;
                } catch (_) { /* parse_anievent returned Err */ }

                if (aniResult && aniResult.events.length > 0) {
                    const evts = aniResult.events;
                    const maxFrame = evts.reduce((m, e) => Math.max(m, e.frame), 0) || 1;

                    const TYPE_COLORS: Record<string, string> = {
                        sound: "#60a5fa", widesound: "#3b82f6",
                        effect: "#a78bfa", effectoff: "#7c3aed", skilleffect: "#c084fc",
                        hit: "#f87171", blowaway: "#ef4444",
                        face: "#4ade80", hand: "#86efac",
                        footstep: "#fbbf24", lookat: "#fb923c",
                        jump: "#f9a8d4", vibrate: "#e2e8f0",
                        quake: "#94a3b8", myquake: "#94a3b8",
                        equipment: "#34d399", linkframework: "#2dd4bf",
                        generic: "#94a3b8", say: "#fdba74",
                        changedir: "#a3e635", changealpha: "#67e8f9",
                    };
                    const getAniColor = (t: string) => TYPE_COLORS[t.toLowerCase()] ?? "#94a3b8";

                    // Draw timeline axis
                    const PAD = 16, CW = 512, CH = 80;
                    const W = CW - PAD * 2;
                    const Y_TOP = 14, Y_BOT = CH - 14, Y_MID = (Y_TOP + Y_BOT) / 2;
                    actx.strokeStyle = "#334155";
                    actx.lineWidth = 1;
                    actx.beginPath();
                    actx.moveTo(PAD, Y_MID);
                    actx.lineTo(PAD + W, Y_MID);
                    actx.stroke();

                    // Draw event ticks
                    for (const ev of evts) {
                        const x = Math.round(PAD + (ev.frame / maxFrame) * W);
                        actx.strokeStyle = getAniColor(ev.event_type);
                        actx.lineWidth = 1.5;
                        actx.beginPath();
                        actx.moveTo(x, Y_TOP + 2);
                        actx.lineTo(x, Y_BOT - 2);
                        actx.stroke();
                    }

                    // Frame labels
                    actx.fillStyle = "rgba(255,255,255,0.3)";
                    actx.font = "10px monospace";
                    actx.textAlign = "left";
                    actx.fillText("0", PAD, CH - 2);
                    actx.textAlign = "right";
                    actx.fillText(String(maxFrame), PAD + W, CH - 2);

                    // Legend
                    const seenTypes = [...new Set(evts.map(e => e.event_type.toLowerCase()))].slice(0, 12);
                    aniLegend.innerHTML = seenTypes.map(t =>
                        `<span style="display:inline-flex;align-items:center;gap:3px;margin-right:10px">` +
                        `<span style="display:inline-block;width:10px;height:3px;background:${getAniColor(t)};border-radius:1px"></span>${t}</span>`
                    ).join("") + `&nbsp;&middot;&nbsp;<span style="opacity:0.45;font-size:10px">${this.t("preview_anievent_legend")}</span>`;

                    // Info line
                    const truncNote = prev.truncated
                        ? `  ·  ${this.t("preview_first_kb_of", [String(Math.round(prev.raw_bytes.length / 1024)), String(Math.round(prev.full_preview_size / 1024))])}`
                        : "";
                    aniInfo.textContent = (aniResult.set_name ? `${this.t("preview_anievent_set", [aniResult.set_name])}  ·  ` : "") +
                        this.t("preview_anievent_summary", [String(aniResult.animation_count), String(aniResult.events.length), String(maxFrame)]) + truncNote;

                    // Table
                    const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    aniTable.innerHTML = `<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px">
                        <thead><tr style="background:var(--bg-panel,#1e293b)">
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">${this.t("preview_col_frame")}</th>
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">${this.t("preview_col_type")}</th>
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">${this.t("preview_col_animation")}</th>
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">${this.t("preview_col_params")}</th>
                        </tr></thead>
                        <tbody>${evts.slice(0, 500).map(e =>
                            `<tr><td style="padding:2px 8px;color:var(--text,#e2e8f0)">${e.frame}</td>` +
                            `<td style="padding:2px 8px;color:${getAniColor(e.event_type)}">${esc(e.event_type)}</td>` +
                            `<td style="padding:2px 8px;color:var(--text-muted,#888)">${esc(e.anim_name)}</td>` +
                            `<td style="padding:2px 8px;color:var(--text-muted,#888)">${esc(e.params)}</td></tr>`
                        ).join("")}</tbody>
                    </table>${evts.length > 500
                        ? `<div style="padding:6px 8px;font-size:11px;color:var(--text-muted,#888);font-family:monospace">… ${this.t("preview_more_rows", [String(evts.length - 500)])}</div>`
                        : ""}`;
                } else {
                    // Fallback: show message on canvas
                    actx.fillStyle = "#4a5568";
                    actx.font = "13px monospace";
                    actx.textAlign = "center";
                    actx.fillText(this.t("preview_anievent_parse_failed"), 256, 36);
                    const hexPeek = Array.from(prev.raw_bytes.slice(0, 48))
                        .map((b: number) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
                    actx.fillStyle = "#64748b";
                    actx.font = "9px monospace";
                    (hexPeek.match(/.{1,24}/g) ?? []).forEach((w, i) => actx.fillText(w, 256, 52 + i * 12));
                    aniInfo.textContent = `${this.t("unit_bytes", [prev.raw_bytes.length.toLocaleString()])}  ·  ${this.t("preview_anievent_no_events")}`;
                }
            }
        } else if (prev.file_type === "mml") {
            visual.className = "preview-tab-content active";
            visual.style.cssText = "display:flex;flex-direction:column;overflow:hidden;padding:0";
            const mmlText = prev.content_text || "";
            visual.innerHTML = this.mmlHighlight(mmlText) + this.mmlPlayerHtml();
            this.initMmlPlayer(mmlText);
        } else if (prev.content_text) {
            const isXml = ext === "xml" || ext === "csh" || ext === "rgn" || ext === "compiled";
            if (isXml) {
                visual.className = "preview-tab-content active xml-view";
                visual.innerHTML = this.xmlHighlight(prev.content_text);
                if (src.entry && isTauri() && /(^|[\\/])itemdb[^\\/]*\.xml$/i.test(prev.name)) {
                    // Item search over the open itemdb, opening an item's models.
                    import("./preview3d/itemPanel").then(({ attachItemPanel }) => {
                        if (gen === this.previewGen) attachItemPanel({ parent: visual, host: this.assetHost(), t: (k, a = []) => this.t(k, a), near: src.entry, floating: false });
                    });
                }
            } else {
                visual.className = "preview-tab-content active";
                visual.textContent = prev.content_text;
            }
        } else {
            hex.classList.add("active");
            activeContainer = "preview-hex";
            visual.textContent = this.t("preview_no_visual");
            visual.className = "preview-tab-content";
        }

        this._activePreviewContainer = activeContainer;
        const ptab = activeContainer.replace("preview-", "");
        const activeTabBtn = document.querySelector(`.preview-tab-btn[data-ptab="${ptab}"]`) as HTMLElement;
        if (activeTabBtn) activeTabBtn.click();

        const hexDump = prev.raw_bytes.map(b => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
        if (prev.truncated) {
            const kb = Math.round(prev.full_preview_size / 1024);
            hex.textContent = `[ ${this.t("preview_hex_truncated", [String(prev.raw_bytes.length), prev.full_preview_size.toLocaleString(), String(kb)])} ]\n\n${hexDump}`;
        } else if (prev.full_preview_size === 0 && prev.size === 0) {
            hex.textContent = `[ ${this.t("preview_empty_file")} ]`;
        } else {
            hex.textContent = hexDump;
        }

        const entriesSalt = this.selectedEntry?.entries_salt_used ?? "";
        const entriesSaltRow = (entriesSalt && entriesSalt !== prev.salt && entriesSalt !== "N/A" && entriesSalt !== "UNENCRYPTED")
            ? `<tr><th>${this.t("preview_entries_salt")}:</th><td class="mono">${entriesSalt}</td></tr>`
            : "";
        details.innerHTML = `<table class="details-table"><tbody>
                    <tr><th>${this.t("preview_file_name")}:</th><td>${prev.name}</td></tr>
                    <tr><th>${this.t("preview_file_type")}:</th><td>${prev.file_type}</td></tr>
                    <tr><th>${this.t("preview_source")}:</th><td>${prev.source}</td></tr>
                    <tr><th>${this.t("preview_salt")}:</th><td class="mono">${prev.salt}</td></tr>
                    ${entriesSaltRow}
                    <tr><th>${this.t("preview_extracted")}:</th><td>${this.t("unit_bytes", [prev.size.toLocaleString()])}</td></tr>
                    <tr><th>${this.t("preview_compressed")}:</th><td>${this.t("unit_bytes", [prev.raw_size.toLocaleString()])}</td></tr>
                    <tr><th>${this.t("preview_offset")}:</th><td class="mono">0x${prev.offset.toString(16).toUpperCase()}</td></tr>
                    <tr><th>${this.t("preview_checksum")}:</th><td class="mono">0x${prev.checksum.toString(16).toUpperCase()}</td></tr>
                    <tr><th>${this.t("preview_flags")}:</th><td class="mono">0x${prev.flags.toString(16).toUpperCase()}</td></tr>
                </tbody></table>`;
    }

    private async selectFile(e: AggregateEntry, div: HTMLElement) {
        this.selectedEntry = e;
        document.querySelectorAll(".tree-item").forEach(i => (i as HTMLElement).style.background = "transparent");
        div.style.background = "color-mix(in srgb, var(--accent-cyan) 20%, transparent)";
        this.log(this.t("log_selected", [e.name]));

        const visual = document.getElementById("preview-visual")!;
        visual.textContent = this.t("preview_loading");
        visual.className = "preview-tab-content active";

        const req = ++this.selectGen;
        try {
            const prev = await this.fetchPreview(e);
            if (req !== this.selectGen) return; // a newer selection owns the panel
            await this.applyPreviewToPanel(prev, { entry: e });
        } catch (err) {
            if (req !== this.selectGen) return;
            this.log(this.t("preview_error", [String(err)]), "error");
            visual.className = "preview-tab-content active";
            visual.textContent = String(err);
        }
    }

    private async openLooseFile(path: string): Promise<void> {
        this.selectedEntry = null;
        this.loadedEntries = [];
        const treeEl = document.getElementById("file-tree");
        if (treeEl) treeEl.innerHTML = `<div class="tree-empty-state">${path.split(/[\\/]/).pop()}</div>`;

        document.querySelector('.nav-item[data-tab="list"]')?.dispatchEvent(new Event('click'));

        const visual = document.getElementById("preview-visual")!;
        visual.textContent = this.t("preview_loading");
        visual.className = "preview-tab-content active";

        const req = ++this.selectGen;
        try {
            const prev = await invoke("preview_loose_file", { path }) as PreviewData;
            if (req !== this.selectGen) return;
            await this.applyPreviewToPanel(prev, { loosePath: path });
            this.log(this.t("log_opened_loose", [prev.name, this.t("unit_bytes", [prev.size.toLocaleString()])]));
        } catch (err) {
            if (req !== this.selectGen) return;
            visual.textContent = this.t("preview_error", [String(err)]);
            visual.className = "preview-tab-content active";
            this.log(this.t("log_loose_preview_error", [String(err)]), "error");
        }
    }

    private async extractSelected() {
        if (!this.selectedEntry) {
            await message(this.t("msg_select_file_first"), { title: this.t("dlg_no_selection"), kind: "error" });
            return;
        }
        const fileName = this.selectedEntry.name.split(/[\\/¥₩]/).pop() || "extracted_file";
        const dest = await save({ defaultPath: fileName });
        if (dest) {
            const skey = (this.selectedEntry.salt_used === "N/A" || this.selectedEntry.salt_used === "Search/Default") ? null : this.selectedEntry.salt_used;
            try {
                await invoke("extract_file_to", { 
                    archive: this.selectedEntry.source_archive, 
                    entry: this.selectedEntry.name, 
                    dest: dest, 
                    key: skey 
                });
                this.log(this.t("extract_success", [dest]), "success");
            } catch(e) { this.log(this.t("msg_error_fmt", [String(e)]), "error"); }
        }
    }

    private async extractAll() {
        if (this.loadedEntries.length === 0) return;
        const out = await open({ directory: true });
        if (!out || Array.isArray(out)) return;
        this._taskStartTime = Date.now();
        this.updateProgress(0, this.t("msg_extracting"));
        try {
            const isSeq = !this.currentArchive.toLowerCase().endsWith(".it") && !this.currentArchive.toLowerCase().endsWith(".pack");
            if (isSeq) {
                const seen = new Set<string>();
                for (const e of this.loadedEntries) {
                    if (!e.source_archive || seen.has(e.source_archive)) continue;
                    seen.add(e.source_archive);
                    const key = (e.salt_used === "N/A" || e.salt_used === "Search/Default") ? null : e.salt_used;
                    await invoke("extract_pack_to", { input: e.source_archive, output: out, key, filters: [] });
                }
            } else {
                const salt = this.loadedEntries[0]?.salt_used;
                const key = (salt === "N/A" || salt === "Search/Default") ? null : salt;
                await invoke("extract_pack_to", { input: this.currentArchive, output: out, key, filters: [] });
            }
            this.log(this.t("extract_success", [this.currentArchive]), "success");
        } catch (e) {
            this._taskStartTime = null;
            this.updateProgress(0, "");
            this.log(this.t("msg_error_fmt", [String(e)]), "error");
        }
    }

    private async convertTo(ext: string) {
        if (this._taskStartTime !== null) {
            await message(this.t("msg_task_running"), { title: this.t("dlg_task_in_progress"), kind: "warning" });
            return;
        }
        if (!this.currentArchive) return;
        const out = await save({
            defaultPath: this.currentArchive.replace(/\.(it|pack)$/i, "") + "." + ext,
            filters: [{ name: ext.toUpperCase(), extensions: [ext] }]
        });
        if (out) {
            this._taskStartTime = Date.now();
            try {
                const salt = (this.loadedEntries[0]?.salt_used === "N/A" || this.loadedEntries[0]?.salt_used === "Search/Default") ? null : this.loadedEntries[0]?.salt_used;
                let wrapData = false;
                const hasDataFolder = this.loadedEntries.some(e => {
                    const first = e.name.split(/[\\/]/)[0].toLowerCase();
                    return first === "data";
                });
                if (!hasDataFolder) {
                    wrapData = await ask(this.t("dataWrapPrompt"), { title: this.t("dataWrapTitle"), kind: 'warning' });
                }
                await invoke("run_convert", { input: this.currentArchive, output: out, key: salt, wrapData });
                this.log(this.t("log_converted_to", [ext.toUpperCase(), out]), "success");
            } catch (e) { this.log(this.t("msg_error_fmt", [String(e)]), "error"); }
            finally { this._taskStartTime = null; }
        }
    }

    private async handleTerminalCommand(cmd: string) {
        if (!cmd.trim()) return;
        const args = cmd.split(' ');
        const base = args[0].toLowerCase();

        if (base === "clear") {
            const logView = document.getElementById("log-view");
            if (logView) logView.innerHTML = "";
            return;
        }
        if (base === "help") {
            this.log(this.t("term_help"));
            return;
        }
        if (base === "logs") {
            await invoke("open_log_file");
            return;
        }
        if (base === "salts") {
            if (this.engineSalts.length === 0) {
                try { this.engineSalts = await invoke("get_all_salts") as string[]; } catch (_) {}
            }
            const suggested = ["@6QeTuOaDgJlZcBm#9", "})wWb4?-sVGHNoPKpc"];
            const userHistory = (this.config.salt_history || []).map(s => s.trim());
            const all = [...new Set([...suggested, ...userHistory, ...this.engineSalts])].filter(s => s.length > 0);
            this.log(`${this.t("term_salts_loaded", [String(all.length)])}\n${all.join('\n')}`);
            return;
        }
        if (base === "version") {
            this.log(this.t("title"), "info");
            return;
        }

        try {
            const r = await invoke("execute_terminal_command", { command: cmd }) as string;
            this.log(r, "info");
        } catch (e) { this.log(`${e}`, "error"); }
    }

    private initTooltip() {
        const tip = document.createElement('div');
        tip.id = 'app-tooltip';
        document.body.appendChild(tip);
        let showTimer: number | null = null;

        const show = (anchor: HTMLElement) => {
            // Resolve locale key: if value starts with "tooltip_", look it up
            let text = anchor.dataset.tooltip || '';
            // Any value that is a locale key resolves to its translation; raw text passes through.
            const translated = this.t(text);
            if (translated && translated !== text) text = translated;
            if (!text) return;
            tip.textContent = text;
            tip.style.opacity = '1';

            const r = anchor.getBoundingClientRect();
            const tw = tip.offsetWidth;
            const th = tip.offsetHeight;
            let x = r.right + 8;
            let y = r.top + (r.height - th) / 2;
            if (x + tw > window.innerWidth - 4) x = r.left - tw - 8;
            y = Math.max(4, Math.min(y, window.innerHeight - th - 4));
            tip.style.left = x + 'px';
            tip.style.top = y + 'px';
        };

        document.addEventListener('mouseover', (e) => {
            const anchor = (e.target as Element).closest('[data-tooltip]') as HTMLElement | null;
            if (showTimer) clearTimeout(showTimer);
            if (!anchor?.dataset.tooltip) { tip.style.opacity = '0'; return; }
            showTimer = window.setTimeout(() => show(anchor), 180);
        });

        document.addEventListener('mouseout', (e) => {
            const anchor = (e.target as Element).closest('[data-tooltip]');
            const related = e.relatedTarget as Element | null;
            if (!anchor?.contains(related)) {
                if (showTimer) clearTimeout(showTimer);
                tip.style.opacity = '0';
            }
        });

        document.addEventListener('click', () => { tip.style.opacity = '0'; });
        document.addEventListener('scroll', () => { tip.style.opacity = '0'; }, true);
    }

    private updateProgress(percent: number, msg: string, indeterminate = false) {
        const dashBar = document.getElementById("dash-pipe-extract") as HTMLElement | null;
        const dashLabel = document.getElementById("dash-pipe-label");
        if (dashBar) dashBar.style.width = indeterminate ? "100%" : `${percent}%`;
        if (dashLabel) dashLabel.textContent = msg || (percent === 0 ? this.t("dash_pipe_idle") : "");

        const bar = document.getElementById("progress-bar");
        if (bar) {
            if (indeterminate) {
                bar.classList.add("indeterminate");
                bar.style.width = "100%";
            } else {
                bar.classList.remove("indeterminate");
                bar.style.width = `${percent}%`;
            }
        }

        const eta = document.getElementById("eta-msg");
        if (eta) eta.textContent = msg;
    }

    private async wipeHistory() {
        this.config.salt_history = ["})wWb4?-sVGHNoPKpc"];
        await this.saveConfig();
        await message(this.t("historyWiped"), { title: this.t("success"), kind: "info" });
        this.log(this.t("historyWiped"), "success");
    }

    private handleAutoInput(path: string, fullSeq = false) {
        const lp = path.toLowerCase();
        const isLoose = lp.endsWith(".dds") || lp.endsWith(".pmg") || lp.endsWith(".compiled");
        if (isLoose) {
            this.openLooseFile(path).catch(() => {});
            return;
        }

        const isArchive = lp.endsWith(".it") || lp.endsWith(".pack");
        if (isArchive) {
            (document.getElementById("list-input") as HTMLInputElement).value = path;
            (document.getElementById("extract-input") as HTMLInputElement).value = path;
            this.handlePathAutoFill("extract-input", path);

            if (this.config.startup_auto_extract) {
                this.runList(fullSeq);
            }
            if (this.config.startup_auto_switch) {
                document.querySelector('.nav-item[data-tab="list"]')?.dispatchEvent(new Event('click'));
            }
        } else {
            (document.getElementById("pack-input") as HTMLInputElement).value = path;
            (document.getElementById("extract-output") as HTMLInputElement).value = path;
            this.handlePathAutoFill("pack-input", path);
        }
    }

    private formatDuration(ms: number): string {
        if (ms < 1000) return `${ms}ms`;
        const s = Math.round(ms / 1000);
        if (s < 60) return `${s}s`;
        const m = Math.floor(s / 60);
        const rem = s % 60;
        return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
    }

    private setupEventListen() {
        listen("progress", (event) => {
            const p = event.payload as { current: number; total: number; msg: string; bytes?: number; total_bytes?: number };

            if (p.msg === "Complete") {
                this._taskStartTime = null;
                this.updateProgress(100, this.t("msg_complete"));
                setTimeout(() => this.updateProgress(0, ""), 2000);
                return;
            }

            if (p.current === 0 && p.total === 0) {
                this.updateProgress(0, p.msg || "");
                return;
            }

            const percent = p.total > 0 ? (p.current / p.total) * 100 : 0;
            const pctStr = p.total > 0 ? `${Math.round(percent)}%` : "";

            let parts: string[] = [];
            if (pctStr) parts.push(pctStr);

            if (p.total_bytes && p.bytes && p.bytes > 0) {
                const mb = (p.bytes / 1048576).toFixed(1);
                const totalMb = (p.total_bytes / 1048576).toFixed(1);
                parts.push(`${mb}/${totalMb} MB`);
            }

            if (this._taskStartTime !== null && p.current > 1 && p.total > 0) {
                const elapsed = Date.now() - this._taskStartTime;
                const rate = p.current / elapsed;
                const remaining = p.total - p.current;
                const etaMs = rate > 0 ? remaining / rate : 0;
                if (etaMs > 500) parts.push(this.t("progress_eta", [this.formatDuration(etaMs)]));
            }

            this.updateProgress(percent, parts.join(" — "));
        });

        listen("log-message", (event) => {
            const p = event.payload as { message: string, level: string };
            this.log(p.message, p.level, true); // fromRust=true: already in log.txt via WriteLogger
        });

        listen("open-file", (event) => {
            const data = event.payload as { path: string, full_sequence: boolean } | string;
            const path = typeof data === "string" ? data : data.path;
            const fullSeq = typeof data === "string" ? false : data.full_sequence;
            this.handleAutoInput(path, fullSeq);
        });

        listen("tauri://drag-drop", async (event) => {
            const p = event.payload as any;
            // Dropped onto the List tab tree of an open archive: add/merge into it
            if (p.paths && p.paths.length > 0 && await this.vfsHandleExternalDrop(p.paths, p.position)) return;
            if (p.paths && p.paths.length > 0) {
                const path = p.paths[0];
                this.log(`[DROP] ${path}`);
                const lp = path.toLowerCase();
                if (lp.endsWith(".it") || lp.endsWith(".pack")) {
                    // Archive drag: always open list tab and load — don't check startup_auto_switch
                    (document.getElementById("list-input") as HTMLInputElement).value = path;
                    (document.getElementById("extract-input") as HTMLInputElement).value = path;
                    this.handlePathAutoFill("extract-input", path);
                    document.querySelector('.nav-item[data-tab="list"]')?.dispatchEvent(new Event('click'));
                    this.runList();
                } else {
                    this.handleAutoInput(path);
                }
            }
        });
    }
}

// Disable WebView2 native right-click context menu everywhere except text inputs.
// Without this, right-clicking shows an "Import passwords / Send tab to your devices"
// browser menu which blocks window minimize/maximize and is never useful here.
document.addEventListener("contextmenu", (e) => {
    const t = e.target as HTMLElement;
    const editable = t.tagName === "INPUT" || t.tagName === "TEXTAREA" || (t as HTMLElement).isContentEditable;
    if (!editable) e.preventDefault();
});

new App();
