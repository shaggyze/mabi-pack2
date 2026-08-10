import { invoke } from "./platform/invoke";
import { open, save, ask, message } from "./platform/dialog";
import { writeTextFile } from "./platform/fs";
import { listen } from "./platform/event";
import { locales as TRANSLATIONS } from "./locales";
import type { PMGViewer, PmgGeometry } from "./pmgLoader";

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

interface AggregateEntry extends FileEntry {
    source_archive: string;
    salt_used: string;
    entries_salt_used: string;
    iv0: number;
    h_off: number;
    mode: string;
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
    kanan_cfg_path: string;
    patcher_game_path: string;
    patcher_hyddwn_enabled: boolean;
    patcher_hyddwn_url: string;
    patcher_auto_update: boolean;
    patcher_focus_on_start: boolean;
    patcher_max_workers: number;
    patcher_run_elevated: boolean;
    launch_use_nexon_launcher: boolean;
    launch_cmd_override: string;
    pre_patch_cmd: string;
    pre_launch_cmd: string;
    post_launch_cmd: string;
    parallel_ops: boolean;
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

class App {
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
        kanan_cfg_path: "",
        patcher_game_path: "",
        patcher_hyddwn_enabled: false,
        patcher_hyddwn_url: "http://127.0.0.1:11000",
        patcher_auto_update: false,
        patcher_focus_on_start: false,
        patcher_run_elevated: false,
        patcher_max_workers: 10,
        launch_use_nexon_launcher: false,
        launch_cmd_override: "",
        pre_patch_cmd: "",
        pre_launch_cmd: "",
        post_launch_cmd: "",
        parallel_ops: true,
    };

    private loadedEntries: AggregateEntry[] = [];
    private selectedEntry: AggregateEntry | null = null;
    private pmgViewer?: PMGViewer;
    private currentArchive: string = "";
    private engineSalts: string[] = [];
    private previewCache = new Map<string, PreviewData>();
    private _taskStartTime: number | null = null;
    private _audioBlobUrl: string = "";
    private _activePreviewContainer: string = "preview-visual";
    private _mmlAudioCtx: AudioContext | null = null;
    private _mmlStopFlag: boolean = false;

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
        this.translateUI();
        this.syncSettingsUI();
        this.initTooltip();
        this.setupNavigation();
        this.setupDashboard();
        this.setupJobQueue();
        this.setupVfsEditing();
        this.setupLauncher();
        this.setupFeaturesEditor();
        this.setupThemeCustomizer();
        this.setupPatcherTab();
        this.setupResizableList();
        this.setup3dPreviewResize();
        this.setupForms();
        this.setupEventListen();

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
            this.log("[Patcher] Auto-update enabled — starting patch on launch", "info");
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
        return text;
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

        // Empty file tree placeholder
        const treeEmpty = document.getElementById("file-tree-empty");
        if (treeEmpty) treeEmpty.textContent = this.t("tree_empty");

        // Main title
        const mainTitle = document.getElementById("main-title");
        if (mainTitle) mainTitle.textContent = this.t("title");

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
        ["dashboard", "extract", "pack", "list", "differ", "jobs", "patcher", "features", "launcher", "settings"].forEach(tab => {
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
            if (span.id) span.dataset.tooltip = span.id;
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
        const s = document.documentElement.style;
        const set = (v: string | undefined, prop: string) => v ? s.setProperty(prop, v) : s.removeProperty(prop);

        set(o.bg_deep, '--bg-deep');
        set(o.bg_sidebar, '--bg-sidebar');
        set(o.bg_input, '--bg-input');
        set(o.bg_deep ?? o.bg_surface_color, '--bg-terminal');
        set(o.accent_cyan, '--accent-cyan');
        set(o.accent_blue, '--accent-blue');
        set(o.accent_cyan, '--accent-neon');
        set(o.text_primary, '--text-primary');
        set(o.text_muted, '--text-muted');

        if (o.bg_surface_color !== undefined || o.surface_opacity !== undefined) {
            const base = o.bg_surface_color ?? this.getCssVar('--bg-deep');
            const alpha = ((o.surface_opacity ?? 60) / 100).toFixed(2);
            const hex = base.startsWith('#') ? base : '#011627';
            const r = parseInt(hex.slice(1,3), 16);
            const g = parseInt(hex.slice(3,5), 16);
            const b = parseInt(hex.slice(5,7), 16);
            s.setProperty('--bg-surface', `rgba(${r},${g},${b},${alpha})`);
        } else {
            s.removeProperty('--bg-surface');
        }

        if (o.border_color !== undefined || o.border_opacity !== undefined) {
            const base = o.border_color ?? this.getCssVar('--accent-cyan');
            const alpha = ((o.border_opacity ?? 30) / 100).toFixed(2);
            const hex = base.startsWith('#') ? base : '#7fdbca';
            const r = parseInt(hex.slice(1,3), 16);
            const g = parseInt(hex.slice(3,5), 16);
            const b = parseInt(hex.slice(5,7), 16);
            s.setProperty('--border-glass', `rgba(${r},${g},${b},${alpha})`);
        } else {
            s.removeProperty('--border-glass');
        }

        if (o.font_family) s.setProperty('--ui-font', o.font_family);
        else s.removeProperty('--ui-font');
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
        setColor('tc-border-color',  o.border_color,     '--accent-cyan');
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
            sel.innerHTML = '<option value="">— saved themes —</option>';
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
            (this.config.theme_overrides as any)[key] = value;
            this.applyThemeOverrides();
            this.saveConfig();
        };

        const bindColor = (id: string, key: keyof ThemeOverrides) => {
            document.getElementById(id)?.addEventListener('input', (e) => {
                update(key, (e.target as HTMLInputElement).value);
            });
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
            if (!name) { alert('Enter a theme name first.'); return; }
            if (!this.config.custom_themes) this.config.custom_themes = {};
            this.config.custom_themes[name] = { ...this.config.theme_overrides };
            this.saveConfig();
            this.syncCustomizerUI();
            // Select the newly saved theme in the dropdown and show feedback
            const sel = document.getElementById('custom-theme-select') as HTMLSelectElement | null;
            if (sel) sel.value = name;
            if (nameEl) {
                nameEl.value = '';
                nameEl.placeholder = `Saved: ${name}`;
                setTimeout(() => { nameEl.placeholder = 'My Theme Name'; }, 2000);
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
            if (!confirm(`Delete theme "${name}"?`)) return;
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
            const chosen = await open({ directory: true, title: "Select Mabinogi folder" });
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
            if (!gp) { setText("Set game path first.", false); return; }
            setText("Checking...");
            this.log("Checking for updates...");
            try {
                const res = await invoke("check_patch_version", { gamePath: gp }) as any;
                const localEl = document.getElementById("patcher-version-local");
                const remoteEl = document.getElementById("patcher-version-remote");
                if (localEl) localEl.textContent = String(res.local_version ?? "—");
                if (remoteEl) remoteEl.textContent = String(res.remote_version ?? "—");
                if (res.needs_update) {
                    setText(`Update available: v${res.remote_version}`, false);
                    this.log(`Update available: local v${res.local_version} → v${res.remote_version}`);
                } else if (res.remote_version == null) {
                    setText(`Installed: v${res.local_version ?? "?"}`, true);
                    this.log(`Local version: v${res.local_version ?? "?"} (remote check unavailable)`);
                } else {
                    setText("Up to date ✓", true);
                    this.log(`Up to date (v${res.local_version})`);
                }
            } catch(e) {
                setText(`Check failed: ${e}`, false);
                this.log(`Check error: ${e}`);
            }
        });

        // Patch / Repair buttons
        document.getElementById("btn-patcher-patch")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText("Set game path first.", false); return; }
            await this.runPatcher(gp, false);
        });
        document.getElementById("btn-patcher-repair")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText("Set game path first.", false); return; }
            await this.runPatcher(gp, true);
        });

        // Verify button
        document.getElementById("btn-patcher-verify")?.addEventListener("click", async () => {
            const gp = getGamePath();
            if (!gp) { setText("Set game path first.", false); return; }
            setText("Verifying...");
            this.log(`Verifying: ${gp}`);
            try {
                const res = await invoke("verify_game_files", { gamePath: gp }) as any;
                if (res.error && !res.version) { setText(`Error: ${res.error}`, false); this.log(`Error: ${res.error}`); return; }
                const managed = res.managed_version ?? res.version ?? 0;
                const local = res.local_version ?? res.version ?? 0;
                const bt = res.buildtime ? new Date(res.buildtime * 1000).toLocaleDateString() : "";
                const verLabel = (managed !== local) ? `v${managed} (local: v${local})` : `v${managed}`;
                const header = verLabel + (bt ? ` (${bt})` : "") + ` — ${res.files_ok ?? 0} ok, ${res.files_missing ?? 0} missing, ${res.files_mismatched ?? 0} wrong`;
                if (res.ok) {
                    setText(header, true);
                    this.log(`Verify OK: ${header}`);
                    const localEl = document.getElementById("patcher-version-local");
                    if (localEl && local) localEl.textContent = String(local);
                } else {
                    const missStr = (res.missing ?? []).slice(0, 5).join(", ");
                    const mismStr = (res.mismatched ?? []).slice(0, 3).map((m: any) => m.path ?? m).join(", ");
                    setText(header, false);
                    this.log(`Verify issues: ${header}`);
                    if (missStr) this.log(`Missing: ${missStr}`);
                    if (mismStr) this.log(`Wrong: ${mismStr}`);
                }
            } catch(e) {
                setText(`Error: ${e}`, false);
                this.log(`Verify error: ${e}`);
            }
        });

        // Stop button
        document.getElementById("btn-patcher-stop")?.addEventListener("click", () => {
            this.log("Stop requested — cancellation not yet implemented");
        });

        // Settings > Patcher subtab wiring (elements live in stab-patcher but found by ID)
        const autoUpdateChk = document.getElementById("patcher-auto-update") as HTMLInputElement | null;
        const focusOnStartChk = document.getElementById("patcher-focus-on-start") as HTMLInputElement | null;
        const runElevatedChk = document.getElementById("patcher-run-elevated") as HTMLInputElement | null;
        const maxWorkersEl = document.getElementById("patcher-max-workers") as HTMLInputElement | null;
        const hyddwnUrlEl = document.getElementById("patcher-hyddwn-url") as HTMLInputElement | null;
        const launchNexonEl = document.getElementById("launch-use-nexon-launcher") as HTMLInputElement | null;
        const launchCmdEl = document.getElementById("launch-cmd-override") as HTMLTextAreaElement | null;
        const prePatchEl = document.getElementById("pre-patch-cmd") as HTMLTextAreaElement | null;
        const preLaunchEl = document.getElementById("pre-launch-cmd") as HTMLTextAreaElement | null;
        const postLaunchEl = document.getElementById("post-launch-cmd") as HTMLTextAreaElement | null;

        if (autoUpdateChk) autoUpdateChk.checked = this.config.patcher_auto_update;
        if (focusOnStartChk) focusOnStartChk.checked = this.config.patcher_focus_on_start;
        if (runElevatedChk) runElevatedChk.checked = this.config.patcher_run_elevated ?? false;
        if (maxWorkersEl) maxWorkersEl.value = String(this.config.patcher_max_workers ?? 10);
        if (hyddwnUrlEl && this.config.patcher_hyddwn_url) hyddwnUrlEl.value = this.config.patcher_hyddwn_url;
        if (launchNexonEl) launchNexonEl.checked = this.config.launch_use_nexon_launcher ?? false;
        if (launchCmdEl) launchCmdEl.value = this.config.launch_cmd_override ?? "";
        if (prePatchEl) prePatchEl.value = this.config.pre_patch_cmd ?? "";
        if (preLaunchEl) preLaunchEl.value = this.config.pre_launch_cmd ?? "";
        if (postLaunchEl) postLaunchEl.value = this.config.post_launch_cmd ?? "";

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
        prePatchEl?.addEventListener("blur", () => { this.config.pre_patch_cmd = prePatchEl.value.trim(); this.saveConfig(); });
        preLaunchEl?.addEventListener("blur", () => { this.config.pre_launch_cmd = preLaunchEl.value.trim(); this.saveConfig(); });
        postLaunchEl?.addEventListener("blur", () => { this.config.post_launch_cmd = postLaunchEl.value.trim(); this.saveConfig(); });

        // Patcher settings: version refresh + force re-download + clear cache
        document.getElementById("btn-patcher-settings-check")?.addEventListener("click", async () => {
            const gp = this.config.patcher_game_path;
            if (!gp) return;
            try {
                const res = await invoke("check_patch_version", { gamePath: gp }) as any;
                const el = document.getElementById("patcher-settings-version");
                if (el) el.textContent = `v${res.local_version ?? "?"}`;
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
                if (el) el.textContent = res.deleted ? "Cache cleared" : "No cache";
            } catch(e) {
                if (el) el.textContent = `Error: ${e}`;
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
                    if (pipeLabel) pipeLabel.textContent = "Idle";
                    if (stopBtn) stopBtn.style.display = "none";
                    if (e.error) this.log(`Error: ${e.error}`);
                    // Clear all worker bars on completion
                    const barsEl = document.getElementById("patcher-bars");
                    if (barsEl) barsEl.innerHTML = "";
                    this.workerBars.clear();
                } else {
                    if (pipeCard) pipeCard.style.display = "";
                    if (wrap) wrap.style.display = "block";
                    if (bar) bar.style.width = pct + "%";
                    if (stopBtn) stopBtn.style.display = "";
                    const info = e.phase === "downloading"
                        ? `${e.parts_done}/${e.parts_total} parts (${pct}%)`
                        : e.phase === "scanning"
                        ? `Scanning ${e.parts_done}/${e.parts_total} — ${e.files_done} need update`
                        : `${e.files_done}/${e.files_total} files (${pct}%)`;
                    const fileShort = e.current_file.length > 55 ? "..." + e.current_file.slice(-52) : e.current_file;
                    if (detail) detail.textContent = info + " — " + fileShort;
                    if (e.phase === "scanning" && e.parts_done === e.parts_total) {
                        this.log(`Scan complete: ${e.files_done} of ${e.parts_total} files need update`);
                    }
                    if (e.phase === "installing" && e.files_done > 0 && e.files_done % 50 === 0) {
                        this.log(`Installing: ${e.files_done}/${e.files_total} files (${pct}%)`);
                    }
                    if (pipeBar) pipeBar.style.width = pct + "%";
                    if (pipeLabel) pipeLabel.textContent = "Patching: " + info;
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
                        if (phaseEl) phaseEl.textContent = `installing ${e.parts_done}/${e.parts_total}`;
                        if (e.parts_done === 1) this.log(`Installing: ${fileShort}`);
                    } else {
                        if (fill) { fill.style.animation = "patcher-sweep 1.5s linear infinite"; fill.style.width = "40%"; }
                        if (phaseEl) phaseEl.textContent = "downloading";
                    }
                }
            });
        });
    }

    async runPatcher(gamePath: string, forceRepair: boolean) {
        const statusEl = document.getElementById("patcher-status");
        const wrap = document.getElementById("patcher-progress-wrap");
        const bar = document.getElementById("patcher-progress-bar");
        const detail = document.getElementById("patcher-progress-detail");
        const pipeCard = document.getElementById("dash-pipe-card");
        const stopBtn = document.getElementById("btn-patcher-stop");
        const setText = (msg: string, ok?: boolean) => {
            if (statusEl) { statusEl.textContent = msg; statusEl.style.color = ok === false ? "var(--accent-neon)" : ok === true ? "var(--accent-cyan)" : "var(--text-muted)"; }
        };
        if (pipeCard) pipeCard.style.display = "";
        if (wrap) wrap.style.display = "block";
        if (bar) bar.style.width = "0%";
        if (detail) detail.textContent = "Starting...";
        if (stopBtn) stopBtn.style.display = "";
        setText(forceRepair ? "Repairing..." : "Patching...");
        this.log(forceRepair ? "Starting full repair — scanning files for changes..." : "Starting patch...");
        try {
            const maxWorkers = this.config.patcher_max_workers ?? 10;
            const parallelOps = this.config.parallel_ops ?? true;
            const res = await invoke("patch_game_files", { gamePath, maxWorkers, forceRepair, parallelOps }) as any;
            if (wrap) wrap.style.display = "none";
            if (pipeCard) pipeCard.style.display = "none";
            if (stopBtn) stopBtn.style.display = "none";
            if (res.managed_version) {
                const localEl = document.getElementById("patcher-version-local");
                if (localEl) localEl.textContent = String(res.managed_version);
            }
            if (res.needs_elevation) {
                setText("Requires administrator â€” relaunching...", false);
                this.log("Permission denied â€” relaunching as administrator...");
                await invoke("request_elevation");
            } else if (res.ok) {
                const msg = res.patched === 0
                    ? `Up to date (v${res.managed_version ?? "?"})`
                    : `Patched ${res.patched} files  v${res.managed_version ?? "?"}`;
                setText(msg, true);
                this.log(msg);
            } else if (res.message) {
                setText(res.message, true);
                this.log(res.message);
            } else {
                const errs = (res.errors ?? []).slice(0, 3).join("; ");
                setText(`Errors: ${errs}`, false);
                this.log(`Errors: ${errs}`);
            }
        } catch(e) {
            if (wrap) wrap.style.display = "none";
            if (pipeCard) pipeCard.style.display = "none";
            if (stopBtn) stopBtn.style.display = "none";
            const errStr = String(e).toLowerCase();
            if (errStr.includes("access is denied") || errStr.includes("permissiondenied") || errStr.includes("permission denied")) {
                setText("Requires administrator â€” relaunching...", false);
                this.log("Permission denied â€” relaunching as administrator...");
                await invoke("request_elevation");
            } else {
                setText(`Failed: ${e}`, false);
                this.log(`Error: ${e}`);
            }
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

    private async refreshModsList() {
        const list  = document.getElementById("dash-mods-list");
        const empty = document.getElementById("dash-mods-empty");
        const path  = document.getElementById("dash-mods-path");
        if (!list) return;
        try {
            const dir  = await invoke("get_mods_dir") as string;
            const mods = await invoke("list_mod_files") as Array<{
                file: string; name: string; version?: string; author?: string;
                description?: string; tags?: string[]; file_count: number; is_public: boolean; error?: string;
            }>;
            if (path) path.textContent = dir;
            list.querySelectorAll(".mod-item").forEach(el => el.remove());
            if (mods.length === 0) {
                if (empty) empty.style.display = "";
            } else {
                if (empty) empty.style.display = "none";
                for (const m of mods) {
                    const el = document.createElement("div");
                    el.className = "mod-item";
                    if (m.error) {
                        el.innerHTML = `<span class="mod-item-name">${m.file}</span><span class="mod-item-err">${m.error}</span>`;
                    } else {
                        const pub = m.is_public ? `<span class="mod-item-badge-pub">PUBLIC</span>` : "";
                        const tagsHtml = m.tags && m.tags.length
                            ? m.tags.map(t => `<span class="mod-tag">${t}</span>`).join("")
                            : "";
                        const desc = m.description ? `<div class="mod-item-desc">${m.description}</div>` : "";
                        const byline = [m.version, m.author].filter(Boolean).join(" · ");
                        el.innerHTML = `
                            <div class="mod-item-header">
                                <span class="mod-item-name">${m.name}</span>
                                ${pub}
                                <button class="tab-btn mod-apply-btn" data-modfile="${m.file}" style="margin-left:auto;font-size:11px;padding:2px 8px;">Apply</button>
                            </div>
                            <div class="mod-item-meta">${byline} · ${m.file_count} files ${tagsHtml}</div>
                            ${desc}`;
                        el.querySelector(".mod-apply-btn")?.addEventListener("click", async () => {
                            await this.applyModFromDashboard(dir + "/" + m.file);
                        });
                    }
                    list.insertBefore(el, empty!);
                }
            }
        } catch (_) {}
    }

    private async applyModFromDashboard(modFilePath: string) {
        try {
            const { open } = await import("./platform/dialog");
            const archivePath = await open({
                title: "Select target .it or .pack archive",
                filters: [{ name: "Archive", extensions: ["it", "pack"] }],
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
            alert(`Applied: ${result.name} → ${result.replaced} replaced, ${result.deleted} deleted, ${result.patched} patched`);
        } catch (err) { alert("Apply failed: " + err); }
    }

    private setupModsActions() {
        document.getElementById("btn-open-mods-dir")?.addEventListener("click", async () => {
            try {
                const dir = await invoke("get_mods_dir") as string;
                await invoke("execute_terminal_command", { command: `explorer "${dir}"` });
                this.log(`[Mods] Opened mods directory: ${dir}`, "info");
            } catch (e) { this.log(`[Mods] Failed to open mods dir: ${e}`, "error"); }
        });
        document.getElementById("btn-new-mod-template")?.addEventListener("click", async () => {
            try {
                const tmpl = await invoke("get_mod_template") as string;
                const dir  = await invoke("get_mods_dir") as string;
                const dest = dir + "\\new_mod.mod";
                await writeTextFile(dest, tmpl);
                await invoke("execute_terminal_command", { command: `explorer /select,"${dest}"` });
                this.log(`[Mods] Created new mod template: ${dest}`, "info");
            } catch (e) { this.log(`[Mods] Failed to create template: ${e}`, "error"); }
        });
    }

    // ── VFS editing ─────────────────────────────────────────────────────────────

    private vfsPending: Array<{op: string; [k: string]: string}> = [];

    private setupVfsEditing() {
        const tree = document.getElementById("file-tree")!;
        const toolbar = document.getElementById("vfs-toolbar")!;

        // Drag-over: highlight drop target
        tree.addEventListener("dragover", (e) => {
            if (e.dataTransfer?.types.includes("Files")) {
                e.preventDefault();
                tree.classList.add("vfs-drop-active");
            }
        });
        tree.addEventListener("dragleave", () => tree.classList.remove("vfs-drop-active"));
        tree.addEventListener("drop", async (e) => {
            e.preventDefault();
            tree.classList.remove("vfs-drop-active");
            if (!this.currentArchive) return;
            const files = Array.from(e.dataTransfer?.files ?? []);
            // Find which folder was hovered
            const hoveredRow = (e.target as HTMLElement).closest<HTMLElement>(".tree-row.folder, .tree-item");
            let destFolder = "";
            if (hoveredRow) {
                const folderPath = hoveredRow.dataset.path ?? "";
                destFolder = folderPath ? folderPath.replace(/\\/g, "/").replace(/\/?$/, "/") : "";
            }
            // Build candidate list for conflict checking
            const candidates: Array<{localPath: string; destPath: string}> = [];
            for (const f of files) {
                const localPath = (f as any).path as string | undefined;
                if (!localPath) continue;
                candidates.push({ localPath, destPath: destFolder + f.name });
            }
            // Resolve conflicts (shows dialog if any file already exists in the archive)
            const resolved = await this.resolveConflicts(candidates);
            for (const r of resolved) {
                this.vfsPending.push({ op: "add", dest: r.destPath, local_src: r.localPath });
            }
            if (resolved.length > 0) this.renderVfsPending();
        });

        // Right-click on tree items → unified context menu
        tree.addEventListener("contextmenu", (e) => {
            if (!this.currentArchive) return;
            const row = (e.target as HTMLElement).closest<HTMLElement>(".tree-item, .tree-row");
            if (!row) return;
            e.preventDefault();
            const path = row.dataset.path ?? "";
            // Build a synthetic entry so showContextMenu can work
            const syntheticEntry = this.loadedEntries.find(en => en.name === path) ?? {
                name: path, source_archive: this.currentArchive, salt_used: "",
                entries_salt_used: "", original_size: 0, raw_size: 0,
                offset: 0, checksum: 0, flags: 0, key: [], iv0: 0, h_off: 0, mode: ""
            } as AggregateEntry;
            this.showContextMenu(e, syntheticEntry);
        });

        // Merge archive button
        document.getElementById("btn-vfs-merge")?.addEventListener("click", async () => {
            if (!this.currentArchive) return;
            try {
                const { open } = await import("./platform/dialog");
                const chosen = await open({ filters: [{ name: "Archive", extensions: ["it", "pack"] }] });
                if (!chosen) return;
                const srcPath = typeof chosen === "string" ? chosen : (chosen as any).path ?? chosen[0];
                this.vfsPending.push({ op: "merge", src_archive: srcPath });
                this.renderVfsPending();
                this.log(`[VFS] Queued merge: ${srcPath} → ${this.currentArchive}`, "info");
            } catch (err) {
                this.log(`[VFS] Merge error: ${err}`, "error");
            }
        });

        // Apply button
        document.getElementById("btn-vfs-apply")?.addEventListener("click", async () => {
            if (!this.currentArchive || this.vfsPending.length === 0) return;
            const btn = document.getElementById("btn-vfs-apply")!;
            btn.textContent = "Applying…";
            btn.setAttribute("disabled", "true");
            this.log(`[VFS] Applying ${this.vfsPending.length} change(s) to ${this.currentArchive}`, "info");
            try {
                const result = await invoke("apply_vfs_changes", {
                    archive: this.currentArchive,
                    key: null,
                    changes: this.vfsPending,
                }) as any;
                this.vfsPending = [];
                this.renderVfsPending();
                this.log(`[VFS] Applied ${result.changes} change(s) — ${JSON.stringify(result.stats)}`, "info");
                // Reload the archive listing
                await this.listArchive(this.currentArchive);
            } catch (err) {
                this.log(`[VFS] Apply failed: ${err}`, "error");
            }
            btn.textContent = "APPLY CHANGES";
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
            this.log(`[VFS] Reset ${count} pending change(s)`, "info");
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
        if (badge) badge.textContent = `${this.vfsPending.length} pending`;
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

    // ── VFS Conflict Resolution ──────────────────────────────────────────────────

    /** Check candidates against the loaded archive entries and show a dialog for
     *  each collision.  Returns only the items that should be added (with resolved
     *  destination paths). */
    private async resolveConflicts(
        candidates: Array<{localPath: string; destPath: string}>
    ): Promise<Array<{localPath: string; destPath: string}>> {
        const result: Array<{localPath: string; destPath: string}> = [];

        // Build lookup from currently loaded archive entries
        const existingPaths = new Set(this.loadedEntries.map(e => e.name));

        const conflicts: typeof candidates = [];
        for (const c of candidates) {
            if (existingPaths.has(c.destPath)) {
                conflicts.push(c);
            } else {
                result.push(c);
            }
        }

        if (conflicts.length === 0) return result;

        let batchAction: "overwrite" | "skip" | null = null;

        for (const conflict of conflicts) {
            if (batchAction === "overwrite") {
                result.push(conflict);
                continue;
            }
            if (batchAction === "skip") {
                continue;
            }

            const choice = await this.showConflictDialog(conflict.destPath, conflicts.length > 1);

            if (choice.applyAll) {
                if (choice.action === "overwrite") batchAction = "overwrite";
                else if (choice.action === "skip") batchAction = "skip";
            }

            if (choice.action === "overwrite") {
                result.push(conflict);
            } else if (choice.action === "rename" && choice.newName) {
                const folder = conflict.destPath.includes("/")
                    ? conflict.destPath.slice(0, conflict.destPath.lastIndexOf("/") + 1)
                    : "";
                result.push({ localPath: conflict.localPath, destPath: folder + choice.newName });
            }
            // action === "skip" → omit from result
        }

        return result;
    }

    /** Show the conflict dialog for a single file and wait for the user's choice. */
    private showConflictDialog(
        destPath: string,
        hasMore: boolean
    ): Promise<{action: "overwrite" | "skip" | "rename"; newName?: string; applyAll: boolean}> {
        return new Promise((resolve) => {
            const ctrl = new AbortController();
            const { signal } = ctrl;

            const overlay      = document.getElementById("conflict-dialog")!;
            const filenameEl   = document.getElementById("conflict-filename")!;
            const applyAllRow  = document.getElementById("conflict-apply-all-row") as HTMLElement;
            const applyAllCb   = document.getElementById("conflict-apply-all") as HTMLInputElement;
            const renameInput  = document.getElementById("conflict-rename-input") as HTMLInputElement;
            const btnOverwrite = document.getElementById("conflict-btn-overwrite")!;
            const btnRename    = document.getElementById("conflict-btn-rename")!;
            const btnSkip      = document.getElementById("conflict-btn-skip")!;

            // Fill in the conflicting file path and pre-populate the rename input
            filenameEl.textContent = destPath;
            const basename = destPath.includes("/")
                ? destPath.slice(destPath.lastIndexOf("/") + 1)
                : destPath;
            renameInput.value = basename;

            // Show "Apply to all" only when there are multiple conflicts
            applyAllRow.classList.toggle("hidden", !hasMore);
            applyAllCb.checked = false;

            overlay.classList.remove("hidden");
            renameInput.focus();
            renameInput.select();

            const finish = (action: "overwrite" | "skip" | "rename", newName?: string) => {
                ctrl.abort();
                overlay.classList.add("hidden");
                const applyAll = action !== "rename" && applyAllCb.checked;
                resolve({ action, newName, applyAll });
            };

            btnOverwrite.addEventListener("click", () => finish("overwrite"), { signal });
            btnSkip.addEventListener("click",      () => finish("skip"),      { signal });
            btnRename.addEventListener("click", () => {
                const newName = renameInput.value.trim();
                finish("rename", newName || basename);
            }, { signal });
            renameInput.addEventListener("keydown", (e: KeyboardEvent) => {
                if (e.key === "Enter") {
                    const newName = renameInput.value.trim();
                    finish("rename", newName || basename);
                } else if (e.key === "Escape") {
                    finish("skip");
                }
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
                "extract":   ["Archive (.it / .pack)", "Output folder"],
                "pack":      ["Source folder",         "Output archive (.it)"],
                "differ":    ["Base archive (.it)",    "Modified archive (.it)"],
                "merge":     ["Source folder",         "Output archive (.it)"],
                "apply-mod": [".mod file path",        "Target archive (.it)"],
            };
            const [h1, h2] = hints[type] ?? ["Input path", "Output path"];
            if (inp) inp.placeholder = h1;
            if (out) out.placeholder = h2;
        };
        const typeSelect = document.getElementById("jobs-type-select") as HTMLSelectElement;
        typeSelect?.addEventListener("change", () => updateJobHints(typeSelect.value));
        updateJobHints(typeSelect?.value ?? "extract");

        document.getElementById("btn-jobs-browse-input")?.addEventListener("click", async () => {
            const { open } = await import("./platform/dialog");
            const type = (document.getElementById("jobs-type-select") as HTMLSelectElement).value;
            const archiveFilter = { name: "Archives", extensions: ["it", "pack"] };
            const modFilter = { name: "Mod files", extensions: ["mod"] };
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
                path = await save({ filters: [{ name: "Archives", extensions: ["it"] }] });
            } else if (type === "differ") {
                path = await save({ filters: [{ name: "Patch", extensions: ["patch"] }] });
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

        this.log(`[Jobs] Added ${type} job: ${input} → ${output}`, "info");
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
        this.updateJobUI(job, "running", 0, "Starting…");

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
            this.updateJobUI(job, "done", 100, "Completed");
            row.className = "job-row done";
            this.log(`[Jobs] ${job.type} completed: ${job.input}`, "info");
        } catch (e: any) {
            job.status = "error";
            this.updateJobUI(job, "error", 0, `Error: ${e}`);
            row.className = "job-row error";
            this.log(`[Jobs] ${job.type} failed: ${e}`, "error");
        }
    }

    private updateJobUI(job: JobEntry, status: string, pct: number, log: string) {
        const statusEl = document.getElementById(`job-status-${job.id}`);
        const progEl = document.getElementById(`job-prog-${job.id}`);
        const logEl = document.getElementById(`job-log-${job.id}`);
        if (statusEl) statusEl.textContent = status;
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
        this.log(`[Jobs] Running all: ${pending.length} pending job(s)`, "info");
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
            const file = await open({ filters: [{ name: "Archives", extensions: ["it", "pack"] }] });
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
        if (!archive) { this.setFeaturesStatus("Please select an archive", "error"); return; }

        this.setFeaturesStatus("Loading…", "busy");
        const btn = document.getElementById("btn-features-load") as HTMLButtonElement;
        btn.disabled = true;

        this.log(`[Features] Loading features from: ${archive}`, "info");
        try {
            const data = await invoke("get_features_from_archive", { archive, key }) as any;
            this.featuresData = data;
            this.featuresModified = false;
            this.renderFeatures();
            this.setFeaturesStatus(`Loaded ${data.features.length} features, ${data.servers.length} servers`, "ok");
            this.log(`[Features] Loaded ${data.features.length} features, ${data.servers.length} servers`, "info");
            document.getElementById("btn-features-save")?.classList.remove("hidden");
        } catch (e: any) {
            this.setFeaturesStatus(`Load failed: ${e}`, "error");
            this.log(`[Features] Load failed: ${e}`, "error");
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

        this.log(`[Features] Saving features to: ${archive}`, "info");
        this.setFeaturesStatus("Saving…", "busy");
        const btn = document.getElementById("btn-features-save") as HTMLButtonElement;
        btn.disabled = true;

        try {
            const result = await invoke("save_features_to_archive", {
                archive,
                key,
                featuresJson: JSON.stringify(this.featuresData),
            }) as any;
            this.featuresModified = false;
            this.setFeaturesStatus(`Saved — ${result.features} features, ${result.bytes} bytes`, "ok");
            this.log(`[Features] Saved — ${result.features} features, ${result.bytes} bytes`, "info");
        } catch (e: any) {
            this.setFeaturesStatus(`Save failed: ${e}`, "error");
            this.log(`[Features] Save failed: ${e}`, "error");
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
            row.innerHTML = `<span>ID ${s.server_id}</span><b>${s.name}</b><span>${s.region}</span><span>ch ${s.channel}</span>`;
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

            const condsDiv = document.createElement("div");
            condsDiv.className = "feature-conds";

            if (f.conditions.length === 0) {
                const empty = document.createElement("span");
                empty.style.cssText = "opacity:.3;font-size:11px;";
                empty.textContent = "(no conditions)";
                condsDiv.appendChild(empty);
            } else {
                for (let ci = 0; ci < f.conditions.length; ci++) {
                    const cond = f.conditions[ci];
                    if (!cond) continue;
                    const tag = document.createElement("span");
                    tag.className = "feature-cond-tag";
                    tag.textContent = cond;
                    tag.title = `Click to toggle condition at index ${ci}`;
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

    private launcherSession: { access_token: string; g_access_token: string; session_token: string; hashed_user_id: string } | null = null;
    private readonly LAUNCHER_SESSION_KEY = "nexon_session";
    private launcherProfiles: any[] = [];
    private activeProfileId: string | null = null;
    private activeProfileLoginIp: string = "";
    private activeProfileLoginPort: number = 0;
    private activeProfileIsOfficial: boolean = true;
    private profileEditorMode: "new" | "edit" | null = null;
    private workerBars: Map<number, HTMLElement> = new Map();
    private kananMods: Array<{ name: string; enabled: boolean }> = [];

    private setupLauncher() {
        // Restore session from localStorage (fallback when no profiles)
        const saved = localStorage.getItem(this.LAUNCHER_SESSION_KEY);
        if (saved) {
            try {
                this.launcherSession = JSON.parse(saved);
                this.updateLauncherUI(true);
                this.fetchLauncherVersion();
            } catch { localStorage.removeItem(this.LAUNCHER_SESSION_KEY); }
        }

        // Load profiles from backend
        this.loadProfiles();

        // Login / logout / launch
        document.getElementById("btn-launcher-login")?.addEventListener("click", () => this.launcherDoLogin());
        document.getElementById("btn-launcher-logout")?.addEventListener("click", () => this.launcherDoLogout());
        document.getElementById("btn-launcher-launch")?.addEventListener("click", () => this.launcherDoLaunch());
        document.getElementById("btn-launcher-import-session")?.addEventListener("click", () => this.launcherImportSession());

        document.getElementById("btn-launcher-check-update")?.addEventListener("click", async () => {
            const statusEl = document.getElementById("launcher-update-status")!;
            statusEl.textContent = "Checking...";
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
                        statusEl.textContent = `Version ${info.cached_version}R — Update available!`;
                        statusEl.className = "launcher-update-status error";
                        this.log(`[Launcher] Version check: ${info.cached_version}R — update available`, "warn");
                    } else if (info.update_available === false) {
                        statusEl.textContent = `Version ${info.cached_version}R — Up to date`;
                        statusEl.className = "launcher-update-status up-to-date";
                        this.log(`[Launcher] Version check: ${info.cached_version}R — up to date`, "info");
                    } else {
                        statusEl.textContent = `Version ${info.cached_version}R (cached)`;
                        statusEl.className = "launcher-update-status up-to-date";
                        this.log(`[Launcher] Version check: ${info.cached_version}R (cached, no local comparison)`, "info");
                    }
                } else {
                    statusEl.textContent = "Version info not found — open Nexon Launcher once to cache it";
                    statusEl.className = "launcher-update-status error";
                    this.log("[Launcher] Version check: no cached version found", "warn");
                }
            } catch (e) {
                statusEl.textContent = "Check failed: " + e;
                statusEl.className = "launcher-update-status error";
                this.log(`[Launcher] Version check failed: ${e}`, "error");
            }
        });

        // Profile selector change (Settings > Launcher sub-tab)
        document.getElementById("launcher-profile-select")?.addEventListener("change", (e) => {
            const id = (e.target as HTMLSelectElement).value;
            this.selectProfile(id);
        });

        // Profile quick-select on main Launcher page
        document.getElementById("launcher-page-profile-select")?.addEventListener("change", (e) => {
            const id = (e.target as HTMLSelectElement).value;
            this.selectProfile(id);
            // Mirror selection to settings dropdown
            const settingsSel = document.getElementById("launcher-profile-select") as HTMLSelectElement;
            if (settingsSel) settingsSel.value = id;
        });
        document.getElementById("btn-launcher-manage-profiles")?.addEventListener("click", () => {
            // Navigate to Settings > Launcher sub-tab
            document.getElementById("tab-settings")?.click();
            setTimeout(() => {
                (document.querySelector("[data-stab='launcher']") as HTMLElement)?.click();
            }, 50);
        });

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

        // Kanan mods
        const kananPathEl = document.getElementById("kanan-cfg-path") as HTMLInputElement;
        if (this.config.kanan_cfg_path) {
            kananPathEl.value = this.config.kanan_cfg_path;
            this.loadKananMods(this.config.kanan_cfg_path);
        }

        document.getElementById("btn-kanan-browse")?.addEventListener("click", async () => {
            const { open } = await import("./platform/dialog");
            const file = await open({
                filters: [{ name: "Loader Config", extensions: ["cfg"] }],
                title: "Select Kanan Loader.cfg"
            });
            if (file && !Array.isArray(file)) {
                const p = file as string;
                kananPathEl.value = p;
                this.config.kanan_cfg_path = p;
                await invoke("set_config", { config: this.config });
                await this.loadKananMods(p);
            }
        });

        document.getElementById("btn-kanan-save")?.addEventListener("click", () => this.saveKananMods());
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

            if (active) {
                this.applyProfileToUI(active);
                if (active.auto_login && active.session_valid) {
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
                sel.innerHTML = "<option value=''>— No profiles saved —</option>";
                continue;
            }
            for (const p of this.launcherProfiles) {
                const opt = document.createElement("option");
                opt.value = p.id;
                const sessionBadge = p.session_valid ? " ✓" : p.has_session ? " ⚠" : "";
                const typeBadge = p.profile_type && p.profile_type !== "nexon" ? ` [${p.profile_type}]` : "";
                const emailPart = p.email ? ` (${p.email})` : "";
                opt.textContent = `${p.name}${emailPart}${typeBadge}${sessionBadge}`;
                if (p.id === this.activeProfileId) opt.selected = true;
                sel.appendChild(opt);
            }
        }
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
                badge.textContent = `Custom server: ${profile.login_ip}:${profile.login_port || 11000} — ${profile.client_dir || "no game dir"}`;
            } else {
                const dir = profile.client_dir ? ` — ${profile.client_dir}` : "";
                badge.textContent = `Official Nexon NA${dir}`;
            }
        }
    }

    private async selectProfile(id: string) {
        this.activeProfileId = id;
        const profile = this.launcherProfiles.find(p => p.id === id);
        if (!profile) return;
        this.applyProfileToUI(profile);
        try { await invoke("launcher_set_active_profile", { id }); } catch {}
        if (profile.auto_login && profile.session_valid) {
            await this.autologinProfile(id);
        }
    }

    private async autologinProfile(profileId: string) {
        this.log(`[Launcher] Auto-login attempt for profile: ${profileId}`, "info");
        try {
            const data = await invoke("launcher_load_profile", { id: profileId }) as any;
            const token = data.session_token_for_autologin;
            if (!token) { this.log("[Launcher] Auto-login: no saved session token", "warn"); return; }
            this.setLauncherStatus("Auto-logging in…", "busy");
            const result = await invoke("launcher_autologin", { sessionToken: token }) as any;
            this.launcherSession = result.session;
            this.updateLauncherUI(true);
            this.setLauncherStatus("Auto-logged in", "ok");
            this.log("[Launcher] Auto-login successful", "info");
            this.fetchLauncherVersion();
            // Update session expiry in profile
            await invoke("launcher_update_profile_session", {
                id: profileId,
                sessionToken: result.session.session_token,
                expiresIn: result.expiresIn || 86400,
            }).catch(() => {});
        } catch (e: any) {
            this.setLauncherStatus(`Auto-login failed: ${e}`, "error");
            this.log(`[Launcher] Auto-login failed: ${e}`, "error");
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

        if (!name) { this.setLauncherStatus("Profile name is required", "error"); return; }

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
            this.setLauncherStatus(`Profile "${name}" saved`, "ok");
            this.log(`[Launcher] Profile "${name}" saved`, "info");
        } catch (e: any) {
            this.setLauncherStatus(`Save failed: ${e}`, "error");
            this.log(`[Launcher] Profile save failed: ${e}`, "error");
        }
    }

    private async detectLauncherProfiles() {
        const statusEl = document.getElementById("profile-detect-status");
        const areaEl = document.getElementById("detected-profiles-area");
        const listEl = document.getElementById("detected-profiles-list");
        if (statusEl) statusEl.textContent = "Scanning…";
        this.log("[Launcher] Scanning for installed launchers...", "info");
        try {
            const detected = await invoke("detect_launcher_profiles") as Array<{
                source: string; name: string; client_dir: string;
                login_ip: string; login_port: number;
                chat_ip: string; chat_port: number;
                is_official: boolean;
            }>;
            if (!detected || detected.length === 0) {
                if (statusEl) statusEl.textContent = "No launchers detected";
                if (areaEl) areaEl.style.display = "none";
                this.log("[Launcher] No launchers detected", "warn");
                return;
            }
            if (statusEl) statusEl.textContent = `Found ${detected.length} launcher(s)`;
            this.log(`[Launcher] Detected ${detected.length} launcher(s): ${detected.map(d => d.name).join(", ")}`, "info");
            if (areaEl) areaEl.style.display = "block";
            if (listEl) {
                listEl.innerHTML = "";
                for (const d of detected) {
                    const row = document.createElement("div");
                    row.style.cssText = "display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border-glass)";
                    const badge = d.is_official ? "OFFICIAL" : d.source.toUpperCase();
                    const info = d.is_official
                        ? `${d.name}${d.client_dir ? " — " + d.client_dir : ""}`
                        : `${d.name}${d.login_ip ? " — " + d.login_ip + ":" + d.login_port : ""}`;
                    const alreadyImported = this.launcherProfiles.some(
                        p => p.name === d.name && p.profile_type === d.source
                    );
                    row.innerHTML = `
                        <span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px;background:var(--accent-cyan);color:#000">${badge}</span>
                        <span style="flex:1;font-size:12px">${info}</span>
                        <button class="tab-btn" style="font-size:11px;padding:2px 8px" ${alreadyImported ? "disabled" : ""}>${alreadyImported ? "Imported ✓" : "Import"}</button>
                    `;
                    const importBtn = row.querySelector("button")!;
                    const detected_copy = d;
                    importBtn.addEventListener("click", async () => {
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
                            importBtn.textContent = "Imported!";
                            importBtn.disabled = true;
                            this.log(`[Launcher] Imported profile: ${detected_copy.name}`, "info");
                        } catch (e: any) {
                            importBtn.textContent = "Error";
                            this.log(`[Launcher] Profile import failed: ${e}`, "error");
                        }
                    });
                    listEl.appendChild(row);
                }
            }
        } catch (e: any) {
            if (statusEl) statusEl.textContent = `Detection failed: ${e}`;
            this.log(`[Launcher] Profile detection failed: ${e}`, "error");
        }
    }

    private async deleteActiveProfile() {
        if (!this.activeProfileId) return;
        const profile = this.launcherProfiles.find(p => p.id === this.activeProfileId);
        if (!profile) return;
        if (!confirm(`Delete profile "${profile.name}"?`)) return;
        const profileName = profile.name;
        try {
            await invoke("launcher_delete_profile", { id: this.activeProfileId });
            this.activeProfileId = null;
            await this.loadProfiles();
            this.setLauncherStatus("Profile deleted", "idle");
            this.log(`[Launcher] Deleted profile: ${profileName}`, "info");
        } catch (e: any) {
            this.setLauncherStatus(`Delete failed: ${e}`, "error");
            this.log(`[Launcher] Profile delete failed: ${e}`, "error");
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
                this.setLauncherStatus("Saved to profile", "ok");
                this.log("[Launcher] Saved current session to active profile", "info");
            } catch (e: any) {
                this.setLauncherStatus(`Save failed: ${e}`, "error");
                this.log(`[Launcher] Save to profile failed: ${e}`, "error");
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
        if (!email || !password) { this.setLauncherStatus("Email and password required", "error"); return; }

        const btn = document.getElementById("btn-launcher-login") as HTMLButtonElement;
        btn.disabled = true;
        this.setLauncherStatus("Logging in…", "busy");

        try {
            const result = await invoke("launcher_login", { username: email, password, remember: rememberEl.checked }) as any;
            this.launcherSession = result.session;
            if (rememberEl.checked) {
                localStorage.setItem(this.LAUNCHER_SESSION_KEY, JSON.stringify(this.launcherSession));
                // Save session to active profile
                if (this.activeProfileId && result.session.session_token) {
                    await invoke("launcher_update_profile_session", {
                        id: this.activeProfileId,
                        sessionToken: result.session.session_token,
                        expiresIn: result.expiresIn || 86400,
                    }).catch(() => {});
                    await this.loadProfiles();
                }
            }
            pwEl.value = "";
            this.updateLauncherUI(true);
            this.setLauncherStatus("Logged in", "ok");
            this.log(`[Launcher] Logged in as ${email}`, "info");
            this.fetchLauncherVersion();
        } catch (e: any) {
            this.setLauncherStatus(`Login failed: ${e}`, "error");
            this.log(`[Launcher] Login failed: ${e}`, "error");
        } finally {
            btn.disabled = false;
        }
    }

    private launcherDoLogout() {
        this.launcherSession = null;
        localStorage.removeItem(this.LAUNCHER_SESSION_KEY);
        this.updateLauncherUI(false);
        this.setLauncherStatus("Not logged in", "idle");
        this.log("[Launcher] Logged out", "info");
        (document.getElementById("launcher-version-value") as HTMLElement).textContent = "—";
        (document.getElementById("launcher-maintenance-value") as HTMLElement).textContent = "—";
    }

    private async launcherImportSession() {
        const btn = document.getElementById("btn-launcher-import-session") as HTMLButtonElement;
        if (btn) btn.disabled = true;
        this.setLauncherStatus("Importing session from Nexon Launcher...", "busy");
        try {
            const result = await invoke("launcher_import_session") as { session: any };
            this.launcherSession = result.session;
            localStorage.setItem(this.LAUNCHER_SESSION_KEY, JSON.stringify(this.launcherSession));
            this.updateLauncherUI(true);
            this.setLauncherStatus("Session imported from Nexon Launcher", "ok");
            this.log("[Launcher] Session imported from Nexon Launcher", "info");
            this.fetchLauncherVersion();
        } catch (e) {
            this.setLauncherStatus(`Import failed: ${e}`, "error");
            this.log(`[Launcher] Session import failed: ${e}`, "error");
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    private async launcherDoLaunch() {
        const isCustomServer = !this.activeProfileIsOfficial;
        if (!isCustomServer && !this.launcherSession) {
            this.setLauncherStatus("Please log in first (or import a custom server profile)", "error");
            return;
        }
        const clientDir = (document.getElementById("launcher-client-dir") as HTMLInputElement).value.trim();
        if (!clientDir) { this.setLauncherStatus("Mabinogi folder is required", "error"); return; }

        const btn = document.getElementById("btn-launcher-launch") as HTMLButtonElement;
        btn.disabled = true;
        this.setLauncherStatus("Launching…", "busy");

        const preLaunchCmd = (document.getElementById("pre-launch-cmd") as HTMLTextAreaElement)?.value?.trim() || "";
        const postLaunchCmd = (document.getElementById("post-launch-cmd") as HTMLTextAreaElement)?.value?.trim() || "";
        const launchCmdOverride = (document.getElementById("launch-cmd-override") as HTMLTextAreaElement)?.value?.trim() || "";
        const useNexonLauncher = (document.getElementById("launch-use-nexon-launcher") as HTMLInputElement)?.checked ?? false;

        this.log(`[Launcher] Launching Mabinogi from: ${clientDir}${isCustomServer ? ` (custom server: ${this.activeProfileLoginIp})` : ""}`, "info");
        if (preLaunchCmd) this.log(`[Launcher] Pre-launch: ${preLaunchCmd}`, "info");

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
            }) as any;
            const result = document.getElementById("launcher-launch-result")!;
            result.textContent = `Launched ${r.executable} (${r.argumentCount} args)${r.patchAvailable ? " — update available" : ""}`;
            result.className = "launcher-launch-result success";
            result.classList.remove("hidden");
            this.setLauncherStatus("Mabinogi launched!", "ok");
            this.log(`[Launcher] Mabinogi launched: ${r.executable} (${r.argumentCount} args)`, "info");
            if (postLaunchCmd) this.log(`[Launcher] Post-launch: ${postLaunchCmd}`, "info");
        } catch (e: any) {
            const result = document.getElementById("launcher-launch-result")!;
            result.textContent = `Launch failed: ${e}`;
            result.className = "launcher-launch-result error";
            result.classList.remove("hidden");
            this.setLauncherStatus(`Launch error: ${e}`, "error");
            this.log(`[Launcher] Launch failed: ${e}`, "error");
        } finally {
            btn.disabled = false;
        }
    }

    private async fetchLauncherVersion() {
        if (!this.launcherSession) return;
        try {
            const ver = await invoke("launcher_get_version", { session: this.launcherSession }) as number;
            const verStr = ver > 0 ? String(ver) : "—";
            (document.getElementById("launcher-version-value") as HTMLElement).textContent = verStr;
            const maint = await invoke("launcher_check_maintenance", { session: this.launcherSession }) as boolean;
            (document.getElementById("launcher-maintenance-value") as HTMLElement).textContent = maint ? "Yes" : "No";
            this.log(`[Launcher] Game version: ${verStr}, maintenance: ${maint}`, "info");
        } catch (e) {
            this.log(`[Launcher] Version check failed (non-critical): ${e}`, "warn");
        }
    }

    private updateLauncherUI(loggedIn: boolean) {
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

    private async loadKananMods(path: string) {
        const listEl = document.getElementById("kanan-mods-list")!;
        const saveBtn = document.getElementById("btn-kanan-save")!;
        const statusEl = document.getElementById("kanan-status")!;
        if (!listEl) return;

        try {
            this.kananMods = await invoke("read_kanan_cfg", { path }) as Array<{ name: string; enabled: boolean }>;
            listEl.innerHTML = "";
            if (this.kananMods.length === 0) {
                listEl.innerHTML = "<div style='opacity:.6;font-size:12px;padding:6px 0;'>No mods found in Loader.cfg</div>";
                saveBtn?.classList.add("hidden");
                return;
            }
            for (let i = 0; i < this.kananMods.length; i++) {
                const mod = this.kananMods[i];
                const row = document.createElement("div");
                row.className = "sys-stat";
                row.style.cssText = "padding:4px 0;min-height:unset;";
                const lbl = document.createElement("span");
                lbl.style.cssText = "flex:1;font-size:12px;";
                lbl.textContent = mod.name;
                const sw = document.createElement("label");
                sw.className = "switch";
                const cb = document.createElement("input");
                cb.type = "checkbox";
                cb.checked = mod.enabled;
                cb.dataset.kananIdx = String(i);
                cb.addEventListener("change", (e) => {
                    const idx = parseInt((e.target as HTMLInputElement).dataset.kananIdx ?? "0");
                    this.kananMods[idx].enabled = (e.target as HTMLInputElement).checked;
                });
                const slider = document.createElement("span");
                slider.className = "slider";
                sw.appendChild(cb);
                sw.appendChild(slider);
                row.appendChild(lbl);
                row.appendChild(sw);
                listEl.appendChild(row);
            }
            saveBtn?.classList.remove("hidden");
            statusEl?.classList.add("hidden");
        } catch (e: any) {
            listEl.innerHTML = `<div style='color:var(--accent-warn,#f90);font-size:12px;padding:6px 0;'>Failed to read: ${e}</div>`;
            saveBtn?.classList.add("hidden");
        }
    }

    private async saveKananMods() {
        const path = this.config.kanan_cfg_path;
        if (!path) return;
        const statusEl = document.getElementById("kanan-status")!;
        this.log(`[Kanan] Saving mods to: ${path}`, "info");
        try {
            await invoke("write_kanan_cfg", { path, mods: this.kananMods });
            if (statusEl) {
                statusEl.textContent = "Saved!";
                statusEl.style.color = "var(--green, #4ade80)";
                statusEl.classList.remove("hidden");
                setTimeout(() => statusEl.classList.add("hidden"), 2000);
            }
            this.log(`[Kanan] Saved ${this.kananMods.length} mod(s)`, "info");
        } catch (e: any) {
            if (statusEl) {
                statusEl.textContent = `Save failed: ${e}`;
                statusEl.style.color = "var(--accent-warn,#f90)";
                statusEl.classList.remove("hidden");
            }
            this.log(`[Kanan] Save failed: ${e}`, "error");
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

    private setup3dPreviewResize() {
        const handle = document.getElementById("preview-3d-resize-handle");
        const viewport = document.getElementById("three-viewport");
        if (!handle || !viewport) return;

        const saved = localStorage.getItem("preview-3d-height");
        if (saved) { viewport.style.height = `${saved}px`; viewport.style.minHeight = `${saved}px`; }

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
            const newH = Math.max(150, startH + delta);
            viewport.style.height = `${newH}px`;
            viewport.style.minHeight = `${newH}px`;
            // Notify three.js of resize if renderer is registered
            (window as any).__threeResizeFn?.();
        });
        document.addEventListener("mouseup", () => {
            if (!dragging) return;
            dragging = false;
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
            localStorage.setItem("preview-3d-height", String(Math.round(viewport.getBoundingClientRect().height)));
        });
    }

    private setupForms() {
        // Browse Buttons
        document.getElementById("btn-browse-extract-in")?.addEventListener("click", async () => {
            const isFullSeq = (document.getElementById("extract-full-sequence") as HTMLInputElement).checked;
            const path = isFullSeq
                ? await open({ directory: true })
                : await open({ filters: [{ name: "Mabinogi Archive", extensions: ["it", "pack"] }] });
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
            const path = await save({ filters: [{ name: "Mabinogi Archive", extensions: ["it"] }] });
            if (path) (document.getElementById("pack-output") as HTMLInputElement).value = path;
        });
        document.getElementById("btn-browse-list")?.addEventListener("click", async () => {
            const isFullSeq = (document.getElementById("list-full-sequence") as HTMLInputElement).checked;
            const path = isFullSeq
                ? await open({ directory: true })
                : await open({ filters: [{ name: "Mabinogi Archive", extensions: ["it", "pack"] }] });
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
            const path = await save({ filters: [{ name: "Mabinogi Archive", extensions: ["it"] }] });
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
                this.log("Registry associations updated.", "success");
            } catch (e) { this.log(`Registry error: ${e}`, "error"); }
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

        document.getElementById("settings-portable-mode")?.addEventListener("change", async (e) => {
            const enable = (e.target as HTMLInputElement).checked;
            try {
                await invoke("set_portable_mode", { enable });
                await refreshConfigPath();
            } catch (err) {
                alert("Failed to switch config location: " + err);
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
            await message(this.t("msg_task_running"), { title: "Task In Progress", kind: "warning" });
            return;
        }
        const input = (document.getElementById("extract-input") as HTMLInputElement).value;
        const output = (document.getElementById("extract-output") as HTMLInputElement).value;
        const key = (document.getElementById("extract-key") as HTMLInputElement).value || null;
        const filterStr = (document.getElementById("extract-filters") as HTMLInputElement).value;
        const filters = filterStr.split(',').map(f => f.trim()).filter(f => f.length > 0);

        if (!input || !output) {
            await message("Please select both an Input Archive and an Output Directory.", { title: "Missing Required Fields", kind: "error" });
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
            this.log(`Error: ${e}`, "error");
        }
    }

    private async runPack() {
        if (this._taskStartTime !== null) {
            await message(this.t("msg_task_running"), { title: "Task In Progress", kind: "warning" });
            return;
        }
        const input = (document.getElementById("pack-input") as HTMLInputElement).value;
        const output = (document.getElementById("pack-output") as HTMLInputElement).value;
        const key = (document.getElementById("pack-key") as HTMLInputElement).value;
        const formatsStr = (document.getElementById("pack-formats") as HTMLInputElement).value;
        const formats = formatsStr.split(',').map(f => f.trim()).filter(f => f.length > 0);
        const ivVal = parseInt((document.getElementById("pack-iv") as HTMLInputElement).value) || 0;

        if (!input || !output || !key) {
            await message("Please select a Source Folder, Output Archive path, and an Encryption Salt.", { title: "Missing Required Fields", kind: "error" });
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
            this.log(`Error: ${e}`, "error");
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

        this.updateProgress(0, "Loading...", true);
        let res: PackListResponse;
        try {
            if (isFullSeq) {
                // If input is a file, get parent directory; if it's already a directory, use it directly
                const isFile = input.toLowerCase().endsWith(".it") || input.toLowerCase().endsWith(".pack");
                const lastIdx = Math.max(input.lastIndexOf("/"), input.lastIndexOf("\\"));
                const dir = isFile ? (lastIdx !== -1 ? input.substring(0, lastIdx) : ".") : input;
                this.log(`Loading full sequence from: ${dir}...`);
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
                    this.log(`[VFS] Restored ${saved.length} deferred pending change(s).`, "info");
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
            this.log(`Error: ${e}`, "error");
        }
    }
    private async runDiffer() {
        const base = (document.getElementById("differ-old") as HTMLInputElement).value;
        const modified = (document.getElementById("differ-new") as HTMLInputElement).value;
        const output = (document.getElementById("differ-output") as HTMLInputElement).value;
        const key = (document.getElementById("differ-key") as HTMLInputElement).value;

        if (!base || !modified || !output || !key) {
            await message("Please select Original, Modified, and Output paths, and an Encryption Salt.", { title: "Missing Required Fields", kind: "error" });
            return;
        }

        try {
            await invoke("create_patch", { base, modified, output, key });
            this.log(this.t("diff_success", [output]), "success");
        } catch (e) { this.log(`Error: ${e}`, "error"); }
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
                    this.log(`Extracted: ${dest}`, "success");
                } catch(e) { this.log(`Error: ${e}`, "error"); }
            }
        };

        copyNameBtn.onclick = () => {
            navigator.clipboard.writeText(entry.name);
            this.log("Name copied to clipboard.");
        };
        copyKeyBtn.onclick = () => {
            navigator.clipboard.writeText(entry.salt_used);
            this.log("Salt copied to clipboard.");
        };

        // Rename / Delete — only when archive is loaded in edit mode
        const canEdit = !!this.currentArchive;
        renameDiv.style.display  = canEdit ? "block" : "none";
        renameBtn.style.display  = canEdit ? "block" : "none";
        deleteBtn.style.display  = canEdit ? "block" : "none";

        renameBtn.onclick = () => {
            const newName = prompt("New path (relative to archive root):", entry.name);
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
                    this.log(`Converted to PNG: ${out}`, "success");
                }
            } catch(e) { this.log(`Failed: ${e}`, "error"); }
        };

        convDdsBtn.onclick = async () => {
            try {
                const out = await save({ defaultPath: entry.name.replace(/\.png$/i, ".dds") });
                if (out) {
                    await invoke("run_convert", { input: entry.source_archive, output: out, key: entry.salt_used, wrapData: false });
                    this.log(`Converted to DDS: ${out}`, "success");
                }
            } catch(e) { this.log(`Failed: ${e}`, "error"); }
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
                    this.log(`Decompiled to XML: ${out}`, "success");
                }
            } catch(e) { this.log(`Decompile failed: ${e}`, "error"); }
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
                    this.log(`Exported OBJ: ${out}`, "success");
                }
            } catch(e) { this.log(`OBJ export failed: ${e}`, "error"); }
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
            <button id="mml-play-btn" style="padding:3px 13px;background:var(--accent-cyan,#4dd9e4);color:#000;border:none;border-radius:3px;cursor:pointer;font-size:12px;font-weight:600">&#9654; Play</button>
            <button id="mml-stop-btn" style="padding:3px 13px;background:var(--bg2,#1e2028);color:var(--text,#ccc);border:1px solid var(--border,#333);border-radius:3px;cursor:pointer;font-size:12px" disabled>&#9632; Stop</button>
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
            if (statusEl) statusEl.textContent = "Stopped";
        };

        stopBtn.onclick = doStop;

        playBtn.onclick = () => {
            doStop();
            this._mmlStopFlag = false;
            playBtn.disabled = true;
            stopBtn.disabled = false;
            if (statusEl) statusEl.textContent = "Playing…";

            // Use only the first channel (before the first comma)
            const channel = mml.split(",")[0].replace(/\s+/g, "").toUpperCase();
            const events = this.parseMmlChannel(channel);
            if (events.length === 0) {
                if (statusEl) statusEl.textContent = "No notes found";
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
                if (!this._mmlStopFlag && statusEl) statusEl.textContent = "Done";
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

    private async applyPreviewToPanel(prev: PreviewData): Promise<void> {
        const visual = document.getElementById("preview-visual")!;
        const hex = document.getElementById("preview-hex")!;
        const details = document.getElementById("preview-details")!;
        const audio = document.getElementById("preview-audio")!;
        const threed = document.getElementById("preview-3d")!;

        if (this.pmgViewer) { this.pmgViewer.dispose(); this.pmgViewer = undefined; (window as any).__threeResizeFn = undefined; }
        this._mmlStopFlag = true;
        if (this._mmlAudioCtx) { this._mmlAudioCtx.close().catch(() => {}); this._mmlAudioCtx = null; }
        [visual, hex, details, audio, threed].forEach(el => el.classList.remove("active"));

        let activeContainer = "preview-visual";
        const ext = prev.name.toLowerCase().split('.').pop() || "";

        if (prev.file_type === "error") {
            visual.textContent = prev.content_text || "Image decode failed.";
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
                    ? `${prev.name}  [first 8 MB of ${(prev.full_preview_size / 1048576).toFixed(1)} MB]`
                    : prev.name;
                if (msgEl) msgEl.textContent = "";
                if (this.config.audio_autoplay) audioElem.play().catch(() => {});
            }
        } else if (ext === "pmg") {
            threed.classList.add("active");
            activeContainer = "preview-3d";
            const cont = document.getElementById("three-viewport")!;
            const infoEl = document.getElementById("pmg-info")!;
            const { createPMGViewer } = await import("./pmgLoader");
            this.pmgViewer = createPMGViewer(cont, prev.pmg_geometry);
            (window as any).__threeResizeFn = () => this.pmgViewer?.resize();
            if (prev.pmg_geometry) {
                const g = prev.pmg_geometry;
                this.log(`[PMG] ${g.mesh_name || prev.name}  ·  ${g.vertex_count} verts  ${g.face_count} faces`);
                infoEl.textContent = "";
            } else {
                this.log(`[PMG] ${prev.name}  ·  no geometry (empty placeholder)`);
                infoEl.textContent = "No geometry (empty placeholder)";
                infoEl.style.color = "var(--text-muted)";
            }
            visual.textContent = this.t("preview_no_visual");
            visual.className = "preview-tab-content";
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

                this.log(`[RGN] ${prev.name}  ·  v${version}  ·  region ${region_id}  ·  ${area_count} areas  ·  ${width}×${height} px`);
                rgnInfo.textContent = `v${version}  ·  region ${region_id}  ·  ${area_count} area${area_count !== 1 ? "s" : ""}  ·  ${width}×${height} px (displayed ${dw}×${dh})`;
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
                ctx.fillText(prev.content_text || "RGN parse failed", 128, 128);
                rgnInfo.textContent = prev.content_text || "Could not parse .rgn – see Hex View";
                this.log(`[RGN] ${prev.name}: ${prev.content_text || "parse failed"}`, "warn");
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
                    <div style="margin-top:8px">${[8,12,16,20,24,32,48].map(sz => `<div style="margin-bottom:6px;font-size:${sz}px;font-family:'${fontFamily}',sans-serif">${sz}px &mdash; The quick brown fox jumps over the lazy dog 0123456789</div>`).join("")}</div>
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
                ctx.fillText("Empty .area file", 256, 256);
                areaInfo.textContent = "0 bytes";
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
                    areaInfo.textContent = `${props.length.toLocaleString()} props  ·  X ${minX.toFixed(0)}–${maxX.toFixed(0)}  Z ${minZ.toFixed(0)}–${maxZ.toFixed(0)}  ·  format: ${areaResult.format}`;
                    if (prev.truncated) {
                        areaInfo.textContent += `  ·  (first ${(prev.raw_bytes.length/1024).toFixed(0)} KB of ${(prev.full_preview_size/1024).toFixed(0)} KB)`;
                    }
                } else {
                    // Fallback: unknown format — show message + hex dump of first 32 bytes
                    ctx.fillStyle = "#4a5568";
                    ctx.font = "14px monospace";
                    ctx.textAlign = "center";
                    ctx.fillText("Unknown .area format", 256, 230);
                    const hexPeek = Array.from(prev.raw_bytes.slice(0, 32))
                        .map((b: number) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
                    ctx.fillStyle = "#718096";
                    ctx.font = "10px monospace";
                    const words = hexPeek.match(/.{1,24}/g) || [];
                    words.forEach((w, i) => ctx.fillText(w, 256, 258 + i * 14));
                    areaInfo.textContent = `${prev.raw_bytes.length.toLocaleString()} bytes  ·  no props parsed`;
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
                            Animation: ${h.frame_count} frames, ${h.bone_count} bones, ${h.duration_ms}&thinsp;ms duration
                        </p>
                        <table class="details-table" style="margin-bottom:18px"><tbody>
                            <tr><th>Magic</th><td class="mono">${h.magic}</td></tr>
                            <tr><th>Version</th><td>${h.version}</td></tr>
                            <tr><th>Bone count</th><td>${h.bone_count}</td></tr>
                            <tr><th>Frame count</th><td>${h.frame_count}</td></tr>
                            <tr><th>Duration</th><td>${h.duration_ms} ms</td></tr>
                        </tbody></table>`;
                }
            } catch (_) {
                headerHtml = `<p style="color:var(--text-muted,#718096);margin:0 0 12px">Unknown .set format</p>`;
            }
            if (headerHtml) {
                // Binary .set: show header table + hex dump of first 128 bytes
                const hexBytes = prev.raw_bytes.slice(0, 128);
                const hexStr = hexBytes.map((b: number) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
                visual.innerHTML = `<div style="padding:16px;font-family:monospace;overflow:auto;height:100%;box-sizing:border-box">
                    <div style="font-size:11px;opacity:0.5;margin-bottom:14px">${prev.name} &mdash; ${prev.full_preview_size.toLocaleString()} bytes</div>
                    ${headerHtml}
                    <div style="font-size:10px;opacity:0.5;margin-bottom:6px">First ${Math.min(128, prev.raw_bytes.length)} bytes (hex):</div>
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
                actx.fillText("Empty .anievent file", 256, 45);
                aniInfo.textContent = "0 bytes";
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
                    ).join("") + `&nbsp;&middot;&nbsp;<span style="opacity:0.45;font-size:10px">0=Sound 1=FX 2=Hit 3=Spawn (guessed)</span>`;

                    // Info line
                    const truncNote = prev.truncated
                        ? `  ·  first ${Math.round(prev.raw_bytes.length / 1024)} KB of ${Math.round(prev.full_preview_size / 1024)} KB`
                        : "";
                    aniInfo.textContent = (aniResult.set_name ? `set: "${aniResult.set_name}"  ·  ` : "") +
                        `${aniResult.animation_count} anim${aniResult.animation_count !== 1 ? "s" : ""}  ·  ` +
                        `${aniResult.events.length} events  ·  frames 0–${maxFrame}${truncNote}`;

                    // Table
                    const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    aniTable.innerHTML = `<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px">
                        <thead><tr style="background:var(--bg-panel,#1e293b)">
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">Frame</th>
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">Type</th>
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">Animation</th>
                            <th style="text-align:left;padding:3px 8px;color:var(--text-muted,#888);font-weight:normal;border-bottom:1px solid var(--border,#334155)">Params</th>
                        </tr></thead>
                        <tbody>${evts.slice(0, 500).map(e =>
                            `<tr><td style="padding:2px 8px;color:var(--text,#e2e8f0)">${e.frame}</td>` +
                            `<td style="padding:2px 8px;color:${getAniColor(e.event_type)}">${esc(e.event_type)}</td>` +
                            `<td style="padding:2px 8px;color:var(--text-muted,#888)">${esc(e.anim_name)}</td>` +
                            `<td style="padding:2px 8px;color:var(--text-muted,#888)">${esc(e.params)}</td></tr>`
                        ).join("")}</tbody>
                    </table>${evts.length > 500
                        ? `<div style="padding:6px 8px;font-size:11px;color:var(--text-muted,#888);font-family:monospace">… ${evts.length - 500} more rows</div>`
                        : ""}`;
                } else {
                    // Fallback: show message on canvas
                    actx.fillStyle = "#4a5568";
                    actx.font = "13px monospace";
                    actx.textAlign = "center";
                    actx.fillText("Could not parse .anievent", 256, 36);
                    const hexPeek = Array.from(prev.raw_bytes.slice(0, 48))
                        .map((b: number) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
                    actx.fillStyle = "#64748b";
                    actx.font = "9px monospace";
                    (hexPeek.match(/.{1,24}/g) ?? []).forEach((w, i) => actx.fillText(w, 256, 52 + i * 12));
                    aniInfo.textContent = `${prev.raw_bytes.length.toLocaleString()} bytes  ·  no events parsed`;
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
            hex.textContent = `[ First ${prev.raw_bytes.length} bytes of ${prev.full_preview_size.toLocaleString()} bytes (${kb} KB) ]\n\n${hexDump}`;
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
                    <tr><th>${this.t("preview_extracted")}:</th><td>${prev.size.toLocaleString()} bytes</td></tr>
                    <tr><th>${this.t("preview_compressed")}:</th><td>${prev.raw_size.toLocaleString()} bytes</td></tr>
                    <tr><th>${this.t("preview_offset")}:</th><td class="mono">0x${prev.offset.toString(16).toUpperCase()}</td></tr>
                    <tr><th>${this.t("preview_checksum")}:</th><td class="mono">0x${prev.checksum.toString(16).toUpperCase()}</td></tr>
                    <tr><th>${this.t("preview_flags")}:</th><td class="mono">0x${prev.flags.toString(16).toUpperCase()}</td></tr>
                </tbody></table>`;
    }

    private async selectFile(e: AggregateEntry, div: HTMLElement) {
        this.selectedEntry = e;
        document.querySelectorAll(".tree-item").forEach(i => (i as HTMLElement).style.background = "transparent");
        div.style.background = "color-mix(in srgb, var(--accent-cyan) 20%, transparent)";
        this.log(`Selected: ${e.name}`);

        const visual = document.getElementById("preview-visual")!;
        visual.textContent = this.t("preview_loading");
        visual.className = "preview-tab-content active";

        try {
            const prev = await this.fetchPreview(e);
            await this.applyPreviewToPanel(prev);
        } catch (err) {
            this.log(`Preview error: ${err}`, "error");
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

        try {
            const prev = await invoke("preview_loose_file", { path }) as PreviewData;
            await this.applyPreviewToPanel(prev);
            this.log(`Opened loose file: ${prev.name} (${prev.size.toLocaleString()} bytes)`);
        } catch (err) {
            visual.textContent = `Preview error: ${err}`;
            visual.className = "preview-tab-content active";
            this.log(`Loose file preview error: ${err}`, "error");
        }
    }

    private async extractSelected() {
        if (!this.selectedEntry) {
            await message("Please select a file from the list first.", { title: "No Selection", kind: "error" });
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
                this.log(`Extracted: ${dest}`, "success");
            } catch(e) { this.log(`Error: ${e}`, "error"); }
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
            this.log(`Error: ${e}`, "error");
        }
    }

    private async convertTo(ext: string) {
        if (this._taskStartTime !== null) {
            await message(this.t("msg_task_running"), { title: "Task In Progress", kind: "warning" });
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
                this.log(`Converted to ${ext.toUpperCase()}: ${out}`, "success");
            } catch (e) { this.log(`Error: ${e}`, "error"); }
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
            this.log("Commands: clear, help, logs, salts, status, version, extract <path> <out>, pack <path> <out> <key>");
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
            this.log(`${all.length} salts loaded:\n${all.join('\n')}`);
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
            if (text.startsWith('tooltip_') || text.startsWith('tab_') || text.startsWith('label_')) {
                text = this.t(text) || text;
            }
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
        if (dashLabel) dashLabel.textContent = msg || (percent === 0 ? "Idle" : "");

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
                if (etaMs > 500) parts.push(`ETA: ${this.formatDuration(etaMs)}`);
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

        listen("tauri://drag-drop", (event) => {
            const p = event.payload as any;
            if (p.paths && p.paths.length > 0) {
                const path = p.paths[0];
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
