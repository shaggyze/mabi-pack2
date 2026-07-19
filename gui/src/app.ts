import { invoke } from "@tauri-apps/api/core";
import { open, save, ask, message } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { locales as TRANSLATIONS } from "./locales";
import type { PMGViewer, PmgGeometry } from "./pmgLoader";

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
}

class App {
    private config: Config = {
        theme: "sky-dark",
        locale: "en",
        log_level: "error",
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
        sequence_ignore_list: []
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

        if (!this.config.suppress_admin_warning) {
            const isAdmin = await invoke("is_ran_as_admin");
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
            "btn_unpack", "btn_create", "btn_load", "btn_diff", "btn_admin", "btn_wipe", "logs", "label-list-full-sequence",
            "label_list_auto_expand", "label_list_auto_select",
            "label_select_none", "label_select_first", "label_select_all",
            "ready", "set_conversion",
            "extractSelected", "extractAll", "ctxConvIt", "ctxConvPack",
            "preview_tab_visual", "preview_tab_hex", "preview_tab_details",
            "label_settings_auto_png", "label_settings_auto_dds",
            "label_audio_autoplay", "label_audio_autoplay_inline", "label_audio_loop",
            "ctx_extract", "ctx_copy_name", "ctx_copy_key", "ctx_conv_png", "ctx_conv_dds"
        ];
        ids.forEach(id => {
            document.querySelectorAll<HTMLElement>(`[id="${id}"]`).forEach(el => {
                el.textContent = this.t(id);
            });
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
            ["differ-run", "btn_diff"]
        ];
        runBtnMap.forEach(([id, key]) => {
            const el = document.getElementById(id);
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
        ["dashboard", "extract", "pack", "list", "differ", "settings"].forEach(tab => {
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
            { id: "extract-auto-png", prop: "auto_convert_png" },
            { id: "pack-auto-dds", prop: "auto_convert_dds" },
            { id: "pack-wrap-data", prop: "pack_wrap_data" },
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
            ["settings-lang",            "tooltip_lang"],
            ["settings-theme",           "tooltip_theme"],
            ["settings-log",             "tooltip_log_level"],
            ["btn_admin",                "tooltip_admin"],
            ["btn_wipe",                 "tooltip_wipe"],
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
    }

    private applyTheme() {
        const cls = `theme-${this.config.theme}`;
        document.documentElement.className = cls;
        document.body.className = cls;
        localStorage.setItem("mabi_theme", this.config.theme);
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

        document.getElementById("sidebar-toggle")?.addEventListener("click", () => {
            const sidebar = document.querySelector(".sidebar") as HTMLElement;
            const btn = document.getElementById("sidebar-toggle")!;
            sidebar.classList.toggle("collapsed");
            btn.textContent = sidebar.classList.contains("collapsed") ? "▶" : "◀";
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
            if (path) (document.getElementById("differ-out") as HTMLInputElement).value = path;
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
            { id: "extract-auto-png", prop: "auto_convert_png" },
            { id: "pack-auto-dds", prop: "auto_convert_dds" },
            { id: "pack-wrap-data", prop: "pack_wrap_data" },
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
        const output = (document.getElementById("differ-out") as HTMLInputElement).value;
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

        const extractBtn = document.getElementById("menu-extract")!;
        const copyNameBtn = document.getElementById("menu-copy-name")!;
        const copyKeyBtn = document.getElementById("menu-copy-key")!;
        const convPngBtn = document.getElementById("menu-conv-png")!;
        const convDdsBtn = document.getElementById("menu-conv-dds")!;
        
        const closeMenu = () => {
            menu.style.display = "none";
            document.removeEventListener("click", closeMenu);
        };
        setTimeout(() => document.addEventListener("click", closeMenu), 10);

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

        const isDds = entry.name.toLowerCase().endsWith(".dds");
        const isPng = entry.name.toLowerCase().endsWith(".png");
        convPngBtn.style.display = isDds ? "block" : "none";
        convDdsBtn.style.display = isPng ? "block" : "none";
        
        convPngBtn.onclick = async () => {
            try {
                const out = await save({ defaultPath: entry.name.replace(".dds", ".png") });
                if (out) {
                    await invoke("run_convert", { input: entry.source_archive, output: out, key: entry.salt_used, wrapData: false });
                    this.log(`Converted to PNG: ${out}`, "success");
                }
            } catch(e) { this.log(`Failed: ${e}`, "error"); }
        };

        convDdsBtn.onclick = async () => {
            try {
                const out = await save({ defaultPath: entry.name.replace(".png", ".dds") });
                if (out) {
                    await invoke("run_convert", { input: entry.source_archive, output: out, key: entry.salt_used, wrapData: false });
                    this.log(`Converted to DDS: ${out}`, "success");
                }
            } catch(e) { this.log(`Failed: ${e}`, "error"); }
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

        if (this.pmgViewer) { this.pmgViewer.dispose(); this.pmgViewer = undefined; }
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
        } else if (prev.content_text) {
            const isXml = ext === "xml" || ext === "set" || ext === "csh" || ext === "area" || ext === "rgn" || ext === "compiled";
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
                this.handleAutoInput(p.paths[0]);
            }
        });
    }
}

new App();
