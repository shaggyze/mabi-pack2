export interface Task {
  id: string;
  title: string;
  done: boolean;
  priority: "high" | "medium" | "low";
}

export interface Category {
  id: string;
  title: string;
  icon: string;
  tasks: Task[];
}

export const PLANS: Category[] = [
  {
    id: "vfs",
    title: "Virtual File System",
    icon: "🗂",
    tasks: [
      { id: "vfs-tree-edit",  title: "Virtual tree editing (move files between folders)", done: true,  priority: "high" },
      { id: "vfs-drag-drop",  title: "Drag & drop local files into archive tree",         done: true,  priority: "high" },
      { id: "vfs-merge",      title: "Archive merging (drag .it onto .it in tree)",        done: true,  priority: "high" },
      { id: "vfs-conflict",   title: "Conflict resolution dialog (FileZilla-style)",        done: false, priority: "medium" },
      { id: "vfs-deferred",   title: "Deferred rebuild — pending-changes index",            done: false, priority: "medium" },
    ],
  },
  {
    id: "jobs",
    title: "Job Queue",
    icon: "⚡",
    tasks: [
      { id: "jobs-queue",    title: "Dedicated batch-queue tab for multiple jobs",      done: true,  priority: "high" },
      { id: "jobs-parallel", title: "Parallel job execution with per-job progress",     done: false, priority: "medium" },
      { id: "jobs-eta",      title: "ETA + indeterminate shimmer for list ops",         done: true,  priority: "medium" },
    ],
  },
  {
    id: "preview",
    title: "Preview & Formats",
    icon: "🔭",
    tasks: [
      { id: "preview-pmg",        title: ".pmg 3D viewer (Three.js)",                      done: true,  priority: "high" },
      { id: "preview-dds",        title: ".dds image preview",                              done: true,  priority: "high" },
      { id: "preview-xml",        title: "XML syntax-highlighted viewer",                   done: true,  priority: "high" },
      { id: "preview-audio",      title: "Audio playback (.wav/.mp3/.ogg)",                 done: true,  priority: "medium" },
      { id: "preview-features",   title: "features.xml.compiled auto-decompile on extract", done: true,  priority: "high" },
      { id: "preview-feat-edit",  title: "features.xml editor (Fetitor-style toggle UI)",   done: true,  priority: "high" },
      { id: "preview-feat-repack","title": "features.xml recompile on pack (round-trip)",    done: true,  priority: "high" },
      { id: "preview-rgn",        title: ".rgn region parser (terrain height map)",          done: false, priority: "medium" },
      { id: "preview-area",       title: ".area prop placement parser + 2D map overlay",     done: false, priority: "medium" },
      { id: "preview-area-3d",    title: ".area + .rgn full 3D world preview (Three.js)",    done: false, priority: "low" },
      { id: "preview-set",        title: ".set animation keyframe table viewer",             done: false, priority: "low" },
      { id: "preview-mml",        title: "MML audio playback (PSGConverter port)",           done: false, priority: "low" },
      { id: "preview-anievent",   title: ".anievent animation event timeline",               done: false, priority: "low" },
      { id: "preview-pmg-3d-ref", title: ".pmg + propdb.xml 3D refinement (material/skin)", done: false, priority: "medium" },
    ],
  },
  {
    id: "modloader",
    title: "Mod Loader (.mod)",
    icon: "🧩",
    tasks: [
      { id: "mod-format",    title: ".mod instruction file format (TOML-based spec)",    done: true,  priority: "high" },
      { id: "mod-parser",    title: ".mod parser in Rust + Tauri command",               done: true,  priority: "high" },
      { id: "mod-apply",     title: "Apply .mod: replace/delete/patch files in archive", done: true,  priority: "high" },
      { id: "mod-features",  title: "Apply feature flag toggles from .mod",              done: true,  priority: "high" },
      { id: "mod-from-ini",  title: "Import mods from uotiaralist.ini in .mod file",     done: true,  priority: "medium" },
      { id: "mod-browser",   title: "In-app mod browser (reads .mod from mods/ folder)", done: false, priority: "medium" },
      { id: "mod-webui",     title: "WebUI mod browsing + install-from-web",             done: false, priority: "low" },
    ],
  },
  {
    id: "api",
    title: "REST API",
    icon: "🌐",
    tasks: [
      { id: "api-server",   title: "HTTP API server (auto-start on 127.0.0.1:7331)",     done: true,  priority: "high" },
      { id: "api-extract",  title: "POST /api/v1/extract",                               done: true,  priority: "high" },
      { id: "api-pack",     title: "POST /api/v1/pack",                                  done: true,  priority: "high" },
      { id: "api-list",     title: "GET  /api/v1/list",                                  done: true,  priority: "high" },
      { id: "api-mod",      title: "POST /api/v1/mod/apply",                             done: true,  priority: "high" },
      { id: "api-serve-cli","title": "mabi-patcher serve --port N CLI subcommand",        done: true,  priority: "high" },
      { id: "api-stream",   title: "Streaming progress via SSE or WebSocket",             done: false, priority: "medium" },
      { id: "api-uotiara",  title: "Connect to Uotiara WebUI (mod-picker → .it build)",  done: true,  priority: "high" },
      { id: "api-version",  title: "/api/mabi-version endpoint (replaces Proff API)",    done: false, priority: "medium" },
    ],
  },
  {
    id: "launcher",
    title: "Launcher",
    icon: "🚀",
    tasks: [
      { id: "launch-auth",    title: "Nexon NA login (SHA512 pw + device ID + autologin)",  done: true,  priority: "high" },
      { id: "launch-passport","title": "Passport → Client.exe launch (spawn_client)",      done: true,  priority: "high" },
      { id: "launch-profile", title: "Multi-account profile manager",                      done: true,  priority: "medium" },
      { id: "launch-mabitd",  title: "MabiTDown patch downloader integration",             done: false, priority: "medium" },
      { id: "launch-kanan",   title: "Kanan mod list UI (edits LibLoader Loader.cfg)",     done: false, priority: "low" },
    ],
  },
  {
    id: "research",
    title: "Research",
    icon: "🔬",
    tasks: [
      { id: "research-kr",       title: "KR .it Snow2 mode variants (ModernBE/LE/etc.)",  done: false, priority: "high" },
      { id: "research-propdb",   title: "PropDB.xml client-key extraction from Client.exe",done: false, priority: "high" },
      { id: "research-white",    title: "Whitecipher watchdog-neutralization (Auryn fix)", done: false, priority: "low" },
      { id: "research-nps64",    title: "Re-offset nps64.dll proxy jmp targets",           done: false, priority: "low" },
    ],
  },
];
