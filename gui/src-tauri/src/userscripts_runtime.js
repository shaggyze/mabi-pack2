// GM_* API for Browser tab userscripts (userscripts.rs). Evaluated once per page
// before the scripts; page_ready fills in the page id and token placeholders.
(function () {
  "use strict";
  if (window.__mpUSDoc !== "__MP_DOC__" || window.__mpUS) return;
  var TOKEN = "__MP_TOKEN__";
  var internals = window.__TAURI_INTERNALS__;
  // Keep our own reference: a page replacing invoke later does not see the token.
  var invoke = internals && internals.invoke ? internals.invoke.bind(internals) : null;
  var hasOwn = Object.prototype.hasOwnProperty;

  function call(script, op, args) {
    if (!invoke) return Promise.reject(new Error("userscript bridge unavailable"));
    return invoke("plugin:userscripts|gm", { token: TOKEN, script: script, op: op, args: args || {} });
  }
  function warn(name) { return function (e) { console.warn("[userscript] " + name + ":", e); }; }
  function safe(fn, self, args) {
    if (typeof fn !== "function") return;
    try { return fn.apply(self, args || []); } catch (e) { console.error(e); }
  }

  // Tampermonkey's stored value format: type letter + text.
  function dec(v) {
    if (typeof v !== "string" || !v) return v;
    var t = v.charAt(0), r = v.slice(1);
    if (t === "s") return r;
    if (t === "n") return Number(r);
    if (t === "b") return r === "true";
    if (t === "o") { try { return JSON.parse(r); } catch (e) { return undefined; } }
    return v;
  }
  function enc(v) {
    switch (typeof v) {
      case "string": return "s" + v;
      case "number": return "n" + v;
      case "boolean": return "b" + v;
      case "undefined": return null;
      case "function": return null;
      default: return "o" + JSON.stringify(v);
    }
  }
  function copy(v) { return v !== null && typeof v === "object" ? JSON.parse(JSON.stringify(v)) : v; }

  function b64ToBytes(b) { var s = atob(b || ""), u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
  function bytesToB64(u) { var s = "", c = 0x8000; for (var i = 0; i < u.length; i += c) s += String.fromCharCode.apply(null, u.subarray(i, i + c)); return btoa(s); }
  function latin1Bytes(str) { var u = new Uint8Array(str.length); for (var i = 0; i < str.length; i++) u[i] = str.charCodeAt(i) & 255; return u; }

  function absolute(url) { return new URL(String(url), location.href).href; }

  // ── Menu commands (shown in the Browser tab's Scripts panel) ──────────────
  var menus = {}, menuSeq = 0;
  function pushMenu(script) {
    var m = menus[script] || {};
    var items = Object.keys(m).map(function (k) { return { id: Number(k), caption: m[k].caption }; });
    call(script, "menu", { items: items }).catch(warn(script));
  }

  // ── Notifications: an in-page toast ───────────────────────────────────────
  function toast(title, text, image, onclick, ondone, timeout) {
    var host = document.body || document.documentElement;
    if (!host) { setTimeout(function () { toast(title, text, image, onclick, ondone, timeout); }, 100); return; }
    var box = document.createElement("div");
    box.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:360px;display:flex;gap:10px;align-items:flex-start;" +
      "padding:12px 14px;border-radius:8px;background:#25252d;color:#f3f4f6;font:13px/1.4 system-ui,sans-serif;box-shadow:0 6px 24px rgba(0,0,0,.45);cursor:pointer";
    if (image) { var img = document.createElement("img"); img.src = image; img.style.cssText = "width:40px;height:40px;object-fit:contain;flex:none"; box.appendChild(img); }
    var col = document.createElement("div");
    if (title) { var h = document.createElement("div"); h.textContent = title; h.style.fontWeight = "600"; col.appendChild(h); }
    var p = document.createElement("div"); p.textContent = text || ""; col.appendChild(p);
    box.appendChild(col);
    var done = false;
    function close() { if (done) return; done = true; box.remove(); safe(ondone); }
    box.addEventListener("click", function () { safe(onclick); close(); });
    host.appendChild(box);
    setTimeout(close, timeout > 0 ? timeout : 6000);
  }

  // ── run-at ────────────────────────────────────────────────────────────────
  function whenReady(runAt, fn) {
    var rs = document.readyState;
    if (runAt === "document-start" || runAt === "document-begin") return fn();
    if (runAt === "document-body") {
      if (document.body) return fn();
      var mo = new MutationObserver(function () { if (document.body) { mo.disconnect(); fn(); } });
      mo.observe(document.documentElement, { childList: true });
      return;
    }
    if (runAt === "load") {
      if (rs === "complete") return fn();
      window.addEventListener("load", function () { fn(); }, { once: true });
      return;
    }
    var end = runAt === "document-end";
    if (rs === "loading") document.addEventListener("DOMContentLoaded", function () { end ? fn() : setTimeout(fn, 0); }, { once: true });
    else if (end) fn(); else setTimeout(fn, 0);
  }

  // ── Sandbox: scripts with grants get their own globals over the page's ────
  function makeSandbox(api) {
    // The proxy target is the script's own globals object, not window: a Proxy
    // must not hide a non-configurable property of its target, and window's
    // document/location/top are non-configurable ("'has' on proxy" TypeError).
    // Per sandbox: each wrapper compares against this sandbox's own proxy.
    var bound = new WeakMap();
    var local = Object.create(null);
    Object.keys(api).forEach(function (k) { local[k] = api[k]; });
    function isSelf(k) { return k === "window" || k === "self" || k === "globalThis" || k === "frames"; }
    var self = new Proxy(local, {
      // `with (sandbox)`: own names and window aliases resolve here, the rest
      // fall through to the real global scope.
      has: function (t, k) { return typeof k === "string" && (k in t || isSelf(k)); },
      get: function (t, k) {
        if (isSelf(k)) return self;
        if (k in t) return t[k];
        var v = Reflect.get(window, k);
        // Window methods need the real window as this. Page scripts (New Relic's
        // nrWrapper) replace natives with plain functions, so every function is
        // wrapped: calls get window for a sandbox this, while properties
        // ($.fn) and `new` pass through the proxy unchanged.
        // Capitalized globals (Object, HTMLElement, Image) are constructors: keep identity.
        if (typeof v === "function" && typeof k === "string" && !/^[A-Z]/.test(k)) {
          var b = bound.get(v);
          if (!b) {
            b = new Proxy(v, { apply: function (f, that, args) { return Reflect.apply(f, that === self ? window : that, args); } });
            bound.set(v, b);
          }
          return b;
        }
        return v;
      },
      set: function (t, k, v) {
        if (typeof k === "string" && !(k in t) && ((/^on[a-z]+$/.test(k) && k in window) || k === "location" || k === "name" || k === "status")) { window[k] = v; return true; }
        t[k] = v;
        return true;
      },
      getOwnPropertyDescriptor: function (t, k) {
        var d = Reflect.getOwnPropertyDescriptor(t, k);
        if (d) return d;
        d = Reflect.getOwnPropertyDescriptor(window, k);
        // Reported as configurable: the target does not hold it.
        if (d) d.configurable = true;
        return d;
      }
    });
    return self;
  }
  // ── GM_xmlhttpRequest ─────────────────────────────────────────────────────
  function charsetOf(ct) { var m = /charset=([^;]+)/i.exec(ct || ""); return m ? m[1].trim().replace(/"/g, "") : "utf-8"; }
  function decodeText(bytes, ct) { try { return new TextDecoder(charsetOf(ct)).decode(bytes); } catch (e) { return new TextDecoder().decode(bytes); } }

  function makeResponse(r, d) {
    var bytes = b64ToBytes(r.body);
    var ctMatch = /^content-type:\s*(.*)$/im.exec(r.headers || "");
    var ct = d.overrideMimeType || (ctMatch ? ctMatch[1].trim() : "");
    var text = null, doc;
    function getText() { if (text === null) text = decodeText(bytes, ct); return text; }
    function getDoc() {
      if (doc === undefined) {
        try { doc = new DOMParser().parseFromString(getText(), /xml/i.test(ct) && !/html/i.test(ct) ? "text/xml" : "text/html"); } catch (e) { doc = null; }
      }
      return doc;
    }
    var type = (d.responseType || "").toLowerCase();
    var res = {
      readyState: 4, status: r.status, statusText: r.statusText, responseHeaders: r.headers, finalUrl: r.finalUrl,
      context: d.context, lengthComputable: true, loaded: bytes.length, total: bytes.length
    };
    Object.defineProperty(res, "responseText", { get: getText, enumerable: true });
    Object.defineProperty(res, "responseXML", { get: getDoc, enumerable: true });
    Object.defineProperty(res, "response", {
      enumerable: true,
      get: function () {
        if (type === "arraybuffer") return bytes.buffer;
        if (type === "blob") return new Blob([bytes], { type: ct });
        if (type === "json") { try { return JSON.parse(getText()); } catch (e) { return null; } }
        if (type === "document") return getDoc();
        if (type === "stream") return new Response(bytes).body;
        return getText();
      }
    });
    return res;
  }

  function bodyOf(d) {
    var data = d.data;
    if (data === undefined || data === null) return Promise.resolve({ body: null, type: null });
    if (typeof data === "string") return Promise.resolve({ body: bytesToB64(d.binary ? latin1Bytes(data) : new TextEncoder().encode(data)), type: null });
    // FormData / Blob / URLSearchParams / ArrayBuffer: let Response serialize it (with its content type).
    var r;
    try { r = new Response(data); } catch (e) { return Promise.resolve({ body: bytesToB64(new TextEncoder().encode(String(data))), type: null }); }
    var type = r.headers.get("content-type");
    return r.arrayBuffer().then(function (buf) { return { body: bytesToB64(new Uint8Array(buf)), type: type }; });
  }

  function xhr(script, d) {
    d = d || {};
    var aborted = false, settled = false, resolveP, rejectP;
    var promise = new Promise(function (res, rej) { resolveP = res; rejectP = rej; });
    promise.catch(function () {});
    var control = {
      abort: function () {
        if (settled) return;
        aborted = settled = true;
        var r = { readyState: 4, status: 0, statusText: "aborted", responseHeaders: "", response: null, responseText: "", finalUrl: d.url, context: d.context };
        safe(d.onabort, null, [r]); safe(d.onloadend, null, [r]);
        rejectP(r);
      }
    };
    promise.abort = control.abort;
    var url;
    try { url = absolute(d.url); } catch (e) {
      setTimeout(function () { var r = { readyState: 4, status: 0, statusText: "bad url", error: String(e), responseHeaders: "", response: null, responseText: "", finalUrl: d.url }; safe(d.onerror, null, [r]); rejectP(r); }, 0);
      return { control: control, promise: promise };
    }
    safe(d.onloadstart, null, [{ readyState: 1, status: 0, finalUrl: url, context: d.context }]);
    bodyOf(d).then(function (b) {
      if (aborted) return null;
      var headers = {};
      var h = d.headers || {};
      Object.keys(h).forEach(function (k) { headers[k] = String(h[k]); });
      if (b.type && !Object.keys(headers).some(function (k) { return k.toLowerCase() === "content-type"; })) headers["Content-Type"] = b.type;
      return call(script, "xhr", {
        method: d.method || "GET", url: url, headers: headers, body: b.body, timeout: d.timeout || 0,
        anonymous: !!d.anonymous, ua: navigator.userAgent, redirect: d.redirect || "follow"
      });
    }).then(function (r) {
      if (aborted || !r) return;
      settled = true;
      var res = makeResponse(r, d);
      safe(d.onreadystatechange, res, [res]);
      safe(d.onprogress, res, [res]);
      safe(d.onload, res, [res]);
      safe(d.onloadend, res, [res]);
      resolveP(res);
    }).catch(function (e) {
      if (aborted) return;
      settled = true;
      var msg = String(e && e.message || e);
      var res = { readyState: 4, status: 0, statusText: msg, error: msg, responseHeaders: "", response: null, responseText: "", finalUrl: url, context: d.context };
      safe(d.onreadystatechange, res, [res]);
      if (/timed? ?out/i.test(msg)) safe(d.ontimeout, res, [res]); else safe(d.onerror, res, [res]);
      safe(d.onloadend, res, [res]);
      rejectP(res);
    });
    return { control: control, promise: promise };
  }

  // ── One script's API ──────────────────────────────────────────────────────
  function buildApi(p) {
    var id = p.id, name = (p.info && p.info.script && p.info.script.name) || id;
    var store = {}, listeners = {}, listenerSeq = 0;
    Object.keys(p.storage || {}).forEach(function (k) { store[k] = dec(p.storage[k]); });

    function fire(key, oldV, newV) {
      Object.keys(listeners).forEach(function (lid) {
        var l = listeners[lid];
        if (l.key === key) safe(l.fn, null, [key, oldV, newV, false]);
      });
    }
    function getValue(k, def) { return hasOwn.call(store, k) && store[k] !== undefined ? copy(store[k]) : def; }
    function setValue(k, v) {
      var old = store[k], e = enc(v);
      if (e === null) return deleteValue(k);
      store[k] = copy(v);
      call(id, "set", { key: String(k), value: e }).catch(warn(name));
      fire(k, old, v);
    }
    function deleteValue(k) {
      var old = store[k];
      delete store[k];
      call(id, "delete", { key: String(k) }).catch(warn(name));
      fire(k, old, undefined);
    }
    function listValues() { return Object.keys(store); }
    function getValues(keys) {
      var out = {};
      if (Array.isArray(keys)) keys.forEach(function (k) { if (hasOwn.call(store, k)) out[k] = copy(store[k]); });
      else if (keys && typeof keys === "object") Object.keys(keys).forEach(function (k) { out[k] = getValue(k, keys[k]); });
      else Object.keys(store).forEach(function (k) { out[k] = copy(store[k]); });
      return out;
    }
    function setValues(obj) { Object.keys(obj || {}).forEach(function (k) { setValue(k, obj[k]); }); }
    function deleteValues(keys) { (keys || []).forEach(deleteValue); }
    function addValueChangeListener(key, fn) { var lid = ++listenerSeq; listeners[lid] = { key: key, fn: fn }; return lid; }
    function removeValueChangeListener(lid) { delete listeners[lid]; }

    function addStyle(css) {
      var s = document.createElement("style");
      s.textContent = css;
      (document.head || document.documentElement).appendChild(s);
      return s;
    }
    function addElement(parent, tag, attrs) {
      if (typeof parent === "string") { attrs = tag; tag = parent; parent = null; }
      var el = document.createElement(tag);
      Object.keys(attrs || {}).forEach(function (k) {
        if (k === "textContent" || k === "innerHTML") el[k] = attrs[k]; else el.setAttribute(k, attrs[k]);
      });
      (parent || (/^(script|style|link|meta)$/i.test(tag) ? document.head : document.body) || document.documentElement).appendChild(el);
      return el;
    }
    function resource(n) { return (p.resources || {})[n]; }
    function getResourceText(n) { var r = resource(n); return r ? decodeText(b64ToBytes(r.b64), r.mime) : null; }
    function getResourceURL(n) { var r = resource(n); return r ? "data:" + r.mime + ";base64," + r.b64 : null; }

    function registerMenuCommand(caption, fn, opts) {
      var mid = (opts && typeof opts === "object" && opts.id != null) ? Number(opts.id) : ++menuSeq;
      if (isNaN(mid)) mid = ++menuSeq;
      (menus[id] = menus[id] || {})[mid] = { caption: String(caption), fn: fn };
      pushMenu(id);
      return mid;
    }
    function unregisterMenuCommand(mid) { if (menus[id]) { delete menus[id][mid]; pushMenu(id); } }

    function openInTab(url, opts) {
      var bg = opts === true || !!(opts && typeof opts === "object" && (opts.active === false || opts.loadInBackground));
      var tab = { closed: false, onclose: null, close: function () {} };
      try { call(id, "open_tab", { url: absolute(url), background: bg }).catch(warn(name)); } catch (e) { warn(name)(e); }
      return tab;
    }
    function setClipboard(data, info) {
      var text = String(data);
      var html = info === "html" || (info && info.type === "html") || (info && info.mimetype === "text/html");
      function fallback() {
        var ta = document.createElement("textarea");
        ta.value = text; ta.style.cssText = "position:fixed;left:-9999px;top:0";
        (document.body || document.documentElement).appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch (e) {}
        ta.remove();
      }
      try {
        if (html && window.ClipboardItem) {
          return navigator.clipboard.write([new ClipboardItem({ "text/html": new Blob([text], { type: "text/html" }), "text/plain": new Blob([text], { type: "text/plain" }) })]).catch(fallback);
        }
        return navigator.clipboard.writeText(text).catch(fallback);
      } catch (e) { fallback(); return Promise.resolve(); }
    }
    function notification(details, title, image, onclick) {
      var d = typeof details === "object" && details ? details : { text: details, title: title, image: image, onclick: onclick };
      toast(d.title || name, d.text, d.image, d.onclick, d.ondone, d.timeout);
      call(id, "log", { text: "notification: " + (d.title ? d.title + ": " : "") + (d.text || "") }).catch(function () {});
    }
    function download(details, fname) {
      var d = typeof details === "object" && details ? details : { url: details, name: fname };
      var url;
      try { url = absolute(d.url); } catch (e) { safe(d.onerror, null, [{ error: "bad url", details: String(e) }]); return { abort: function () {} }; }
      var name0 = d.name || url.split(/[?#]/)[0].split("/").pop() || "download";
      var job;
      if (/^(blob|data):/.test(url)) {
        job = fetch(url).then(function (r) { return r.arrayBuffer(); }).then(function (buf) {
          return call(id, "download", { name: name0, body: bytesToB64(new Uint8Array(buf)) });
        });
      } else {
        job = call(id, "download", { url: url, name: name0, headers: d.headers || {}, ua: navigator.userAgent });
      }
      job.then(function (path) { safe(d.onload, null, [{ path: path }]); }, function (e) { safe(d.onerror, null, [{ error: "download failed", details: String(e) }]); });
      return { abort: function () {} };
    }
    var cookie = {
      list: function () { return Promise.reject(new Error("GM.cookie is not supported")); },
      set: function () { return Promise.reject(new Error("GM.cookie is not supported")); },
      delete: function () { return Promise.reject(new Error("GM.cookie is not supported")); }
    };
    var log = function () { console.log.apply(console, ["[" + name + "]"].concat([].slice.call(arguments))); };

    var info = p.info || {};
    function GM_xmlhttpRequest(d) { return xhr(id, d).control; }
    var resolved = function (fn) { return function () { var a = arguments; return new Promise(function (res) { res(fn.apply(null, a)); }); }; };
    var GM = {
      info: info,
      getValue: resolved(getValue), setValue: resolved(setValue), deleteValue: resolved(deleteValue), listValues: resolved(listValues),
      getValues: resolved(getValues), setValues: resolved(setValues), deleteValues: resolved(deleteValues),
      addValueChangeListener: resolved(addValueChangeListener), removeValueChangeListener: resolved(removeValueChangeListener),
      addStyle: resolved(addStyle), addElement: addElement,
      getResourceText: resolved(getResourceText), getResourceUrl: resolved(getResourceURL), getResourceURL: resolved(getResourceURL),
      registerMenuCommand: registerMenuCommand, unregisterMenuCommand: unregisterMenuCommand,
      openInTab: openInTab, setClipboard: setClipboard,
      notification: function (d, t, i, c) { return new Promise(function (res) { notification(d, t, i, c); res(true); }); },
      xmlHttpRequest: function (d) { return xhr(id, d).promise; },
      download: function (d, n) {
        var o = typeof d === "object" && d ? Object.assign({}, d) : { url: d, name: n };
        return new Promise(function (res, rej) {
          var ol = o.onload, oe = o.onerror;
          o.onload = function (r) { safe(ol, null, [r]); res(r); };
          o.onerror = function (r) { safe(oe, null, [r]); rej(r); };
          download(o);
        });
      },
      log: log, cookie: cookie
    };
    return {
      GM_info: info, GM: GM, unsafeWindow: window,
      GM_getValue: getValue, GM_setValue: setValue, GM_deleteValue: deleteValue, GM_listValues: listValues,
      GM_getValues: getValues, GM_setValues: setValues, GM_deleteValues: deleteValues,
      GM_addValueChangeListener: addValueChangeListener, GM_removeValueChangeListener: removeValueChangeListener,
      GM_addStyle: addStyle, GM_addElement: addElement, GM_getResourceText: getResourceText, GM_getResourceURL: getResourceURL,
      GM_registerMenuCommand: registerMenuCommand, GM_unregisterMenuCommand: unregisterMenuCommand,
      GM_openInTab: openInTab, GM_setClipboard: setClipboard, GM_notification: notification,
      GM_xmlhttpRequest: GM_xmlhttpRequest, GM_download: download, GM_log: log, GM_cookie: cookie
    };
  }

  // Same order as PARAMS in userscripts.rs.
  var ORDER = ["GM_info", "GM", "unsafeWindow", "GM_getValue", "GM_setValue", "GM_deleteValue", "GM_listValues", "GM_getValues",
    "GM_setValues", "GM_deleteValues", "GM_addValueChangeListener", "GM_removeValueChangeListener", "GM_addStyle", "GM_addElement",
    "GM_getResourceText", "GM_getResourceURL", "GM_registerMenuCommand", "GM_unregisterMenuCommand", "GM_openInTab",
    "GM_setClipboard", "GM_notification", "GM_xmlhttpRequest", "GM_download", "GM_log", "GM_cookie"];

  // ── Errors: shown in the Scripts panel and written to log.txt ─────────────
  function errText(e) {
    if (e && e.stack) return String(e.stack).split("\n").slice(0, 3).join(" | ");
    return String(e && e.message || e);
  }
  function report(script, name, e) {
    console.error("[userscript] " + name + ":", e);
    call(script, "error", { text: errText(e).slice(0, 1000) }).catch(function () {});
  }
  // Uncaught errors from a script's own code later on (timers, event handlers):
  // the eval carries `//# sourceURL=userscript:<id>`.
  window.addEventListener("error", function (ev) {
    var m = /^userscript:(.+)$/.exec(ev.filename || "");
    var id = m && alias[m[1]];
    if (id) report(id, started[id], ev.error || ev.message);
  });
  // A script whose wrapper never called run() did not parse (syntax error).
  var expected = {}, started = {}, alias = {};
  setTimeout(function () {
    Object.keys(expected).forEach(function (id) {
      if (!started[id]) call(id, "error", { text: "did not start: the script has a syntax error" }).catch(function () {});
    });
  }, 5000);

  var api = {
    expect: function (id) { expected[id] = true; },
    run: function (p, fn) {
      var a = buildApi(p);
      var name = (p.info && p.info.script && p.info.script.name) || p.id;
      started[p.id] = name;
      alias[p.id.replace(/\s/g, "_")] = p.id;
      var args = ORDER.map(function (k) { return a[k]; });
      args.push(p.sandbox ? makeSandbox(a) : window);
      whenReady(p.runAt, function () {
        try { fn.apply(window, args); } catch (e) { report(p.id, name, e); }
      });
    },
    menu: function (token, script, mid) {
      if (token !== TOKEN) return;
      var m = menus[script];
      if (m && m[mid]) safe(m[mid].fn);
    }
  };
  Object.defineProperty(window, "__mpUS", { value: Object.freeze(api) });
})();
