// "Import from Kanan" dialog: pick Kanan's profiles.dat, unlock it with the
// Kanan master password, choose accounts, import them (each is logged in once
// and only the session is saved), finishing any MFA challenges on the way.
// The master password is held only in this dialog's input and closure, and is
// dropped when the dialog closes.

import { invoke } from "./platform/invoke";
import { open } from "./platform/dialog";

export interface KananImportHost {
    t(key: string, args?: string[]): string;
    log(msg: string, level: "info" | "warn" | "error" | "success"): void;
    /** Reload the profile list after an import. */
    reloadProfiles(): Promise<void>;
}

interface KananAccount { index: number; username: string; has_password: boolean; profile_name?: string }
interface KananOutcome {
    username: string; profile_id: string; profile_name: string;
    status: "logged_in" | "mfa_required" | "failed";
    mfa_key?: string; mfa_type?: string; error?: string;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...kids: (Node | string)[]): HTMLElementTagNameMap[K] {
    const e = Object.assign(document.createElement(tag), props);
    for (const k of kids) e.append(k);
    return e;
}

/** "Import from Hyddwn Launcher": same dialog without the file and master-password
 *  steps (Hyddwn's saved logins are read from %LOCALAPPDATA%\Hyddwn Launcher). */
export function importFromHyddwn(host: KananImportHost): Promise<void> {
    return importFromKanan(host, undefined, "hyddwn");
}

/** `knownPath`: a profiles.dat found by launcher detection; skips the file picker. */
export async function importFromKanan(host: KananImportHost, knownPath?: string, source: "kanan" | "hyddwn" = "kanan"): Promise<void> {
    const t = (k: string, a: string[] = []) => host.t(k, a);
    const hyddwn = source === "hyddwn";
    let path: string | null = hyddwn ? "" : knownPath || null;
    if (!hyddwn && !path) {
        const defaultPath = await invoke("kanan_default_path").catch(() => null) as string | null;
        const picked = await open({
            title: t("kanan_pick_file"),
            defaultPath: defaultPath ?? undefined,
            filters: [{ name: "profiles.dat", extensions: ["dat"] }],
        });
        path = Array.isArray(picked) ? picked[0] : picked;
    }
    if (!hyddwn && !path) return;

    // Modal shell (reuses the conflict dialog styling).
    const header = el("div", { className: "conflict-header", textContent: t(hyddwn ? "hyddwn_title" : "kanan_title") });
    const body = el("div", { className: "conflict-body" });
    const actions = el("div", { className: "conflict-actions" });
    const modal = el("div", { className: "conflict-modal" }, header, body, actions);
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    const overlay = el("div", { className: "conflict-overlay" }, modal);
    document.body.append(overlay);

    let masterPassword = "";
    let imported = false;
    let closeResolve: () => void = () => {};
    const closed = new Promise<void>((r) => { closeResolve = r; });
    let isClosed = false;
    // Skips the MFA prompt on screen (if any) when the dialog closes (e.g. Escape).
    let cancelMfa: (() => void) | null = null;
    const close = () => {
        masterPassword = "";
        isClosed = true;
        overlay.remove();
        cancelMfa?.();
        closeResolve();
    };
    const button = (key: string, primary: boolean, onClick: () => void) => {
        const b = el("button", { className: primary ? "tab-btn primary" : "tab-btn", textContent: t(key) });
        b.addEventListener("click", onClick);
        return b;
    };
    const message = (text: string, error = false) => {
        const p = el("p", { className: "conflict-msg", textContent: text });
        if (error) p.style.color = "var(--accent-error, #ff5c5c)";
        return p;
    };
    const setActions = (...buttons: HTMLButtonElement[]) => actions.replaceChildren(...buttons);
    const busy = (key: string) => {
        body.replaceChildren(message(t(key)));
        setActions();
    };
    overlay.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); close(); } });

    // Step 1: master password.
    const askPassword = (error?: string) => {
        const input = el("input", { type: "password", className: "form-input", autocomplete: "off", placeholder: t("kanan_password_label") });
        input.spellcheck = false;
        const submit = () => { masterPassword = input.value; input.value = ""; void unlock(); };
        input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } });
        body.replaceChildren(message(t("kanan_password_prompt", [path ?? ""])), input, ...(error ? [message(error, true)] : []));
        setActions(button("kanan_unlock", true, submit), button("kanan_cancel", false, close));
        input.focus();
    };

    // Step 2: decrypt and list accounts.
    const unlock = async () => {
        busy("kanan_unlocking");
        let accounts: KananAccount[];
        try {
            accounts = (hyddwn
                ? await invoke("hyddwn_list_accounts")
                : await invoke("kanan_list_accounts", { path, masterPassword })) as KananAccount[];
        } catch (e) {
            masterPassword = "";
            if (hyddwn) {
                body.replaceChildren(message(String(e), true));
                setActions(button("kanan_close", true, close));
            } else {
                askPassword(String(e));
            }
            return;
        }
        if (accounts.length === 0) {
            masterPassword = "";
            body.replaceChildren(message(t(hyddwn ? "hyddwn_no_accounts" : "kanan_no_accounts")));
            setActions(button("kanan_close", true, close));
            return;
        }
        const boxes = accounts.map((a) => {
            const cb = el("input", { type: "checkbox", checked: a.has_password, disabled: !a.has_password });
            cb.dataset.index = String(a.index);
            const label = a.profile_name ? `${a.profile_name} (${a.username})` : a.username;
            return { cb, row: el("label", { className: "checkbox-label" }, cb, " ", label) };
        });
        const list = el("div", { className: "conflict-options" }, ...boxes.map((b) => b.row));
        body.replaceChildren(message(t("kanan_select_accounts")), list);
        setActions(
            button("kanan_import_selected", true, () => {
                const indices = boxes.filter((b) => b.cb.checked).map((b) => Number(b.cb.dataset.index));
                if (indices.length) void runImport(indices);
            }),
            button("kanan_cancel", false, close),
        );
    };

    // Step 3: import (login) each selected account.
    const runImport = async (indices: number[]) => {
        busy("kanan_importing");
        let outcomes: KananOutcome[];
        try {
            outcomes = (hyddwn
                ? await invoke("hyddwn_import_accounts", { indices })
                : await invoke("kanan_import_accounts", { path, masterPassword, indices })) as KananOutcome[];
        } catch (e) {
            body.replaceChildren(message(t("log_kanan_import_failed", [String(e)]), true));
            setActions(button("kanan_close", true, close));
            return;
        } finally {
            masterPassword = "";
        }
        imported = true;
        const lines: string[] = [];
        let ok = 0;
        for (const o of outcomes) {
            if (o.status === "mfa_required") {
                const r = await askMfa(o);
                if (r === true) { ok++; lines.push(t("kanan_result_ok", [o.username])); }
                else if (r === false) lines.push(t("kanan_result_skipped", [o.username]));
                else lines.push(t("kanan_result_failed", [o.username, r]));
            } else if (o.status === "logged_in") {
                ok++;
                lines.push(t("kanan_result_ok", [o.username]));
            } else {
                lines.push(t("kanan_result_failed", [o.username, o.error ?? ""]));
            }
        }
        const done = t("kanan_done", [String(ok)]);
        host.log(`[Launcher] ${done}`, ok === outcomes.length ? "success" : "warn");
        for (const l of lines) host.log(`[Launcher] ${l}`, "info");
        body.replaceChildren(message(done), ...lines.map((l) => message(l)));
        setActions(button("kanan_close", true, close));
    };

    // MFA for one account: true = logged in, false = skipped, string = error.
    const askMfa = (o: KananOutcome, error?: string): Promise<true | false | string> => new Promise((settle) => {
        // Closed (Escape / Cancel): skip this and any remaining MFA prompts.
        if (isClosed) { settle(false); return; }
        const resolve = (r: true | false | string) => { cancelMfa = null; settle(r); };
        cancelMfa = () => resolve(false);
        const input = el("input", { type: "text", className: "form-input", autocomplete: "one-time-code", inputMode: "numeric" });
        const submit = async () => {
            const otp = input.value.trim();
            if (!otp) return;
            busy("kanan_importing");
            try {
                await invoke("kanan_import_otp", { profileId: o.profile_id, mfaKey: o.mfa_key, otp });
                resolve(true);
            } catch (e) {
                resolve(await askMfa(o, String(e)));
            }
        };
        input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); void submit(); } });
        body.replaceChildren(
            message(t("kanan_mfa_prompt", [o.mfa_type || "email", o.username])),
            input,
            ...(error ? [message(error, true)] : []),
        );
        setActions(button("kanan_mfa_submit", true, () => void submit()), button("kanan_mfa_skip", false, () => resolve(false)));
        input.focus();
    });

    if (hyddwn) void unlock(); else askPassword();
    await closed;
    if (imported) await host.reloadProfiles();
}
