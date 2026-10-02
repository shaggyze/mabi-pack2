//! Replacement for `nexon_x64.dll`, which the official Nexon Launcher normally
//! deploys next to its `nexon_client.exe`.
//!
//! Mabinogi's `nexon_api_x64.dll` finds a running `nexon_client.exe`, loads
//! `<its dir>\bin\nexon_x64.dll` and calls `nxapi_get_func_addr(code)`:
//!
//!   0xbeef0001  init(param)                 -> i32 (0 = ok)
//!   0xbeef0002  close()
//!   0xbeef0003  getProductId(buf, size)     -> i32
//!   0xbeef0004  getProductTicket(buf, size) -> i32   <- the passport
//!   0xbeef0005  getClientToken(buf, size)   -> i32
//!   0xbeef0006  stub(buf, size)             -> i32
//!
//! mabi-patcher writes the passport to `%TEMP%\mabi-patcher-nxl3p-ticket.txt`
//! right before launching Client.exe; `init` reads it and deletes it.
//! Port of Rua's nxl3p_shim.dpr.
#![cfg(windows)]

use std::ffi::c_void;
use std::sync::Mutex;

const TICKET_FILE: &str = "mabi-patcher-nxl3p-ticket.txt";
const READY_EVENT: &str = "MABI_NXL3P_ShimReady";

struct State {
    ticket: Vec<u16>,
    product_id: Vec<u16>,
    ok: bool,
}

static STATE: Mutex<State> = Mutex::new(State { ticket: Vec::new(), product_id: Vec::new(), ok: false });

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn log(msg: &str) {
    use std::io::Write;
    let path = std::env::temp_dir().join("mabi-patcher-nxl3p-shim.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", msg);
    }
}

/// Copy `src` into the caller's WCHAR buffer (NUL-terminated, truncated to fit).
unsafe fn copy_out(src: &[u16], buf: *mut u16, size: u32) -> i32 {
    if buf.is_null() || size == 0 {
        return -1;
    }
    let n = src.len().min(size as usize - 1);
    std::ptr::copy_nonoverlapping(src.as_ptr(), buf, n);
    *buf.add(n) = 0;
    0
}

extern "system" fn shim_init(param: u64) -> i32 {
    log("init");
    let mut st = STATE.lock().unwrap();
    // param is sometimes a pointer; anything that doesn't look like an id means 10200.
    let pid = if param == 0 || param > 0xFFFF { 10200 } else { param };
    st.product_id = wide(&pid.to_string());

    let path = std::env::temp_dir().join(TICKET_FILE);
    match std::fs::read_to_string(&path) {
        Ok(t) => {
            let _ = std::fs::remove_file(&path); // ticket is sensitive — keep the window short
            let t = t.trim();
            st.ticket = wide(t);
            st.ok = !t.is_empty();
            log(if st.ok { "init: ticket loaded" } else { "init: ticket empty" });
        }
        Err(e) => log(&format!("init: ticket file not found: {}", e)),
    }
    drop(st);

    unsafe {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::synchapi::{OpenEventW, SetEvent};
        const EVENT_MODIFY_STATE: u32 = 0x0002;
        let mut name = wide(READY_EVENT);
        name.push(0);
        let ev = OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr());
        if !ev.is_null() {
            SetEvent(ev);
            CloseHandle(ev);
        }
    }
    0
}

extern "system" fn shim_close() {
    let mut st = STATE.lock().unwrap();
    st.ticket.iter_mut().for_each(|c| *c = 0);
    st.ticket.clear();
    st.ok = false;
}

extern "system" fn shim_product_id(buf: *mut u16, size: u32) -> i32 {
    let st = STATE.lock().unwrap();
    unsafe { copy_out(&st.product_id, buf, size) }
}

extern "system" fn shim_product_ticket(buf: *mut u16, size: u32) -> i32 {
    let st = STATE.lock().unwrap();
    log(&format!("getProductTicket ok={} len={}", st.ok, st.ticket.len()));
    if !st.ok {
        return -2;
    }
    unsafe { copy_out(&st.ticket, buf, size) }
}

extern "system" fn shim_empty(buf: *mut u16, size: u32) -> i32 {
    unsafe { copy_out(&[], buf, size) }
}

/// Second export of the real DLL. Returning NULL makes the caller fall back to
/// the `nxapi_get_func_addr` (v1) path.
#[no_mangle]
pub extern "system" fn GetDLLInterface() -> *const c_void {
    log("GetDLLInterface");
    std::ptr::null()
}

#[no_mangle]
pub extern "system" fn nxapi_get_func_addr(code: u32) -> *const c_void {
    log(&format!("nxapi_get_func_addr 0x{:08X}", code));
    match code {
        0xBEEF_0001 => shim_init as *const c_void,
        0xBEEF_0002 => shim_close as *const c_void,
        0xBEEF_0003 => shim_product_id as *const c_void,
        0xBEEF_0004 => shim_product_ticket as *const c_void,
        _ => shim_empty as *const c_void,
    }
}
