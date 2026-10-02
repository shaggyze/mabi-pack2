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
//! Ticket hand-off: mabi-patcher puts the passport in a per-launch named file
//! mapping `Local\mabi-patcher.ticket.{GUID}` (DACL: current user + SYSTEM)
//! laid out as [magic "MPT1"][u32 LE length][UTF-8 ticket]. Its name comes from
//! the `MABI_PATCHER_TICKET_MAP` env var, or `--mabi-map <name>` on the game's
//! command line (an elevated start loses the environment). `init` copies the
//! ticket, zeroes the mapping, clears the env var and sets `<name>.ready`.
//! Nothing ticket-related is ever logged.

/// Env var and command-line flag naming the ticket mapping (see the crate docs).
pub const TICKET_MAP_ENV: &str = "MABI_PATCHER_TICKET_MAP";
pub const TICKET_MAP_ARG: &str = "--mabi-map";
const TICKET_MAP_PREFIX: &str = r"Local\mabi-patcher.ticket.";
pub const TICKET_MAP_CAPACITY: usize = 4096;
pub const TICKET_MAP_MAGIC: u32 = u32::from_le_bytes(*b"MPT1");
/// Longest ticket accepted, in UTF-16 units.
pub const TICKET_MAX_CHARS: usize = 1023;

fn is_braced_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// True if `name` is a mabi-patcher ticket mapping name.
pub fn is_ticket_map_name(name: &str) -> bool {
    name.strip_prefix(TICKET_MAP_PREFIX).is_some_and(is_braced_guid)
}

/// The mapping name from a `--mabi-map <name>` pair in a command line, if valid.
pub fn map_name_from_command_line(cmdline: &str) -> Option<&str> {
    let mut it = cmdline.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == TICKET_MAP_ARG {
            return it.next().map(|n| n.trim_matches('"')).filter(|n| is_ticket_map_name(n));
        }
    }
    None
}

/// The ticket in a mapping view, if the view holds a valid one.
pub fn decode_ticket(view: &[u8]) -> Option<String> {
    if view.len() < 8 || u32::from_le_bytes(view[..4].try_into().ok()?) != TICKET_MAP_MAGIC {
        return None;
    }
    let n = u32::from_le_bytes(view[4..8].try_into().ok()?) as usize;
    if n == 0 || n > view.len() - 8 {
        return None;
    }
    let t = std::str::from_utf8(&view[8..8 + n]).ok()?;
    (t.encode_utf16().count() <= TICKET_MAX_CHARS && !t.contains('\0')).then(|| t.to_string())
}

#[cfg(windows)]
pub mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::sync::Mutex;
    use winapi::um::handleapi::CloseHandle;

    struct State {
        ticket: Vec<u16>,
        product_id: Vec<u16>,
        ok: bool,
    }

    static STATE: Mutex<State> = Mutex::new(State { ticket: Vec::new(), product_id: Vec::new(), ok: false });

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn wide_z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn log(msg: &str) {
        use std::io::Write;
        let path = std::env::temp_dir().join("mabi-patcher-nxl3p-shim.log");
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", msg);
        }
    }

    fn wipe_u16(v: &mut [u16]) {
        for x in v.iter_mut() {
            unsafe { std::ptr::write_volatile(x, 0) };
        }
    }

    fn wipe_string(mut s: String) {
        for b in unsafe { s.as_bytes_mut() } {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }

    /// Copy `src` into the caller's WCHAR buffer (NUL-terminated). A buffer too
    /// small for all of it gets -1 and is left untouched: a truncated ticket or
    /// product id would only fail later, less clearly.
    unsafe fn copy_out(src: &[u16], buf: *mut u16, size: u32) -> i32 {
        if buf.is_null() || src.len() >= size as usize {
            return -1;
        }
        std::ptr::copy_nonoverlapping(src.as_ptr(), buf, src.len());
        *buf.add(src.len()) = 0;
        0
    }

    /// The mapping name: env var first (then cleared so nothing the game starts
    /// inherits it), else the command-line fallback.
    fn mapping_name() -> Option<(String, &'static str)> {
        use winapi::um::processenv::{GetCommandLineW, SetEnvironmentVariableW};
        let from_env = std::env::var(TICKET_MAP_ENV).ok();
        if from_env.is_some() {
            unsafe { SetEnvironmentVariableW(wide_z(TICKET_MAP_ENV).as_ptr(), std::ptr::null()) };
        }
        if let Some(n) = from_env.filter(|n| is_ticket_map_name(n)) {
            return Some((n, "env"));
        }
        let cl = unsafe {
            let p = GetCommandLineW();
            if p.is_null() {
                return None;
            }
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        };
        map_name_from_command_line(&cl).map(|n| (n.to_string(), "command line"))
    }

    /// Read the ticket from the mapping, then zero the mapping (one-shot).
    fn read_mapping(name: &str) -> Option<String> {
        use winapi::um::memoryapi::{MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE};
        unsafe {
            let wname = wide_z(name);
            let mut access = FILE_MAP_READ | FILE_MAP_WRITE;
            let mut h = OpenFileMappingW(access, 0, wname.as_ptr());
            if h.is_null() {
                access = FILE_MAP_READ;
                h = OpenFileMappingW(access, 0, wname.as_ptr());
            }
            if h.is_null() {
                log(&format!("init: ticket mapping not found (error {})", std::io::Error::last_os_error()));
                return None;
            }
            let view = MapViewOfFile(h, access, 0, 0, TICKET_MAP_CAPACITY) as *mut u8;
            if view.is_null() {
                CloseHandle(h);
                log("init: ticket mapping could not be mapped");
                return None;
            }
            let mut copy = vec![0u8; TICKET_MAP_CAPACITY];
            std::ptr::copy_nonoverlapping(view, copy.as_mut_ptr(), TICKET_MAP_CAPACITY);
            if access & FILE_MAP_WRITE != 0 {
                for i in 0..TICKET_MAP_CAPACITY {
                    std::ptr::write_volatile(view.add(i), 0);
                }
            }
            UnmapViewOfFile(view as *const _);
            CloseHandle(h);
            let ticket = decode_ticket(&copy);
            for b in copy.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
            ticket
        }
    }

    fn signal_ready(name: &str) -> bool {
        use winapi::um::synchapi::{OpenEventW, SetEvent};
        const EVENT_MODIFY_STATE: u32 = 0x0002;
        unsafe {
            let ev = OpenEventW(EVENT_MODIFY_STATE, 0, wide_z(&format!("{}.ready", name)).as_ptr());
            if ev.is_null() {
                return false;
            }
            SetEvent(ev);
            CloseHandle(ev);
            true
        }
    }

    extern "system" fn shim_init(param: u64) -> i32 {
        log("init");
        let mut st = STATE.lock().unwrap();
        // param is sometimes a pointer; anything that doesn't look like an id means 10200.
        let pid = if param == 0 || param > 0xFFFF { 10200 } else { param };
        st.product_id = wide(&pid.to_string());

        let Some((name, source)) = mapping_name() else {
            log("init: no ticket mapping name (env or command line)");
            return if st.ok { 0 } else { -1 };
        };
        match read_mapping(&name) {
            Some(t) => {
                wipe_u16(&mut st.ticket);
                st.ticket = wide(&t);
                wipe_string(t);
                st.ok = !st.ticket.is_empty();
                log(&format!("init: ticket loaded (mapping from {})", source));
            }
            // Already initialised by an earlier call: keep that ticket.
            None if st.ok => log("init: mapping already consumed; keeping the loaded ticket"),
            None => {
                log("init: no valid ticket in the mapping");
                return -1;
            }
        }
        drop(st);
        if !signal_ready(&name) {
            log("init: ready event not found");
        }
        0
    }

    extern "system" fn shim_close() {
        let mut st = STATE.lock().unwrap();
        wipe_u16(&mut st.ticket);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = r"Local\mabi-patcher.ticket.{01234567-89AB-CDEF-0123-456789ABCDEF}";

    #[test]
    fn map_name_validation() {
        assert!(is_ticket_map_name(MAP));
        assert!(!is_ticket_map_name(r"Local\mabi-patcher.ticket.{nope}"));
        assert!(!is_ticket_map_name(r"Global\mabi-patcher.ticket.{01234567-89AB-CDEF-0123-456789ABCDEF}"));
        assert!(!is_ticket_map_name(""));
    }

    #[test]
    fn command_line_fallback() {
        let cl = format!(r#""C:\Nexon\Mabinogi\Client.exe" code:1622 /P:abc --mabi-map {}"#, MAP);
        assert_eq!(map_name_from_command_line(&cl), Some(MAP));
        assert_eq!(map_name_from_command_line(&format!("x --mabi-map \"{}\"", MAP)), Some(MAP));
        assert_eq!(map_name_from_command_line("Client.exe /P:abc"), None);
        assert_eq!(map_name_from_command_line("Client.exe --mabi-map"), None);
        assert_eq!(map_name_from_command_line(r"Client.exe --mabi-map Local\other"), None);
    }

    #[test]
    fn decode() {
        let mut v = vec![0u8; TICKET_MAP_CAPACITY];
        v[..4].copy_from_slice(b"MPT1");
        v[4..8].copy_from_slice(&3u32.to_le_bytes());
        v[8..11].copy_from_slice(b"abc");
        assert_eq!(decode_ticket(&v).as_deref(), Some("abc"));
        v[4..8].copy_from_slice(&5000u32.to_le_bytes());
        assert_eq!(decode_ticket(&v), None, "length past the view");
        assert_eq!(decode_ticket(&vec![0u8; TICKET_MAP_CAPACITY]), None, "zeroed");
        assert_eq!(decode_ticket(b"MPT1"), None);
    }
}
