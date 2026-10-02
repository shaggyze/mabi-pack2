// "Start with Windows": a per-user Run entry that starts the GUI hidden in the
// tray. The value is the quoted exe path plus `--minimized`, so paths with
// spaces work (an unquoted path would be split at the first space).

use anyhow::Result;
use std::path::Path;

/// Command-line flag: start hidden in the system tray.
pub const MINIMIZED_FLAG: &str = "--minimized";
/// Name of the value under HKCU\...\CurrentVersion\Run.
#[cfg_attr(not(windows), allow(dead_code))]
const RUN_VALUE: &str = "mabi-patcher";
#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The Run value for `exe`: `"<exe>" --minimized`.
pub fn run_command(exe: &Path) -> String {
    format!("\"{}\" {}", exe.display(), MINIMIZED_FLAG)
}

/// True if the process arguments (after the program name) ask for a tray start.
pub fn wants_minimized<S: AsRef<str>>(args: &[S]) -> bool {
    args.iter().any(|a| a.as_ref() == MINIMIZED_FLAG)
}

/// True if the Run value starts this exe (quoted or an older unquoted form,
/// with or without `--minimized`; compared case-insensitively, as Windows does).
#[cfg_attr(not(windows), allow(dead_code))]
fn run_value_targets(value: &str, exe: &Path) -> bool {
    let v = value.trim();
    let prog = match v.strip_prefix('"') {
        Some(rest) => match rest.find('"') {
            Some(end) => &rest[..end],
            None => return false,
        },
        None => v.strip_suffix(MINIMIZED_FLAG).unwrap_or(v).trim_end(),
    };
    let norm = |s: &str| s.replace('/', "\\").to_lowercase();
    !prog.is_empty() && norm(prog) == norm(&exe.to_string_lossy())
}

/// True if this exe's Run entry exists and points to this exe (whatever its
/// exact form, e.g. an older unquoted one, which `set_enabled(true)` rewrites quoted).
pub fn is_enabled() -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(_) => return false,
        };
        winreg::RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(RUN_KEY)
            .and_then(|k| k.get_value::<String, _>(RUN_VALUE))
            .map(|v| run_value_targets(&v, &exe))
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    false
}

/// Add (quoted, with `--minimized`) or remove this exe's Run entry.
pub fn set_enabled(enabled: bool) -> Result<()> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
        let hkcu = winreg::RegKey::predef(HKEY_CURRENT_USER);
        if enabled {
            let (key, _) = hkcu.create_subkey(RUN_KEY)?;
            key.set_value(RUN_VALUE, &run_command(&std::env::current_exe()?))?;
        } else if let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) {
            match key.delete_value(RUN_VALUE) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err(anyhow::anyhow!("Start with Windows is only available on Windows"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_command_is_quoted_with_minimized() {
        let exe = Path::new(r"C:\Program Files\mabi patcher\mabi-patcher.exe");
        assert_eq!(run_command(exe), r#""C:\Program Files\mabi patcher\mabi-patcher.exe" --minimized"#);
        assert!(wants_minimized(&["--minimized"]));
        assert!(wants_minimized(&["x".to_string(), "--minimized".to_string()]));
        assert!(!wants_minimized(&["--minimize", "minimized"]));
        assert!(!wants_minimized::<&str>(&[]));
    }

    #[test]
    fn run_value_targets_only_this_exe() {
        let exe = Path::new(r"C:\Program Files\mabi patcher\mabi-patcher.exe");
        assert!(run_value_targets(&run_command(exe), exe));
        assert!(run_value_targets(r#""c:\program files\MABI PATCHER\mabi-patcher.exe""#, exe));
        assert!(run_value_targets(r"C:\Program Files\mabi patcher\mabi-patcher.exe --minimized", exe));
        assert!(!run_value_targets(r#""C:\Old\mabi-patcher.exe" --minimized"#, exe));
        assert!(!run_value_targets("", exe));
        assert!(!run_value_targets(r#""C:\Program Files"#, exe));
    }
}
