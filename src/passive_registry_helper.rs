//! Read-only passive registry observation for the private Windows candidate.
use std::io::{self, Write};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Globalization::{
    GetUserDefaultLocaleName, LCMapStringEx, LCMAP_LINGUISTIC_CASING, LCMAP_LOWERCASE,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid, SECURITY_MAX_SID_SIZE,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use winreg::{enums::*, RegKey, RegValue};

pub(crate) const ROLE: &str = "--private-passive-registry-observation";

struct Failure {
    stage: &'static str,
    native_code: Option<u32>,
}

impl Failure {
    fn model(stage: &'static str) -> Self {
        Self {
            stage,
            native_code: None,
        }
    }

    fn last_native(stage: &'static str) -> Self {
        Self {
            stage,
            native_code: Some(unsafe { GetLastError() }),
        }
    }

    fn io(stage: &'static str, error: io::Error) -> Self {
        Self {
            stage,
            native_code: error.raw_os_error().map(|code| code as u32),
        }
    }
}

enum Value {
    Missing,
    Text(String),
    Multi(Vec<String>),
    NonString,
}

fn utf16_units(bytes: &[u8]) -> Result<Vec<u16>, Failure> {
    if bytes.len() % 2 != 0 {
        return Err(Failure::model("registry_utf16_size"));
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

fn scalar_text(units: &[u16]) -> Result<String, Failure> {
    if units.contains(&0) {
        return Err(Failure::model("registry_embedded_nul"));
    }
    String::from_utf16(units).map_err(|_| Failure::model("registry_utf16"))
}

fn multi_text(units: &[u16]) -> Result<Vec<String>, Failure> {
    let mut fields = Vec::new();
    let mut start = 0;
    for (index, &unit) in units.iter().enumerate() {
        if unit == 0 {
            // The Framework drops the extra final terminator and retains interior empty items.
            if start != index || index + 1 != units.len() {
                fields.push(scalar_text(&units[start..index])?);
            }
            start = index + 1;
        }
    }
    if start < units.len() {
        fields.push(scalar_text(&units[start..])?);
    }
    Ok(fields)
}

fn expand_environment(text: String) -> Result<String, Failure> {
    if text.is_empty() {
        return Ok(text);
    }
    let input: Vec<_> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let capacity = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), null_mut(), 0) };
    if capacity == 0 {
        return Err(Failure::last_native("expand_size"));
    }
    let mut output = vec![0u16; capacity as usize];
    let received =
        unsafe { ExpandEnvironmentStringsW(input.as_ptr(), output.as_mut_ptr(), capacity) };
    if received == 0 {
        return Err(Failure::last_native("expand_read"));
    }
    let end = received as usize - 1;
    if output.get(end) != Some(&0) {
        return Err(Failure::model("expand_shape"));
    }
    scalar_text(&output[..end])
}

fn decode(raw: RegValue<'_>) -> Result<Value, Failure> {
    match raw.vtype {
        REG_SZ | REG_EXPAND_SZ => {
            let units = utf16_units(&raw.bytes)?;
            let text = scalar_text(units.strip_suffix(&[0]).unwrap_or(&units))?;
            if raw.vtype == REG_EXPAND_SZ {
                expand_environment(text).map(Value::Text)
            } else {
                Ok(Value::Text(text))
            }
        }
        REG_MULTI_SZ => multi_text(&utf16_units(&raw.bytes)?).map(Value::Multi),
        // The Framework exposes these as byte arrays or numeric scalars.
        REG_NONE | REG_BINARY | REG_DWORD_BIG_ENDIAN => Ok(Value::NonString),
        REG_DWORD if raw.bytes.len() == 4 => Ok(Value::NonString),
        REG_QWORD if raw.bytes.len() == 8 => Ok(Value::NonString),
        REG_DWORD | REG_QWORD => Err(Failure::model("registry_number_width")),
        _ => Err(Failure::model("registry_value_kind")),
    }
}

fn field(key: &RegKey, name: &str, stage: &'static str) -> Result<Value, Failure> {
    match key.get_raw_value(name) {
        Ok(value) => decode(value),
        Err(error) if error.raw_os_error() == Some(2) => Ok(Value::Missing),
        Err(error) => Err(Failure::io(stage, error)),
    }
}

struct LocaleMatcher {
    name: Vec<u16>,
    desktop: Vec<u16>,
    cli: Vec<u16>,
}

impl LocaleMatcher {
    fn current_user() -> Result<Self, Failure> {
        // Windows SDK LOCALE_NAME_MAX_LENGTH, including the trailing NUL.
        const LOCALE_NAME_MAX_LENGTH: i32 = 85;
        let mut buffer = [0u16; LOCALE_NAME_MAX_LENGTH as usize];
        let count =
            unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), LOCALE_NAME_MAX_LENGTH) };
        if count == 0 {
            return Err(Failure::last_native("locale_name"));
        }
        if !(1..=LOCALE_NAME_MAX_LENGTH).contains(&count) {
            return Err(Failure::model("locale_name_shape"));
        }
        let name = buffer[..count as usize].to_vec();
        if !matches!(name.split_last(), Some((&0, prefix)) if !prefix.contains(&0)) {
            return Err(Failure::model("locale_name_shape"));
        }
        let desktop = lower_for_comparison(&name, "Antigravity")?;
        let cli = lower_for_comparison(&name, "agy")?;
        Ok(Self { name, desktop, cli })
    }

    fn matches_text(&self, value: &str, include_cli: bool) -> Result<bool, Failure> {
        let mapped = lower_for_comparison(&self.name, value)?;
        let contains = |needle: &[u16]| mapped.windows(needle.len()).any(|part| part == needle);
        Ok(contains(&self.desktop) || (include_cli && contains(&self.cli)))
    }

    fn matches(&self, value: &Value, include_cli: bool) -> Result<bool, Failure> {
        match value {
            Value::Text(text) => self.matches_text(text, include_cli),
            Value::Multi(items) => {
                for item in items {
                    if self.matches_text(item, include_cli)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Value::Missing | Value::NonString => Ok(false),
        }
    }
}

fn lower_for_comparison(name: &[u16], value: &str) -> Result<Vec<u16>, Failure> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let units: Vec<_> = value.encode_utf16().collect();
    let length = i32::try_from(units.len()).map_err(|_| Failure::model("locale_input_length"))?;
    let flags = LCMAP_LOWERCASE | LCMAP_LINGUISTIC_CASING;
    let capacity = unsafe {
        LCMapStringEx(
            name.as_ptr(),
            flags,
            units.as_ptr(),
            length,
            null_mut(),
            0,
            null(),
            null(),
            0,
        )
    };
    if capacity == 0 {
        return Err(Failure::last_native("locale_mapping_size"));
    }
    let mut output = vec![0u16; capacity as usize];
    let received = unsafe {
        LCMapStringEx(
            name.as_ptr(),
            flags,
            units.as_ptr(),
            length,
            output.as_mut_ptr(),
            capacity,
            null(),
            null(),
            0,
        )
    };
    if received == 0 {
        return Err(Failure::last_native("locale_mapping_read"));
    }
    if received != capacity || output.contains(&0) {
        return Err(Failure::model("locale_mapping_output"));
    }
    Ok(output)
}

fn selected_location(matched: bool, location: Value) -> Result<Option<String>, Failure> {
    if !matched {
        return Ok(None);
    }
    match location {
        Value::Missing => Ok(None),
        Value::Text(text) => Ok((!text.chars().all(char::is_whitespace)).then_some(text)),
        Value::Multi(_) | Value::NonString => Err(Failure::model("selected_non_string_location")),
    }
}

fn scan(matcher: &LocaleMatcher) -> Result<Vec<String>, Failure> {
    let roots = [
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ];
    let mut locations = Vec::new();
    let access = KEY_READ | KEY_WOW64_64KEY;
    for (handle, relative) in roots {
        let hive = RegKey::predef(handle);
        let root = match hive.open_subkey_with_flags(relative, access) {
            Ok(root) => root,
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue,
            Err(error) => return Err(Failure::io("root_open", error)),
        };
        let names = root
            .enum_keys_os_string()
            .collect::<io::Result<Vec<_>>>()
            .map_err(|error| Failure::io("enumerate_entries", error))?;
        for name in names {
            let entry = root
                .open_subkey_with_flags(&name, access)
                .map_err(|error| Failure::io("entry_open", error))?;
            let display = field(&entry, "DisplayName", "display_name_read")?;
            let location = field(&entry, "InstallLocation", "install_location_read")?;
            let matched = matcher.matches(&display, true)? || matcher.matches(&location, false)?;
            if let Some(location) = selected_location(matched, location)? {
                locations.push(location);
            }
        }
    }
    Ok(locations)
}

pub(crate) fn ordinary_actor() -> bool {
    require_ordinary_token().is_ok()
}

fn require_ordinary_token() -> Result<(), Failure> {
    let mut sid = [0u32; SECURITY_MAX_SID_SIZE as usize / 4];
    let mut capacity = std::mem::size_of_val(&sid) as u32;
    let pointer = sid.as_mut_ptr().cast();
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            pointer,
            &mut capacity,
        )
    } == 0
    {
        return Err(Failure::last_native("ordinary_token_sid"));
    }
    let mut admin = 0;
    if unsafe { CheckTokenMembership(null_mut(), pointer, &mut admin) } == 0 {
        return Err(Failure::last_native("ordinary_token_query"));
    }
    if admin != 0 {
        return Err(Failure::model("ordinary_token_required"));
    }
    Ok(())
}

fn require_ingress() -> Result<(), Failure> {
    let out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if out.is_null() || out == INVALID_HANDLE_VALUE || unsafe { GetFileType(out) } != FILE_TYPE_PIPE
    {
        return Err(Failure::model("private_pipe_required"));
    }
    if !cfg!(target_arch = "x86_64")
        || crate::current_registry_machine_pair()
            != Some((crate::MACHINE_UNKNOWN, crate::MACHINE_AMD64))
    {
        return Err(Failure::model("native_x64_required"));
    }
    require_ordinary_token()
}

fn emit(locations: &[String]) -> Result<(), Failure> {
    let mut bytes = serde_json::to_vec(locations).map_err(|_| Failure::model("wire_encode"))?;
    bytes.extend_from_slice(b"\nAG_END\n");
    let mut pipe = io::stdout().lock();
    pipe.write_all(&bytes)
        .and_then(|()| pipe.flush())
        .map_err(|error| Failure::io("pipe_write", error))
}

pub(crate) fn run() -> i32 {
    let result = require_ingress().and_then(|()| {
        let matcher = LocaleMatcher::current_user()?;
        emit(&scan(&matcher)?)
    });
    if let Err(failure) = result {
        let diagnostic =
            serde_json::json!({"stage": failure.stage, "native_code": failure.native_code});
        let _ = writeln!(io::stderr().lock(), "{diagnostic}");
        return 1;
    }
    0
}
