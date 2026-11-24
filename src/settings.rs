//! What the user switched on, remembered between runs.
//!
//! The old build had no such file: state lived only in the system (an NRPT rule
//! either exists or does not) and the menu asked again every time. A switch UI
//! needs both — the *system* answers "is it on right now", this answers "is it
//! on because the user asked for it", which is what lets the app put a switch
//! back where the user left it and re-apply after a reboot wiped something.
//!
//! General consumers use the existing best-effort settings behavior. The
//! persistent macOS watchdog separately requires readable, parsed intent.
//!
//! Lives in the relay's state directory, next to `upstream.txt`, and for the same
//! reason: the relay task runs **as this user** under an S4U principal, not as
//! SYSTEM, so per-user state is exactly what both processes can reach. It is
//! also why the provider deny-list needs no second copy anywhere — one file,
//! re-read rather than cached, is the pattern `upstream::configured` already
//! set (src/upstream.rs:286).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(not(test))]
use std::time::Duration;
use std::time::Instant;

const FILE_NAME: &str = "settings.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransportProfile {
    SystemTcp,
    ExistingConfigured,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum TransportProfileSetting {
    #[default]
    Absent,
    Explicit(TransportProfile),
    Invalid(serde_json::Value),
}

impl TransportProfileSetting {
    fn is_absent(&self) -> bool { matches!(self, Self::Absent) }
}

fn decode_present_transport_profile<'de, D: serde::Deserializer<'de>>(d: D) -> Result<TransportProfileSetting, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(match serde_json::from_value(value.clone()) {
        Ok(profile) => TransportProfileSetting::Explicit(profile),
        Err(_) => TransportProfileSetting::Invalid(value),
    })
}

fn encode_transport_profile<S: serde::Serializer>(value: &TransportProfileSetting, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        TransportProfileSetting::Absent => serializer.serialize_none(),
        TransportProfileSetting::Explicit(profile) => profile.serialize(serializer),
        TransportProfileSetting::Invalid(raw) => raw.serialize(serializer),
    }
}

/// A complete, saved transport tuple. This value is configuration, not proof
/// that any service, listener or process actually implements it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveTransportConfig {
    pub(crate) profile: TransportProfile,
    pub(crate) dns: bool,
    pub(crate) client_proxy: bool,
    pub(crate) tcp_proxy: bool,
    pub(crate) dns_alias: bool,
}

impl ActiveTransportConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if (self.client_proxy && !self.tcp_proxy) || self.dns_alias != (self.dns && self.client_proxy) {
            return Err("contradictory transport capabilities".into());
        }
        if self.profile == TransportProfile::SystemTcp
            && (self.dns || self.dns_alias || self.client_proxy != self.tcp_proxy) {
            return Err("contradictory system transport configuration".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransportRequirements {
    pub(crate) active_config: ActiveTransportConfig,
    pub(crate) carrier: bool,
    /// Missing watchdog fields do not borrow a default as new authority.
    pub(crate) watchdog: Option<bool>,
}

/// A received component wish. Unspecified and Inactive are both Keep for
/// effects; neither is a negative choice or runtime readiness evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportWish { Set(bool), Unspecified, Inactive }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransportEffects {
    pub(crate) dns: TransportWish,
    pub(crate) local_proxy: TransportWish,
    pub(crate) builtin_exits: TransportWish,
    pub(crate) group_proxy: TransportWish,
    pub(crate) own_proxy_enabled: TransportWish,
    pub(crate) carrier: TransportWish,
    pub(crate) watchdog: TransportWish,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TransportChoices {
    pub(crate) dns: Option<bool>,
    pub(crate) local_proxy: Option<bool>,
    pub(crate) builtin_exits: Option<bool>,
    pub(crate) group_proxy: Option<bool>,
    pub(crate) own_proxy_enabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) enum TransportIntent {
    Missing,
    Legacy(Settings),
    Explicit { settings: Settings, requirements: TransportRequirements },
    Broken(String),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TransportChoice {
    Dns(bool), LocalProxy(bool), BuiltinExits(bool), GroupProxy(bool),
    OwnProxyEnabled(bool), AutoPatch(bool), PatchDeclined(bool),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TransportEdit {
    pub(crate) value_changed: bool,
    pub(crate) presence_changed: bool,
}

#[derive(Clone, Copy)]
struct TransportField {
    key: &'static str,
    required: u8,
    get: fn(&Settings) -> bool,
    set: fn(&mut Settings, bool),
}
const SYSTEM_FIELD: u8 = 1;
const EXISTING_FIELD: u8 = 2;
const WATCHDOG_FIELD: u8 = 4;
const TRANSPORT_FIELDS: [TransportField; 7] = [
    TransportField { key: "dns", required: SYSTEM_FIELD | EXISTING_FIELD, get: |s| s.dns, set: |s, v| s.dns = v },
    TransportField { key: "local_proxy", required: SYSTEM_FIELD | EXISTING_FIELD, get: |s| s.local_proxy, set: |s, v| s.local_proxy = v },
    TransportField { key: "builtin_exits", required: EXISTING_FIELD, get: |s| s.builtin_exits, set: |s, v| s.builtin_exits = v },
    TransportField { key: "group_proxy", required: EXISTING_FIELD, get: |s| s.group_proxy, set: |s, v| s.group_proxy = v },
    TransportField { key: "own_proxy_enabled", required: EXISTING_FIELD, get: |s| s.own_proxy_enabled, set: |s, v| s.own_proxy_enabled = v },
    TransportField { key: "auto_patch", required: WATCHDOG_FIELD, get: |s| s.auto_patch, set: |s, v| s.auto_patch = v },
    TransportField { key: "patch_declined", required: WATCHDOG_FIELD, get: |s| s.patch_declined, set: |s, v| s.patch_declined = v },
];

#[derive(Debug, Clone)]
pub(crate) struct TransportInput {
    present: [bool; 7],
    baseline: [bool; 7],
    profile_baseline: TransportProfileSetting,
    unreadable: bool,
}

impl Default for TransportInput {
    fn default() -> Self {
        Self { present: [false; 7], baseline: [false; 7],
            profile_baseline: TransportProfileSetting::Absent, unreadable: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Absence is a legacy file, regardless of the struct's default.
    #[serde(default, deserialize_with = "decode_present_transport_profile", serialize_with = "encode_transport_profile", skip_serializing_if = "TransportProfileSetting::is_absent")]
    pub(crate) transport_profile: TransportProfileSetting,
    #[serde(skip)]
    pub(crate) transport_input: TransportInput,
    /// WSL intent; None preserves the distinction for older settings files.
    pub wsl: Option<crate::wsl_api::WslPreferences>,
    /// Switch 1: the client patch that lifts the account-region block.
    pub client_patch: bool,

    /// Patch Antigravity by itself: a fresh install as much as one an update
    /// wiped (D27).
    ///
    /// Read by the *watchdog process*, not just the window, which is why it goes
    /// through the settings reader rather than being consulted from an
    /// in-memory `Settings` the watchdog never sees.
    pub auto_patch: bool,

    #[serde(default)]
    pub group_key: String,

    /// The licence key this machine last had accepted. Kept so a restart or an
    /// `_N` update starts straight on the main screen; a key for another 3-digit
    /// version fails `auth::verify_key` and the licence screen comes back.
    #[serde(default)]
    pub license_key: String,

    /// When the group code and the user's own proxy were last set (unix
    /// seconds, 0 = never). The one added later goes first in the route table
    /// (owner, 2026-10-05).
    #[serde(default)]
    pub group_key_at: u64,
    #[serde(default)]
    pub own_proxy_at: u64,

    /// The user switched the client patch **off** on purpose.
    ///
    /// The one thing auto-patch must never do is put back a patch the user took
    /// off (G38), so that wish is kept here and not read off `client_patch`:
    /// `client_patch` false is also every machine that simply has not patched
    /// yet - which is exactly who auto-patch is for. Gating on it left a fresh
    /// Desktop 2.15.0 unpatched with auto-patch on, and its window came up black
    /// (owner, 2026-09-19).
    pub patch_declined: bool,

    /// Read from a file written before `patch_declined` existed, so the field
    /// above is `parse`'s conservative guess rather than something the user
    /// said. The window settles it once at start (`ops::settle_decline`) and
    /// saves it. Never written to the file.
    #[serde(skip)]
    pub decline_unrecorded: bool,

    /// Switch 2 and its parts. The master switch is not stored separately: it is
    /// on when any of its parts is, which keeps one truth instead of two.
    pub dns: bool,
    pub local_proxy: bool,
    pub builtin_exits: bool,
    pub group_proxy: bool,

    /// Diagnostics only, set by hand in `settings.json`, never by the window:
    /// the one route the gate hosts may take (`own`, `group`, `exits`, `relay`,
    /// `direct`, `vpn`), so a measurement can say which path it timed. Empty =
    /// the normal route table. A named route that is not usable yields no route
    /// at all rather than quietly measuring another one.
    #[serde(default)]
    pub debug_route: String,

    /// Providers the user turned off by name. A deny-list rather than an
    /// allow-list on purpose: a provider added in a later release is then on by
    /// default instead of silently missing from everyone's saved settings.
    pub disabled_providers: Vec<String>,

    /// The user's own DNS server(s) for the bypass: IPv4 addresses separated by
    /// spaces, commas or semicolons. They join the pool as one more provider
    /// («свой DNS»): raced with the others, every answer judged against the
    /// reference resolver, so a server that does not substitute the gate hosts
    /// costs nothing. Empty means the slot is unused.
    #[serde(default)]
    pub custom_dns: String,

    /// Whether every enabled provider may answer, or only the first one.
    ///
    /// On (the default) is what the pool was built for: each query is raced and
    /// the answer verified against a reference resolver, so a provider that
    /// silently drops a name costs nothing. Off pins the layer to the first
    /// enabled provider in pool order - for a user who wants exactly one service
    /// seeing their lookups, at the price of having no fallback when it stops
    /// substituting.
    pub rotate_providers: bool,

    /// The user's own order for the DNS pool, by name.
    ///
    /// Empty means the compiled order, which is ordered by measured substitution.
    /// It matters most with rotation off, where the *first* enabled provider is
    /// the only one asked - so being able to say which one that is is the point.
    /// Names not listed here keep their compiled position after the listed ones,
    /// so a provider added in a later release is never silently dropped.
    pub provider_order: Vec<String>,

    /// Unused since D25 (`2.14.0_1`): the rules are installed whatever the
    /// tunnel does, and the relay decides at runtime what they answer. Kept so
    /// a file written by an older build still loads, and an older build reading
    /// a newer file still finds its field.
    pub vpn_detect: bool,

    /// No longer a switch: the certificate of a substituted address is always
    /// verified, and an address that passed is trusted for a day (`resolvers.rs`,
    /// `TLS_VERIFIED_FOR`). Stays in the file so an older build still finds it.
    #[allow(dead_code)]
    pub verify_tls: bool,

    /// The user's own HTTP proxy ("bring your own exit"). Kept even while off so
    /// flipping the switch back does not mean typing it again.
    pub own_proxy: String,
    pub own_proxy_enabled: bool,

    /// Installs the user pointed at by hand, on top of the ones found by the
    /// scan (the pencil next to each path).
    pub manual_paths: Vec<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        // Group proxy is opt-in; the other region bypass defaults remain enabled.
        let mut settings = Self {
            transport_profile: TransportProfileSetting::Absent,
            transport_input: TransportInput::default(),
            wsl: None,
            client_patch: false,
            auto_patch: true,
            group_key: String::new(),
            license_key: String::new(),
            group_key_at: 0,
            own_proxy_at: 0,
            patch_declined: false,
            decline_unrecorded: false,
            dns: true,
            local_proxy: true,
            builtin_exits: true,
            group_proxy: false,
            debug_route: String::new(),
            disabled_providers: Vec::new(),
            custom_dns: String::new(),
            rotate_providers: true,
            provider_order: Vec::new(),
            vpn_detect: true,
            verify_tls: true,
            own_proxy: String::new(),
            own_proxy_enabled: false,
            manual_paths: Vec::new(),
        };
        settings.transport_input.baseline = settings.transport_values();
        settings
    }
}

impl Settings {
    pub fn load() -> Self {
        match read() {
            Read::Parsed(s) => s,
            Read::Missing => Self::default(),
            Read::Unavailable => Self::unavailable(),
            Read::Broken => Self::unreadable(),
        }
    }

    /// What a file that exists but cannot be read stands for: the defaults,
    /// minus the one that acts on the user's files by itself. With saves atomic
    /// a broken file is real damage, and it may have been a user's "patch off".
    fn unreadable() -> Self {
        Self {
            patch_declined: true,
            transport_input: TransportInput { unreadable: true, ..TransportInput::default() },
            ..Self::default()
        }
    }

    fn unavailable() -> Self {
        Self { transport_input: TransportInput { unreadable: true, ..TransportInput::default() }, ..Self::default() }
    }

    /// Compatibility wrapper for the checked settings writer.
    pub fn save(&self) -> bool {
        self.save_checked().is_ok()
    }

    pub(crate) fn save_checked(&self) -> Result<(), String> {
        let json = self.encode_for_save()?;
        let path = path().ok_or("settings path unavailable")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("settings directory: {e}"))?;
        }
        write_replacing(&path, &json).map_err(|e| format!("settings write: {e}"))?;
        // Cache the same decoded bytes that were written, including normalized
        // watchdog state and the still-absent transport choices.
        let received = parse(&json).ok_or("written settings could not be decoded")?;
        if let Ok(mut guard) = CACHE.lock() {
            *guard = Some((received, Instant::now()));
        }
        Ok(())
    }

    /// Whether Antigravity is to be patched without a click: auto-patch on, and
    /// the patch never switched off by hand since.
    pub fn auto_patch_wanted(&self) -> bool {
        self.auto_patch && !self.patch_declined
    }

    fn transport_values(&self) -> [bool; 7] {
        TRANSPORT_FIELDS.map(|field| (field.get)(self))
    }

    fn validate_transport_edits(&self) -> Result<(), String> {
        if self.transport_input.unreadable { return Err("settings input is unreadable".into()); }
        if self.transport_profile != self.transport_input.profile_baseline {
            return Err("transport_profile requires an explicit profile selection".into());
        }
        let values = self.transport_values();
        for (index, field) in TRANSPORT_FIELDS.iter().enumerate() {
            if field.required & (SYSTEM_FIELD | EXISTING_FIELD) != 0
                && !self.transport_input.present[index] && values[index] != self.transport_input.baseline[index] {
                return Err(format!("{} requires an explicit transport choice", field.key));
            }
        }
        Ok(())
    }

    pub(crate) fn encode_for_save(&self) -> Result<String, String> {
        self.validate_transport_edits()?;
        let mut value = serde_json::to_value(self).map_err(|e| format!("settings serialization: {e}"))?;
        let object = value.as_object_mut().ok_or("settings serialization is not an object")?;
        for (index, field) in TRANSPORT_FIELDS.iter().enumerate() {
            if field.required & (SYSTEM_FIELD | EXISTING_FIELD) != 0 && !self.transport_input.present[index] { object.remove(field.key); }
        }
        serde_json::to_string_pretty(&value).map_err(|e| format!("settings serialization: {e}"))
    }

    pub(crate) fn set_transport_choice(&mut self, choice: TransportChoice) -> Result<TransportEdit, String> {
        if self.transport_input.unreadable { return Err("settings input is unreadable".into()); }
        let (index, value) = match choice {
            TransportChoice::Dns(value) => (0, value), TransportChoice::LocalProxy(value) => (1, value),
            TransportChoice::BuiltinExits(value) => (2, value), TransportChoice::GroupProxy(value) => (3, value),
            TransportChoice::OwnProxyEnabled(value) => (4, value), TransportChoice::AutoPatch(value) => (5, value),
            TransportChoice::PatchDeclined(value) => (6, value),
        };
        if index == 0 && value && matches!(self.transport_profile, TransportProfileSetting::Explicit(TransportProfile::SystemTcp)) {
            return Err("system TCP transport cannot enable DNS ingress".into());
        }
        let prior = self.transport_values()[index];
        let presence_changed = !self.transport_input.present[index];
        (TRANSPORT_FIELDS[index].set)(self, value);
        self.transport_input.present[index] = true;
        Ok(TransportEdit { value_changed: prior != value, presence_changed })
    }

    pub(crate) fn select_system_tcp(&mut self) -> Result<TransportEdit, String> {
        self.select_transport_profile(TransportProfile::SystemTcp, [false, true, self.builtin_exits, self.group_proxy, self.own_proxy_enabled])
    }

    pub(crate) fn select_existing_configured(&mut self, dns: bool, local_proxy: bool, builtin_exits: bool, group_proxy: bool, own_proxy_enabled: bool) -> Result<TransportEdit, String> {
        self.select_transport_profile(TransportProfile::ExistingConfigured, [dns, local_proxy, builtin_exits, group_proxy, own_proxy_enabled])
    }

    fn select_transport_profile(&mut self, profile: TransportProfile, values: [bool; 5]) -> Result<TransportEdit, String> {
        if self.transport_input.unreadable { return Err("settings input is unreadable".into()); }
        if profile == TransportProfile::SystemTcp && values[0] { return Err("system TCP transport cannot enable DNS ingress".into()); }
        let mut staged = self.clone();
        let old = staged.transport_values();
        let old_profile = staged.transport_profile.clone();
        let required = match profile { TransportProfile::SystemTcp => SYSTEM_FIELD, TransportProfile::ExistingConfigured => EXISTING_FIELD };
        let mut presence_changed = matches!(old_profile, TransportProfileSetting::Absent);
        let mut changed = old_profile != TransportProfileSetting::Explicit(profile);
        for (index, field) in TRANSPORT_FIELDS.iter().enumerate().filter(|(_, field)| field.required & required != 0) {
            presence_changed |= !staged.transport_input.present[index];
            changed |= old[index] != values[index];
            (field.set)(&mut staged, values[index]);
            staged.transport_input.present[index] = true;
        }
        staged.transport_profile = TransportProfileSetting::Explicit(profile);
        staged.transport_input.profile_baseline = staged.transport_profile.clone();
        staged.transport_requirements()?;
        *self = staged;
        Ok(TransportEdit { value_changed: changed, presence_changed })
    }

    pub(crate) fn transport_requirements(&self) -> Result<TransportRequirements, String> {
        let profile = match self.transport_profile {
            TransportProfileSetting::Explicit(profile) => profile,
            TransportProfileSetting::Absent => return Err("transport profile is absent".into()),
            TransportProfileSetting::Invalid(_) => return Err("transport profile is invalid".into()),
        };
        let effects = self.checked_transport_effects()?;
        let client_proxy = self.local_proxy;
        let tcp_proxy = [effects.local_proxy, effects.builtin_exits, effects.group_proxy, effects.own_proxy_enabled]
            .into_iter().any(|wish| wish == TransportWish::Set(true));
        let active_config = ActiveTransportConfig { profile, dns: self.dns, client_proxy, tcp_proxy, dns_alias: self.dns && client_proxy };
        active_config.validate()?;
        let carrier = match effects.carrier {
            TransportWish::Set(value) => value,
            _ => return Err("transport carrier wish is unreceived".into()),
        };
        let watchdog = match effects.watchdog { TransportWish::Set(value) => Some(value), _ => None };
        Ok(TransportRequirements { active_config, carrier, watchdog })
    }

    /// View saved choices including inactive preferences; omission stays None.
    /// This is a form input, not a route permission or activation receipt.
    pub(crate) fn transport_choices(&self) -> Result<TransportChoices, String> {
        self.validate_transport_edits()?;
        let mut values = [None; 5];
        for (index, field) in TRANSPORT_FIELDS.iter().enumerate() {
            if field.required & EXISTING_FIELD != 0 && self.transport_input.present[index] {
                values[index] = Some((field.get)(self));
            }
        }
        Ok(TransportChoices { dns: values[0], local_proxy: values[1], builtin_exits: values[2], group_proxy: values[3], own_proxy_enabled: values[4] })
    }

    /// Project one received snapshot into applicable component wishes without
    /// turning omissions or inactive stored preferences into effects.
    pub(crate) fn checked_transport_effects(&self) -> Result<TransportEffects, String> {
        self.validate_transport_edits()?;
        let profile = match self.transport_profile {
            TransportProfileSetting::Absent => None,
            TransportProfileSetting::Explicit(profile) => Some(profile),
            TransportProfileSetting::Invalid(_) => return Err("transport profile is invalid".into()),
        };
        if let Some(profile) = profile {
            let required = match profile { TransportProfile::SystemTcp => SYSTEM_FIELD, TransportProfile::ExistingConfigured => EXISTING_FIELD };
            if TRANSPORT_FIELDS.iter().enumerate().any(|(index, field)| field.required & required != 0 && !self.transport_input.present[index]) {
                return Err("transport tuple has missing or invalid fields".into());
            }
            if profile == TransportProfile::SystemTcp && self.dns {
                return Err("system TCP transport cannot enable DNS ingress".into());
            }
        }
        let mut wishes = [TransportWish::Unspecified; 7];
        for (index, field) in TRANSPORT_FIELDS.iter().enumerate() {
            wishes[index] = if profile == Some(TransportProfile::SystemTcp)
                && field.required & EXISTING_FIELD != 0 && field.required & SYSTEM_FIELD == 0 {
                TransportWish::Inactive
            } else if self.transport_input.present[index] {
                TransportWish::Set((field.get)(self))
            } else { TransportWish::Unspecified };
        }
        let applicable = TRANSPORT_FIELDS.iter().enumerate().filter(|(_, field)| field.required & EXISTING_FIELD != 0);
        let mut any_true = false;
        let mut all_known_off = true;
        for (index, _) in applicable {
            match wishes[index] {
                TransportWish::Set(true) => { any_true = true; all_known_off = false; }
                TransportWish::Set(false) | TransportWish::Inactive => {},
                TransportWish::Unspecified => all_known_off = false,
            }
        }
        let carrier = if any_true { TransportWish::Set(true) } else if all_known_off { TransportWish::Set(false) } else { TransportWish::Unspecified };
        let watchdog_received = TRANSPORT_FIELDS.iter().enumerate().all(|(index, field)| field.required & WATCHDOG_FIELD == 0 || self.transport_input.present[index]);
        let watchdog = if watchdog_received { TransportWish::Set(self.auto_patch_wanted()) } else { TransportWish::Unspecified };
        Ok(TransportEffects { dns: wishes[0], local_proxy: wishes[1], builtin_exits: wishes[2],
            group_proxy: wishes[3], own_proxy_enabled: wishes[4], carrier, watchdog })
    }

    /// Lifecycle wish only. A known wish is not route permission, saved-file
    /// proof, or an observation that the carrier is running or ready.
    pub(crate) fn checked_carrier_wish(&self) -> Result<Option<bool>, String> {
        Ok(match self.checked_transport_effects()?.carrier {
            TransportWish::Set(value) => Some(value),
            TransportWish::Unspecified | TransportWish::Inactive => None,
        })
    }

    pub fn provider_enabled(&self, name: &str) -> bool {
        !self
            .disabled_providers
            .iter()
            .any(|d| d.eq_ignore_ascii_case(name))
    }

    pub fn set_provider_enabled(&mut self, name: &str, on: bool) {
        self.disabled_providers
            .retain(|d| !d.eq_ignore_ascii_case(name));
        if !on {
            self.disabled_providers.push(name.to_string());
        }
    }
}

/// What reading the file found. Missing and broken are told apart because they
/// mean opposite things to the watchdog: no file is a machine nobody configured,
/// and the defaults are right for it; a file that does not parse is usually one
/// caught mid-write by another process, and the defaults say "patch" (D27).
pub(crate) enum Read {
    Parsed(Settings),
    Missing,
    Broken,
    Unavailable,
}

pub(crate) fn read() -> Read {
    let Some(path) = path() else {
        return Read::Unavailable;
    };
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text).map_or(Read::Broken, Read::Parsed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Read::Missing,
        Err(_) => Read::Broken,
    }
}

/// Receive the existing on-disk snapshot without defaulting missing or broken
/// input into permission to activate a transport.
pub(crate) fn checked_transport_intent() -> TransportIntent {
    transport_intent_from_read(read())
}

fn transport_intent_from_read(value: Read) -> TransportIntent {
    match value {
        Read::Missing => TransportIntent::Missing,
        Read::Broken | Read::Unavailable => TransportIntent::Broken("settings unavailable or invalid".into()),
        Read::Parsed(settings) if matches!(settings.transport_profile, TransportProfileSetting::Absent) => TransportIntent::Legacy(settings),
        Read::Parsed(settings) => match settings.transport_requirements() {
            Ok(requirements) => TransportIntent::Explicit { settings, requirements },
            Err(error) => TransportIntent::Broken(error),
        },
    }
}

/// The macOS worker must not turn unreadable saved intent into permission.
#[cfg(target_os = "macos")]
pub(crate) fn watchdog_snapshot() -> Result<Settings, String> {
    let path = path().ok_or("путь настроек автопатча недоступен")?;
    watchdog_snapshot_at(&path)
}

#[cfg(target_os = "macos")]
fn watchdog_snapshot_at(path: &std::path::Path) -> Result<Settings, String> {
    let text = std::fs::read_to_string(&path).map_err(|error| format!("чтение настроек автопатча: {error}"))?;
    parse(&text).ok_or_else(|| "настройки автопатча повреждены".into())
}

/// The file's text as settings, a leading byte-order mark allowed.
///
/// Windows PowerShell 5.1's `Set-Content -Encoding utf8` and older Notepad write
/// one, and serde_json rejects it - which `load` turned into "no file": every
/// switch back at its default, the user's own proxy and paths gone, silently.
///
/// A file without `patch_declined` comes from a build before D27, where "the
/// user switched the patch off" was written as `client_patch` false and nothing
/// else. It reads as declined whenever `client_patch` is false - the side that
/// never puts back a patch the user took off (G38) - and the window refines it
/// once with what only it can check (`ops::settle_decline`).
fn parse(text: &str) -> Option<Settings> {
    let value: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let unrecorded = value.get("patch_declined").is_none();
    let mut s = Settings::deserialize(&value).ok()?;
    if unrecorded {
        s.patch_declined = !s.client_patch;
        s.decline_unrecorded = true;
    }
    receive_transport_fields(&value, &mut s);
    Some(s)
}

fn receive_transport_fields(value: &serde_json::Value, settings: &mut Settings) {
    settings.transport_input.present = TRANSPORT_FIELDS.map(|field| value.get(field.key).is_some_and(serde_json::Value::is_boolean));
    settings.transport_input.baseline = settings.transport_values();
    settings.transport_input.profile_baseline = settings.transport_profile.clone();
    settings.transport_input.unreadable = false;
}

/// A temp beside the file, then a rename over it: a reader in another process -
/// the relay re-reads this every 20 s - sees the old file or the new one, never
/// the empty one `fs::write` leaves between truncating and writing. Per process,
/// so two savers never share a temp.
fn write_replacing(path: &Path, text: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let mut result = std::fs::write(&tmp, text);
    if result.is_ok() {
        // A reader that opened the file without delete sharing - a scanner, an
        // editor - blocks the rename for as long as it holds it. Brief, usually.
        for attempt in 0..3 {
            result = std::fs::rename(&tmp, path);
            if result.is_ok() {
                break;
            }
            if attempt < 2 {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn path() -> Option<PathBuf> {
    let dir = crate::dns_forwarder::checked_log_dir().ok()?;
    if dir.as_os_str().is_empty() {
        return None;
    }
    Some(dir.join(FILE_NAME))
}

/// Bind handoff to the bytes actually persisted by this settings owner.
pub(crate) fn saved_intent_sha256(expected: &Settings) -> Result<[u8; 32], String> {
    let path = path().ok_or_else(|| "settings path unavailable".to_owned())?;
    let bytes = std::fs::read(path).map_err(|e| format!("settings read failed: {e}"))?;
    saved_intent_hash(&bytes, expected)
}

fn saved_intent_hash(bytes: &[u8], expected: &Settings) -> Result<[u8; 32], String> {
    let serialized = expected.encode_for_save()?;
    if bytes != serialized.as_bytes() {
        return Err("saved settings do not match current intent".into());
    }
    Ok(Sha256::digest(bytes).into())
}

/// Receive exactly the saved settings bound by the handoff, without fallback.
pub(crate) fn receive_saved_intent(expected_sha256: &[u8; 32]) -> Result<Settings, String> {
    let path = path().ok_or_else(|| "settings path unavailable".to_owned())?;
    let bytes = std::fs::read(path).map_err(|e| format!("settings read failed: {e}"))?;
    receive_intent_bytes(&bytes, expected_sha256)
}

/// Project only the exact bytes received by the existing saved-intent handoff.
pub(crate) fn receive_saved_transport_intent(expected_sha256: &[u8; 32]) -> Result<TransportIntent, String> {
    receive_saved_intent(expected_sha256).map(|settings| transport_intent_from_read(Read::Parsed(settings)))
}

fn receive_intent_bytes(bytes: &[u8], expected_sha256: &[u8; 32]) -> Result<Settings, String> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if &actual != expected_sha256 {
        return Err("saved settings changed during handoff".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|e| format!("saved settings are invalid: {e}"))?;
    parse(text).ok_or_else(|| "saved settings are invalid".into())
}

/// The settings as a *serving* process must read them.
///
/// The relay resolves on a hot path — one call per DNS query, one per CONNECT —
/// so this is cached behind a short TTL rather than read from disk each time.
/// The TTL is the whole bargain: it lets the window write the file and an
/// already-running relay pick the change up without a restart, which is exactly
/// what `upstream.txt` does and why that file is re-read rather than cached
/// forever (src/upstream.rs:302-308).
///
/// Holds only its own lock and calls into nothing else, so it cannot take part
/// in the cross-module reentrancy I50 forbids.
static CACHE: Mutex<Option<(Settings, Instant)>> = Mutex::new(None);

fn cached() -> Settings {
    // Tests get the defaults, never the machine's file.
    //
    // `resolvers` and `proxy` ask this question deep inside the pool, so without
    // this the pool's own unit tests would depend on whatever the person running
    // them last switched in the window — and the failure looks like a bug in the
    // pool rather than in the harness. Behaviour with real settings is covered
    // where it belongs, by tests that build a `Settings` and pass it in.
    #[cfg(test)]
    return Settings::default();

    #[cfg(not(test))]
    {
        cached_from_disk()
    }
}

/// One serving-settings snapshot for a connection's route selection.
pub(crate) fn routing_snapshot() -> Settings {
    cached()
}

#[cfg(not(test))]
fn cached_from_disk() -> Settings {
    const TTL: Duration = Duration::from_secs(20);

    if let Ok(guard) = CACHE.lock() {
        if let Some((s, at)) = guard.as_ref() {
            if at.elapsed() < TTL {
                return s.clone();
            }
        }
    }
    let fresh = match read() {
        Read::Parsed(s) => s,
        Read::Missing => Settings::default(),
        Read::Unavailable => Settings::unavailable(),
        // Damaged, or held by something mid-write. Keep serving what was last
        // read - or, with nothing read yet, the defaults minus the one that
        // acts on the user's files - for another TTL. Caching this too matters:
        // the relay asks on every query, and a file that stays broken would
        // otherwise be re-read and re-parsed on each one.
        Read::Broken => CACHE
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|(s, _)| s.clone()))
            .unwrap_or_else(Settings::unreadable),
    };
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((fresh.clone(), Instant::now()));
    }
    fresh
}

pub fn disabled_providers_cached() -> Vec<String> {
    cached().disabled_providers
}

/// The user's provider order, for the resolver pool to lay itself out by.
pub fn provider_order_cached() -> Vec<String> {
    cached().provider_order
}

/// Whether the pool may rotate, or only its first enabled member answers.
pub fn rotation_enabled() -> bool {
    cached().rotate_providers
}

/// Whether a VPN carrying Antigravity makes the DNS layer stand down.
///
/// Read from `dns.rs`, which runs in the window *and* in the relay, so it goes
/// through the cache like every other cross-process setting.

/// Whether the watchdog may patch what it finds: auto-patch on, and the patch
/// not switched off by hand (D27).
///
/// The watchdog is a separate process that survives reboots, so this is the only
/// way it can hear about either switch. Without the second half it puts back what
/// the window just removed, seconds later, and the switch flips itself back on
/// (G38). Defaults to on when there is no settings file yet, which is the shipped
/// behaviour.
pub fn auto_patch_wanted() -> bool {
    cached().auto_patch_wanted()
}

/// The installs the user pointed at by hand, so the watchdog keeps them patched
/// too and not only the ones in the standard locations.
pub fn manual_paths() -> Vec<PathBuf> {
    cached().manual_paths
}

/// Whether the user wants the local proxy route at all.
///
/// Read by the relay, which restores the proxy variable at every start: without
/// this it put back a route the window had just switched off.
pub fn local_proxy_wanted() -> bool {
    cached().local_proxy
}

/// Whether the user-selected group proxy may be used as a route.
/// Missing settings or an omitted choice keep it disabled until explicitly enabled.
pub fn group_proxy_enabled() -> bool {
    cached().group_proxy
}

/// The user's own proxy was set after the group code, so it goes first.
pub fn own_proxy_first() -> bool {
    let c = cached();
    c.own_proxy_at > c.group_key_at
}

pub fn group_key() -> String {
    cached().group_key.clone()
}

pub fn debug_route() -> String {
    cached().debug_route.clone()
}

pub fn builtin_exits_enabled() -> bool {
    cached().builtin_exits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_effects_distinguish_omitted_and_inactive_choices() {
        let legacy = parse(r#"{"auto_patch":true,"patch_declined":false}"#).unwrap();
        let effects = legacy.checked_transport_effects().unwrap();
        assert_eq!(effects.watchdog, TransportWish::Set(true));
        assert_eq!(effects.dns, TransportWish::Unspecified);
        assert_eq!(effects.local_proxy, TransportWish::Unspecified);
        assert_eq!(effects.own_proxy_enabled, TransportWish::Unspecified);
        assert_eq!(effects.carrier, TransportWish::Unspecified);

        let selected = parse(r#"{"transport_profile":"system_tcp","dns":false,"local_proxy":true,"builtin_exits":true,"group_proxy":true,"own_proxy_enabled":true}"#).unwrap();
        let effects = selected.checked_transport_effects().unwrap();
        assert_eq!(effects.dns, TransportWish::Set(false));
        assert_eq!(effects.local_proxy, TransportWish::Set(true));
        assert_eq!(effects.carrier, TransportWish::Set(true));
        assert_eq!(effects.builtin_exits, TransportWish::Inactive);
        assert_eq!(effects.group_proxy, TransportWish::Inactive);
        assert_eq!(effects.own_proxy_enabled, TransportWish::Inactive);
        assert!(selected.builtin_exits && selected.group_proxy && selected.own_proxy_enabled);
        let choices = selected.transport_choices().unwrap();
        assert_eq!(choices.builtin_exits, Some(true));
        assert_eq!(choices.group_proxy, Some(true));
        assert_eq!(choices.own_proxy_enabled, Some(true));
        assert_eq!(legacy.transport_choices().unwrap(), TransportChoices::default());
    }

    #[test]
    fn configured_client_wish_is_part_of_active_identity() {
        let off = parse(r#"{"transport_profile":"existing_configured","dns":false,"local_proxy":false,"builtin_exits":false,"group_proxy":true,"own_proxy_enabled":false}"#).unwrap().transport_requirements().unwrap();
        let on = parse(r#"{"transport_profile":"existing_configured","dns":false,"local_proxy":true,"builtin_exits":false,"group_proxy":true,"own_proxy_enabled":false}"#).unwrap().transport_requirements().unwrap();
        assert!(off.active_config.tcp_proxy && on.active_config.tcp_proxy);
        assert!(!off.active_config.client_proxy && on.active_config.client_proxy);
        assert_ne!(off.active_config, on.active_config);
        let dns = parse(r#"{"transport_profile":"existing_configured","dns":true,"local_proxy":false,"builtin_exits":false,"group_proxy":true,"own_proxy_enabled":false}"#).unwrap().transport_requirements().unwrap();
        assert!(dns.active_config.dns && dns.active_config.tcp_proxy && !dns.active_config.client_proxy && !dns.active_config.dns_alias);
        assert!(ActiveTransportConfig { client_proxy: true, tcp_proxy: false, ..off.active_config }.validate().is_err());
        assert!(serde_json::from_str::<ActiveTransportConfig>(r#"{"profile":"system_tcp","dns":false,"tcp_proxy":true,"dns_alias":false}"#).is_err());
    }

    #[test]
    #[ignore = "requires an isolated U14_QA_DIR-bound Settings owner"]
    fn transport_effects_actual_watchdog_save_keeps_legacy_routes_unspecified() {
        let root = std::path::PathBuf::from(std::env::var_os("U14_QA_DIR").expect("owned fixture directory"));
        assert_eq!(path(), Some(root.join(FILE_NAME)), "fixture must bind the actual Settings owner");
        assert!(matches!(read(), Read::Missing));
        let mut settings = Settings::load();
        settings.set_transport_choice(TransportChoice::AutoPatch(true)).unwrap();
        settings.save_checked().unwrap();
        let Read::Parsed(saved) = read() else { panic!("saved Settings were not parsed") };
        let effects = saved.checked_transport_effects().unwrap();
        assert_eq!(effects.watchdog, TransportWish::Set(true));
        assert_eq!(effects.carrier, TransportWish::Unspecified);
        assert_eq!(effects.dns, TransportWish::Unspecified);
        assert_eq!(effects.local_proxy, TransportWish::Unspecified);
        assert_eq!(effects.builtin_exits, TransportWish::Unspecified);
        assert_eq!(effects.group_proxy, TransportWish::Unspecified);
        assert_eq!(effects.own_proxy_enabled, TransportWish::Unspecified);
    }

    #[test]
    fn carrier_wish_requires_received_choices() {
        assert_eq!(Settings::default().checked_carrier_wish().unwrap(), None);
        assert_eq!(parse(r#"{"group_proxy":true}"#).unwrap().checked_carrier_wish().unwrap(), Some(true));
        assert_eq!(parse(r#"{"dns":false,"local_proxy":false,"builtin_exits":false,"group_proxy":false}"#).unwrap().checked_carrier_wish().unwrap(), None);
        assert_eq!(parse(r#"{"dns":false,"local_proxy":false,"builtin_exits":false,"group_proxy":false,"own_proxy_enabled":false}"#).unwrap().checked_carrier_wish().unwrap(), Some(false));
        let mut explicit_false = parse("{}").unwrap();
        let change = explicit_false.set_transport_choice(TransportChoice::GroupProxy(false)).unwrap();
        assert!(!change.value_changed && change.presence_changed);
        assert_eq!(explicit_false.checked_carrier_wish().unwrap(), None);
        let mut bare = parse("{}").unwrap();
        bare.local_proxy = false;
        assert!(bare.checked_carrier_wish().is_err());
        assert!(parse(r#"{"transport_profile":"unknown"}"#).unwrap().checked_carrier_wish().is_err());
        assert!(parse(r#"{"transport_profile":"system_tcp","dns":true,"local_proxy":true}"#).unwrap().checked_carrier_wish().is_err());
        let system = parse(r#"{"transport_profile":"system_tcp","dns":false,"local_proxy":true}"#).unwrap();
        assert_eq!(system.checked_carrier_wish().unwrap(), Some(system.transport_requirements().unwrap().carrier));
        let existing = parse(r#"{"transport_profile":"existing_configured","dns":false,"local_proxy":false,"builtin_exits":false,"group_proxy":false,"own_proxy_enabled":false}"#).unwrap();
        assert_eq!(existing.checked_carrier_wish().unwrap(), Some(existing.transport_requirements().unwrap().carrier));
    }

    #[test]
    fn transport_intent_preserves_missing_legacy_and_invalid() {
        assert!(matches!(transport_intent_from_read(Read::Missing), TransportIntent::Missing));
        assert!(matches!(transport_intent_from_read(Read::Broken), TransportIntent::Broken(_)));
        assert!(matches!(transport_intent_from_read(Read::Unavailable), TransportIntent::Broken(_)));
        let old = parse(r#"{"dns":false,"own_proxy":"synthetic"}"#).unwrap();
        assert!(matches!(old.transport_profile, TransportProfileSetting::Absent));
        let direct: Settings = serde_json::from_str("{}").unwrap();
        assert!(matches!(direct.transport_profile, TransportProfileSetting::Absent));
        assert!(matches!(transport_intent_from_read(Read::Parsed(old)), TransportIntent::Legacy(_)));
        for bad in [r#"{"transport_profile":"unknown","license_key":"synthetic"}"#, r#"{"transport_profile":null,"license_key":"synthetic"}"#] {
            let settings = parse(bad).unwrap();
            assert!(matches!(settings.transport_profile, TransportProfileSetting::Invalid(_)));
            assert_eq!(settings.license_key, "synthetic");
            let before: serde_json::Value = serde_json::from_str(bad).unwrap();
            let after = serde_json::to_value(&settings).unwrap();
            assert_eq!(before["transport_profile"], after["transport_profile"]);
            assert!(matches!(transport_intent_from_read(Read::Parsed(settings)), TransportIntent::Broken(_)));
        }
        assert!(parse("{").is_none());
    }

    #[test]
    fn transport_explicit_tuple_never_uses_omission_defaults() {
        let valid = parse(r#"{"transport_profile":"system_tcp","dns":false,"local_proxy":true,"builtin_exits":true,"group_proxy":true,"own_proxy":"synthetic"}"#).unwrap();
        let projected = valid.transport_requirements().unwrap();
        assert_eq!(projected.active_config.profile, TransportProfile::SystemTcp);
        assert!(!projected.active_config.dns && !projected.active_config.dns_alias);
        assert!(projected.active_config.tcp_proxy && projected.carrier);
        assert_eq!(projected.watchdog, None);
        assert!(valid.builtin_exits && valid.group_proxy && valid.own_proxy == "synthetic");
        for json in [r#"{"transport_profile":"system_tcp","local_proxy":true}"#,
                     r#"{"transport_profile":"system_tcp","dns":false}"#,
                     r#"{"transport_profile":"system_tcp","dns":true,"local_proxy":true}"#,
                     r#"{"transport_profile":"existing_configured","dns":false,"local_proxy":false}"#] {
            let settings = parse(json).unwrap();
            assert!(matches!(transport_intent_from_read(Read::Parsed(settings)), TransportIntent::Broken(_)));
        }
        let explicit_false = parse(r#"{"transport_profile":"system_tcp","dns":false,"local_proxy":false}"#).unwrap();
        assert!(!explicit_false.transport_requirements().unwrap().carrier);
        let existing = parse(r#"{"transport_profile":"existing_configured","dns":false,"local_proxy":false,"builtin_exits":false,"group_proxy":false,"own_proxy_enabled":false}"#).unwrap();
        let requirements = existing.transport_requirements().unwrap();
        assert_eq!(requirements.active_config.profile, TransportProfile::ExistingConfigured);
        assert!(!requirements.carrier);
        let dns_only = parse(r#"{"transport_profile":"existing_configured","dns":true,"local_proxy":false,"builtin_exits":false,"group_proxy":false,"own_proxy_enabled":false}"#).unwrap().transport_requirements().unwrap();
        assert!(dns_only.active_config.dns && dns_only.carrier);
        assert!(!dns_only.active_config.dns_alias);
        let watchdog = parse(r#"{"transport_profile":"system_tcp","dns":false,"local_proxy":true,"auto_patch":true,"patch_declined":false}"#).unwrap().transport_requirements().unwrap();
        assert_eq!(watchdog.watchdog, Some(true));
        let bytes = valid.encode_for_save().unwrap().into_bytes();
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        let saved = receive_intent_bytes(&bytes, &hash).unwrap();
        assert!(matches!(transport_intent_from_read(Read::Parsed(saved)), TransportIntent::Explicit { .. }));
        assert!(receive_intent_bytes(&bytes, &[0; 32]).is_err());
    }

    #[test]
    fn data_cache_keeps_received_presence() {
        let mut s = Settings::load();
        s.client_patch = true;
        s.save_checked().unwrap();
        let cached = CACHE.lock().unwrap().as_ref().unwrap().0.clone();
        assert_eq!(cached.encode_for_save().unwrap(), s.encode_for_save().unwrap());
        assert_eq!(&cached.transport_input.present[..5], &s.transport_input.present[..5]);
        assert!(cached.transport_input.present[5] && cached.transport_input.present[6]);
        assert!(!cached.decline_unrecorded);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_worker_requires_current_parsed_intent() {
        let dir = std::env::temp_dir().join(format!("ag-mac-intent-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("settings.json");
        assert!(watchdog_snapshot_at(&path).is_err());
        std::fs::write(&path, "{").unwrap();
        assert!(watchdog_snapshot_at(&path).is_err());
        let on = Settings { auto_patch: true, patch_declined: false, ..Settings::default() };
        std::fs::write(&path, serde_json::to_vec(&on).unwrap()).unwrap();
        assert!(watchdog_snapshot_at(&path).unwrap().auto_patch_wanted());
        let off = Settings { auto_patch: false, ..on };
        std::fs::write(&path, serde_json::to_vec(&off).unwrap()).unwrap();
        assert!(!watchdog_snapshot_at(&path).unwrap().auto_patch_wanted());
        std::fs::remove_file(&path).unwrap();
        assert!(watchdog_snapshot_at(&path).is_err());
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn handoff_binds_saved_bytes_and_rejects_invalid_data() {
        let mut expected = Settings { license_key: "synthetic".into(), ..Settings::default() };
        expected.set_transport_choice(TransportChoice::Dns(false)).unwrap();
        let bytes = expected.encode_for_save().unwrap().into_bytes();
        let hash = saved_intent_hash(&bytes, &expected).unwrap();
        let received = receive_intent_bytes(&bytes, &hash).unwrap();
        assert_eq!(received.license_key, "synthetic");
        assert!(!received.dns);
        assert!(saved_intent_hash(b"{}", &expected).is_err());
        assert!(receive_intent_bytes(b"{}", &hash).is_err());
        let invalid = b"{";
        let invalid_hash: [u8; 32] = Sha256::digest(invalid).into();
        assert!(receive_intent_bytes(invalid, &invalid_hash).is_err());
        let empty_hash: [u8; 32] = Sha256::digest([]).into();
        assert!(receive_intent_bytes(b"", &empty_hash).is_err());
    }

    #[test]
    fn wsl_omission_and_explicit_choice_preserve_other_settings() {
        let old = r#"{"license_key":"old-key","dns":false,"own_proxy":"example"}"#;
        let mut settings: Settings = serde_json::from_str(old).unwrap();
        assert!(settings.wsl.is_none());
        settings.wsl = Some(crate::wsl_api::WslPreferences {
            enabled: false,
            distros: vec!["Ubuntu".into()],
        });
        let saved = serde_json::to_string(&settings).unwrap();
        let restored: Settings = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored.wsl, settings.wsl);
        assert_eq!(restored.license_key, "old-key");
        assert!(!restored.dns);
        assert_eq!(restored.own_proxy, "example");
    }

    #[test]
    fn defaults_keep_group_proxy_opt_in() {
        let s = Settings::default();
        assert!(s.dns && s.local_proxy && s.builtin_exits && s.auto_patch);
        assert!(!s.group_proxy);
        assert!(s.rotate_providers, "the pool races by default");
        assert!(
            !s.client_patch,
            "nothing is patched until something patches it"
        );
        assert!(
            s.auto_patch_wanted(),
            "a fresh install is patched unasked (D27): that is what auto-patch is for"
        );
    }

    #[test]
    fn group_proxy_omission_and_explicit_choices() {
        assert!(!parse(r#"{}"#).unwrap().group_proxy);
        assert!(parse(r#"{"group_proxy":true}"#).unwrap().group_proxy);
        assert!(!parse(r#"{"group_proxy":false}"#).unwrap().group_proxy);
    }

    /// G38 under D27: switching the patch off keeps it off, whatever auto-patch
    /// says, until the user asks for the patch again.
    #[test]
    fn a_patch_switched_off_by_hand_is_not_put_back() {
        let mut s = Settings::default();
        s.patch_declined = true;
        assert!(s.auto_patch, "the auto-patch wish itself is kept");
        assert!(!s.auto_patch_wanted());
        s.patch_declined = false;
        assert!(s.auto_patch_wanted());
        s.auto_patch = false;
        assert!(!s.auto_patch_wanted(), "and auto-patch off is off");
    }

    /// A hand-edited file with a byte-order mark keeps its contents.
    #[test]
    fn a_byte_order_mark_does_not_reset_the_file() {
        let s = parse("\u{feff}{\"dns\": false, \"patch_declined\": true}").expect("parses");
        assert!(!s.dns);
        assert!(s.patch_declined);
    }

    /// A file from a build before D27 has no `patch_declined`. With the patch
    /// off it reads as declined - an older build wrote "switched off by hand"
    /// exactly that way, and that patch must not come back unasked (G38) - and
    /// it is marked, so the window can settle it once.
    #[test]
    fn a_file_from_before_the_decline_flag_reads_conservatively() {
        let off = parse(r#"{"client_patch": false, "auto_patch": true}"#).expect("loads");
        assert!(off.patch_declined && off.decline_unrecorded);
        assert!(!off.auto_patch_wanted());

        let on = parse(r#"{"client_patch": true, "auto_patch": true}"#).expect("loads");
        assert!(!on.patch_declined && on.decline_unrecorded);
        assert!(on.auto_patch_wanted());

        let recorded = parse(r#"{"client_patch": false, "patch_declined": false}"#).expect("loads");
        assert!(!recorded.patch_declined && !recorded.decline_unrecorded);
        assert!(
            recorded.auto_patch_wanted(),
            "a recorded answer is taken as is"
        );
    }

    /// The marker never reaches the file, so a file this build wrote is never
    /// mistaken for an older one.
    #[test]
    fn the_unrecorded_marker_is_not_saved() {
        let s = Settings {
            decline_unrecorded: true,
            ..Settings::default()
        };
        let json = serde_json::to_string(&s).expect("serializes");
        assert!(!json.contains("decline_unrecorded"));
        assert!(json.contains("patch_declined"));
    }

    /// A save is a whole file or nothing, and leaves no temp behind.
    #[test]
    fn a_save_replaces_the_file_whole() {
        let dir = std::env::temp_dir().join("ag_settings_replace");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("settings.json");
        std::fs::write(&file, "old").unwrap();
        write_replacing(&file, "{\"dns\": false}").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{\"dns\": false}");
        let leftovers = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1, "only the file itself");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_provider_is_on_until_it_is_explicitly_turned_off() {
        let mut s = Settings::default();
        assert!(s.provider_enabled("dns-ai"));
        s.set_provider_enabled("dns-ai", false);
        assert!(
            !s.provider_enabled("DNS-AI"),
            "the name match is case-blind"
        );
        assert_eq!(s.disabled_providers.len(), 1);
        // Turning it off twice must not leave two entries behind.
        s.set_provider_enabled("dns-ai", false);
        assert_eq!(s.disabled_providers.len(), 1);
        s.set_provider_enabled("dns-ai", true);
        assert!(s.disabled_providers.is_empty());
    }

    #[test]
    fn an_unknown_field_in_the_file_does_not_throw_the_whole_thing_away() {
        // A settings file written by a newer build must still load in an older
        // one - otherwise a downgrade silently resets every switch.
        let json = r#"{"dns": false, "something_from_the_future": 7}"#;
        let s: Settings = serde_json::from_str(json).expect("unknown fields are ignored");
        assert!(!s.dns);
        assert!(s.local_proxy, "fields left out keep their default");
    }
}
