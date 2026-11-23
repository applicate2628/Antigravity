//! Shared GUI/controller values. These carry observations, never installation
//! authority or a second persisted settings store.

use serde::{Deserialize, Serialize};

/// Wanted configuration. An absent enclosing Settings field means migration
/// is unresolved; it must not be replaced with an implicit disabled choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslPreferences {
    pub enabled: bool,
    pub distros: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState { Unknown, Present, Absent }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RegistrationFreshness { #[default] Unobserved, Current, Stale }

/// Exact registration name plus separately observed availability and intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDistro {
    pub name: String,
    pub registration: RegistrationState,
    pub selected: bool,
    /// None when registration exists but running state was not established.
    pub running: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslTargetState {
    Unconfirmed,
    NotApplied,
    Preparing,
    /// Preparation only; this does not claim a running server or model reply.
    ReadyToOpen,
    Blocked,
    /// Actual owned work or resource retirement has not completed.
    Pending,
    Failed,
    /// Cancellation was received and the owned operation actually settled.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetApplyResult {
    pub name: String,
    pub state: WslTargetState,
    /// Redacted user-facing reason, never command arguments or credentials.
    pub detail: Option<String>,
    /// Privacy-qualified technical failure, forwarded once at completion.
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopDiscovery {
    Absent,
    Present,
    Incomplete { desktop_found: bool, error: String },
}

impl Default for DesktopDiscovery {
    fn default() -> Self {
        Self::Incomplete { desktop_found: false, error: "Установка Desktop ещё не проверена.".into() }
    }
}

impl DesktopDiscovery {
    #[cfg(windows)]
    pub(crate) fn error(&self) -> Option<&str> {
        match self { Self::Incomplete { error, .. } => Some(error), _ => None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslRefreshOutcome {
    Completed,
    Failed,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WslRefreshResult {
    pub attempt: u64,
    pub outcome: WslRefreshOutcome,
}

/// Ordinary snapshot carried by ops::Status and its existing event channel.
/// The controller owns work; the Settings owner supplies acknowledged intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslStatus {
    pub preferences: Option<WslPreferences>,
    pub registration_freshness: RegistrationFreshness,
    pub loading: bool,
    /// Latest terminal result of a consumed manual list refresh in this process.
    pub refresh_result: Option<WslRefreshResult>,
    pub error: Option<String>,
    pub distributions: Vec<RegisteredDistro>,
    pub results: Vec<TargetApplyResult>,
    pub pending: bool,
    pub desktop_target: DesktopDiscovery,
    pub apply_eligibility: Result<(), String>,
}

impl Default for WslStatus {
    fn default() -> Self {
        Self { preferences: None, registration_freshness: RegistrationFreshness::Unobserved,
            loading: false, refresh_result: None, error: None, distributions: Vec::new(), results: Vec::new(), pending: false,
            desktop_target: DesktopDiscovery::default(),
            apply_eligibility: Err("Возможность применения WSL ещё не проверена.".into()) }
    }
}

impl WslStatus {
    pub fn show_configuration(&self) -> bool {
        matches!(&self.desktop_target, DesktopDiscovery::Present | DesktopDiscovery::Incomplete { desktop_found: true, .. })
    }
    pub fn can_apply(&self) -> bool { self.apply_eligibility.is_ok() }
    pub fn can_set_distro(&self, name: &str, selected: bool) -> bool {
        if self.pending || self.loading { return false; }
        let Some(row) = self.distributions.iter().find(|row| row.name == name) else { return false; };
        if !selected { return row.selected; }
        !row.selected && self.preferences.as_ref().is_some_and(|p| p.enabled)
            && self.registration_freshness == RegistrationFreshness::Current
            && row.registration == RegistrationState::Present
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_visibility_requires_received_desktop() {
        let mut status = WslStatus::default();
        assert!(!status.show_configuration());
        status.desktop_target = DesktopDiscovery::Absent;
        assert!(!status.show_configuration());
        status.desktop_target = DesktopDiscovery::Present;
        assert!(status.show_configuration());
        status.desktop_target = DesktopDiscovery::Incomplete { desktop_found: true, error: "unavailable".into() };
        assert!(status.show_configuration());
        assert!(!status.can_apply());
        status.desktop_target = DesktopDiscovery::Incomplete { desktop_found: false, error: "unavailable".into() };
        status.pending = true;
        assert!(!status.show_configuration());
    }
}
