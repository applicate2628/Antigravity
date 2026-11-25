//! Exact machine-owned NRPT effects. Local records authorize mutation; the
//! effective projection only verifies whether the requested policy took effect.

use std::collections::BTreeMap;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::utils::{CommandOutcome, powershell};
use super::{AG_NRPT_CORE, NrptState, machine_state, receive_command};

const PROJECTION: &str = r#"
$ErrorActionPreference='Stop';
function Addresses($values) {
    foreach ($value in @($values)) {
        if ($null -eq $value) { continue }
        if ($value -is [string]) { $value; continue }
        if ($value.IPAddressToString -is [string]) { $value.IPAddressToString; continue }
        throw 'unexpected NRPT address representation'
    }
}
function LocalRule($r) {
    $properties=[ordered]@{};
    foreach ($property in @($r.CimInstanceProperties | Sort-Object Name)) {
        if ($property.Name -notin @('Name','Namespace','NameServers','Comment')) {
            $properties[$property.Name]=$property.Value
        }
    }
    if ($properties.Count -eq 0) { throw 'NRPT native properties unavailable' }
    [pscustomobject][ordered]@{id=[string]$r.Name;names=@($r.Namespace);servers=@(Addresses $r.NameServers);comment=[string]$r.Comment;properties=$properties}
}
function EffectiveRule($r) {
    [pscustomobject]@{names=@($r.Namespace);servers=@(Addresses $r.NameServers)}
}
"#;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalRule { id: String, names: Vec<String>, servers: Vec<IpAddr>, comment: String, properties: BTreeMap<String, Value> }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectiveRule { names: Vec<String>, servers: Vec<IpAddr> }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot { local: Vec<LocalRule>, effective: Vec<EffectiveRule> }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal { version: u32, pending: Option<Intent>, rules: BTreeMap<String, LocalRule> }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent { host: String, change: Change }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
enum Change {
    Create { comment: String, servers: Vec<IpAddr> },
    Update { before: LocalRule, servers: Vec<IpAddr> },
    Remove { before: LocalRule },
}

type Desired = BTreeMap<String, Vec<IpAddr>>;

fn quote(value: &str) -> String { format!("'{}'", value.replace('\'', "''")) }

fn nameservers(servers: &[IpAddr]) -> String {
    servers.iter().map(|ip| quote(&ip.to_string())).collect::<Vec<_>>().join(",")
}

fn wire<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "NRPT result is not UTF-8")?;
    let json = text.trim().strip_suffix("\nAG_END").ok_or("NRPT result incomplete")?.trim();
    serde_json::from_str(json).map_err(|e| format!("NRPT result schema: {e}"))
}

fn run<T: serde::de::DeserializeOwned>(owner: &mut CommandOutcome, script: &str) -> Result<T, String> {
    let command = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {PROJECTION}\n{script}");
    let observation = powershell(owner, &command);
    if let Err(cause) = receive_command(owner, observation) {
        if owner.complete() && owner.releasable() {
            let detail = format!("{cause}; exit={:?}; stderr={}", owner.exit(), String::from_utf8_lossy(owner.stderr()).trim());
            drop(std::mem::take(owner));
            return Err(detail);
        }
        return Err(cause);
    }
    let parsed = wire(owner.stdout());
    drop(std::mem::take(owner));
    parsed
}

fn snapshot(owner: &mut CommandOutcome) -> Result<Snapshot, String> {
    run(owner, r#"
        $local=@(Get-DnsClientNrptRule -ErrorAction Stop | ForEach-Object {LocalRule $_});
        $effective=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | ForEach-Object {EffectiveRule $_});
        ConvertTo-Json -InputObject @{local=$local;effective=$effective} -Depth 12 -Compress; 'AG_END'
    "#)
}

fn namespace(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed == "." { trimmed } else { trimmed.trim_end_matches('.') }
}

fn matches_name(raw: &str, host: &str) -> bool {
    let name = namespace(raw);
    if name == "." || name.eq_ignore_ascii_case(host) { return true; }
    name.starts_with('.') && (host.get(host.len().saturating_sub(name.len())..)
        .is_some_and(|end| end.eq_ignore_ascii_case(name)) || host.eq_ignore_ascii_case(&name[1..]))
}

fn exact_name(names: &[String], host: &str) -> bool {
    matches!(names, [name] if namespace(name).eq_ignore_ascii_case(host))
}

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 38 && b[0] == b'{' && b[37] == b'}' && b[1..37].iter().enumerate().all(|(i, byte)| {
        if [8, 13, 18, 23].contains(&i) { *byte == b'-' } else { byte.is_ascii_hexdigit() }
    })
}

fn owner_comment(comment: &str) -> bool {
    comment.strip_prefix("AG_UNLOCKER_NRPT_OWNED_V1 ").is_some_and(valid_id)
}

impl Journal {
    fn decode(bytes: Option<Vec<u8>>) -> Result<Self, String> {
        let value = match bytes {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("invalid NRPT ownership journal: {e}"))?,
            None => Self { version: 1, pending: None, rules: BTreeMap::new() },
        };
        if value.version != 1 || value.rules.iter().any(|(host, owned)| {
            !AG_NRPT_CORE.contains(&host.as_str()) || !valid_id(&owned.id) || !owner_comment(&owned.comment)
                || !exact_name(&owned.names, host) || owned.servers.is_empty() || owned.properties.is_empty()
        }) {
            return Err("NRPT ownership receipt has invalid scope or identity".into());
        }
        if let Some(intent) = &value.pending {
            if !AG_NRPT_CORE.contains(&intent.host.as_str()) || !match &intent.change {
                Change::Create { comment, servers } => owner_comment(comment) && !servers.is_empty()
                    && !value.rules.contains_key(&intent.host),
                Change::Update { before, servers } => value.rules.get(&intent.host) == Some(before) && !servers.is_empty(),
                Change::Remove { before } => value.rules.get(&intent.host) == Some(before),
            } {
                return Err("NRPT pending intent does not bind its owned preimage".into());
            }
        }
        Ok(value)
    }

    fn desired(&self) -> Desired {
        self.rules.iter().map(|(name, rule)| (name.clone(), rule.servers.clone())).collect()
    }
}

impl Snapshot {
    fn verify(&self, journal: &Journal, applying: bool) -> Result<(), String> {
        for (host, owned) in &journal.rules {
            let by_id: Vec<_> = self.local.iter().filter(|row| row.id.eq_ignore_ascii_case(&owned.id)).collect();
            if by_id.as_slice() != [owned] {
                return Err(format!("NRPT owned local identity conflict for {host}; rules preserved"));
            }
        }
        // Off does not claim foreign policies. Removing an exactly received
        // local ID can reveal an independent suffix or GPO policy safely.
        if !applying { return Ok(()); }
        for &name in AG_NRPT_CORE {
            let local: Vec<_> = self.local.iter().filter(|r| r.names.iter().any(|n| matches_name(n, name))).collect();
            let effective: Vec<_> = self.effective.iter().filter(|r| r.names.iter().any(|n| matches_name(n, name))).collect();
            match journal.rules.get(name) {
                Some(owned) if local.as_slice() == [owned]
                    && matches!(effective.as_slice(), [row] if exact_name(&row.names, name) && row.servers == owned.servers) => {}
                None if local.is_empty() && effective.is_empty() => {}
                _ => return Err(format!("NRPT ownership or effective policy conflict for {name}; rules preserved")),
            }
        }
        Ok(())
    }
}

trait Backend {
    fn observe(&mut self) -> Result<Snapshot, String>;
    fn save(&mut self, journal: &Journal) -> Result<(), String>;
    fn nonce(&mut self) -> Result<String, String>;
    fn effect(&mut self, intent: &Intent) -> Result<Option<LocalRule>, String>;
}

struct Native<'a> { owner: &'a mut CommandOutcome, writer: &'a machine_state::Writer }

fn creation_nonce() -> Result<String, String> {
    let mut id = windows_sys::core::GUID::default();
    let status = unsafe { windows_sys::Win32::System::Com::CoCreateGuid(&mut id) };
    if status < 0 { return Err(format!("NRPT creation identity HRESULT {status:#x}")); }
    let b = id.data4;
    Ok(format!("{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        id.data1, id.data2, id.data3, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]))
}

fn pre_read(rule: &LocalRule) -> Result<String, String> {
    let encoded = serde_json::to_string(rule).map_err(|e| e.to_string())?;
    // Reproject both representations in the same key order. CIM objects and
    // persisted JSON order their members differently.
    Ok(format!(r#"
        function CanonicalRule($row) {{
            $p=[ordered]@{{}};
            foreach($entry in @($row.properties.PSObject.Properties | Sort-Object Name)) {{$p[$entry.Name]=$entry.Value}}
            if($row.properties -is [System.Collections.IDictionary]) {{
                $p=[ordered]@{{}}; foreach($key in @($row.properties.Keys | Sort-Object)) {{$p[$key]=$row.properties[$key]}}
            }}
            [ordered]@{{id=$row.id; names=@($row.names); servers=@($row.servers); comment=$row.comment; properties=$p}}
        }}
        $expected=ConvertFrom-Json -InputObject {expected};
        $current=@(Get-DnsClientNrptRule -Name {id} -ErrorAction Stop);
        if($current.Count -ne 1) {{throw 'NRPT native rule identity changed'}}
        $old=CanonicalRule (LocalRule $current[0]);
        $wanted=CanonicalRule $expected;
        if((ConvertTo-Json -InputObject $old -Depth 12 -Compress) -cne (ConvertTo-Json -InputObject $wanted -Depth 12 -Compress)) {{throw 'NRPT preimage changed'}};
    "#, expected=quote(&encoded), id=quote(&rule.id)))
}

impl Backend for Native<'_> {
    fn observe(&mut self) -> Result<Snapshot, String> { snapshot(self.owner) }

    fn save(&mut self, journal: &Journal) -> Result<(), String> {
        let bytes = serde_json::to_vec(journal).map_err(|e| format!("serialize NRPT journal: {e}"))?;
        self.writer.store(&bytes)
    }

    fn nonce(&mut self) -> Result<String, String> { creation_nonce() }

    fn effect(&mut self, intent: &Intent) -> Result<Option<LocalRule>, String> {
        self.writer.bind_effect(self.owner);
        let host = &intent.host;
        let (script, comment, servers, prior) = match &intent.change {
            Change::Create { comment, servers } => {
                (format!("$received=Add-DnsClientNrptRule -Namespace {} -NameServers @({}) -Comment {} -DisplayName 'AG Unlocker DNS' -PassThru -ErrorAction Stop;",
                    quote(host), nameservers(servers), quote(comment)), comment, servers, None)
            }
            Change::Update { before: old, servers } => (format!("{} $received=Set-DnsClientNrptRule -Name {} -NameServers @({}) -PassThru -ErrorAction Stop;",
                pre_read(old)?, quote(&old.id), nameservers(servers)), &old.comment, servers, Some(old)),
            Change::Remove { before: old } => {
                let script = format!("{} Remove-DnsClientNrptRule -Name {} -Force -ErrorAction Stop; ConvertTo-Json -InputObject $true; 'AG_END'", pre_read(old)?, quote(&old.id));
                if !run::<bool>(self.owner, &script)? { return Err("NRPT removal completion absent".into()); }
                return Ok(None);
            }
        };
        let output: LocalRule = run(self.owner, &format!("{script} ConvertTo-Json -InputObject (LocalRule $received) -Depth 12 -Compress; 'AG_END'"))?;
        if !valid_id(&output.id) || prior.is_some_and(|old| old.id != output.id || old.properties != output.properties) || !exact_name(&output.names, host)
            || output.servers != *servers || output.comment != *comment || output.properties.is_empty() {
            return Err("NRPT effect native receipt does not bind the requested single rule".into());
        }
        Ok(Some(output))
    }
}

fn default_creation_properties() -> BTreeMap<String, Value> {
    // Measured native defaults of the explicit Add profile.
    serde_json::json!({
        "Version":2, "DisplayName":"AG Unlocker DNS", "NameEncoding":"Disable",
        "DirectAccessDnsServers":null, "DirectAccessEnabled":false, "DirectAccessProxyName":null,
        "DirectAccessProxyType":null, "DirectAccessQueryIPsecEncryption":null,
        "DirectAccessQueryIPsecRequired":null, "DnsSecEnabled":false,
        "DnsSecQueryIPsecEncryption":null, "DnsSecQueryIPsecRequired":null,
        "DnsSecValidationRequired":null, "IPsecCARestriction":""
    }).as_object().expect("literal NRPT properties").iter()
        .map(|(key, value)| (key.clone(), value.clone())).collect()
}

fn settle_intent(backend: &mut impl Backend, journal: &mut Journal,
                 acknowledged: Option<&Option<LocalRule>>) -> Result<(), String> {
    let Some(intent) = &journal.pending else { return Ok(()); };
    let snapshot = backend.observe()?;
    let host = &intent.host;
    let ambiguous = || format!("NRPT pending effect for {host} is ambiguous; rules preserved");
    let current = match &intent.change {
        Change::Create { comment, servers } => {
            let found: Vec<_> = snapshot.local.iter().filter(|rule| &rule.comment == comment).collect();
            match found.as_slice() {
                [] => None,
                [rule] if valid_id(&rule.id) && exact_name(&rule.names, host) && &rule.servers == servers
                    && !journal.rules.values().any(|owned| owned.id.eq_ignore_ascii_case(&rule.id))
                    && if let Some(Some(expected)) = acknowledged { *rule == expected }
                        else { rule.properties == default_creation_properties() } => Some((*rule).clone()),
                _ => return Err(ambiguous()),
            }
        }
        Change::Update { before, servers } => {
            let found: Vec<_> = snapshot.local.iter().filter(|rule| rule.id.eq_ignore_ascii_case(&before.id)).collect();
            let mut after = before.clone();
            after.servers = servers.clone();
            match found.as_slice() {
                [rule] if *rule == before || **rule == after => Some((*rule).clone()),
                _ => return Err(ambiguous()),
            }
        }
        Change::Remove { before } => {
            let found: Vec<_> = snapshot.local.iter().filter(|rule| rule.id.eq_ignore_ascii_case(&before.id)).collect();
            match found.as_slice() {
                [] => None,
                [rule] if *rule == before => Some((*rule).clone()),
                _ => return Err(ambiguous()),
            }
        }
    };
    if acknowledged.is_some_and(|expected| *expected != current) {
        return Err(format!("NRPT native receipt and independent local readback differ for {host}"));
    }
    if let Some(rule) = current { journal.rules.insert(host.clone(), rule); }
    else { journal.rules.remove(host); }
    journal.pending = None;
    backend.save(journal)
}

fn converge(backend: &mut impl Backend, journal: &mut Journal, desired: &Desired) -> Result<(), String> {
    let applying = !desired.is_empty();
    for &name in AG_NRPT_CORE {
        let change = match (journal.rules.get(name), desired.get(name)) {
            (None, Some(servers)) => Change::Create {
                comment: format!("AG_UNLOCKER_NRPT_OWNED_V1 {}", backend.nonce()?), servers: servers.clone(),
            },
            (Some(old), Some(servers)) if old.servers != *servers => Change::Update { before: old.clone(), servers: servers.clone() },
            (Some(old), None) => Change::Remove { before: old.clone() },
            _ => continue,
        };
        let native = backend.observe()?;
        native.verify(journal, applying)?;
        if let Change::Create { comment, .. } = &change {
            if native.local.iter().any(|row| row.comment.eq_ignore_ascii_case(comment)) {
                return Err("NRPT creation nonce already exists; no creation attempted".into());
            }
        }
        let intent = Intent { host: name.into(), change };
        journal.pending = Some(intent.clone());
        backend.save(journal)?;
        let acknowledged = backend.effect(&intent)?;
        settle_intent(backend, journal, Some(&acknowledged))?;
        backend.observe()?.verify(journal, applying)?;
    }
    Ok(())
}

fn change(backend: &mut impl Backend, mut journal: Journal, desired: &Desired) -> Result<(), String> {
    settle_intent(backend, &mut journal, None)?;
    backend.observe()?.verify(&journal, !desired.is_empty())?;
    let original = journal.desired();
    if let Err(primary) = converge(backend, &mut journal, desired) {
        let rollback = settle_intent(backend, &mut journal, None)
            .and_then(|_| backend.observe()?.verify(&journal, !original.is_empty()))
            .and_then(|_| converge(backend, &mut journal, &original));
        return match rollback {
            Ok(()) => Err(format!("{primary}; original owned NRPT policy restored")),
            Err(recovery) => Err(format!("{primary}; NRPT recovery required: {recovery}")),
        };
    }
    Ok(())
}

pub(super) fn inspect(owner: &mut CommandOutcome) -> Result<NrptState, String> {
    let journal = Journal::decode(machine_state::read()?)?;
    let native = snapshot(owner)?;
    describe(&journal, &native)
}

fn describe(journal: &Journal, native: &Snapshot) -> Result<NrptState, String> {
    if journal.pending.is_some() {
        // Read-only callers must not mistake pending work for operational DNS
        // or for a vacant machine. The writer reconciles it under its lease.
        return Ok(NrptState { core_applied: false, owned_rules_present: !journal.rules.is_empty(),
            recovery_pending: true, auxiliary_cleanup: false });
    }
    native.verify(&journal, false)?;
    let core_applied = journal.rules.len() == AG_NRPT_CORE.len() && native.verify(&journal, true).is_ok();
    Ok(NrptState { core_applied, owned_rules_present: !journal.rules.is_empty(),
        recovery_pending: false, auxiliary_cleanup: false })
}

pub(super) fn apply(owner: &mut CommandOutcome, writer: &machine_state::Writer,
                    requested: Option<Vec<(&str, Vec<String>)>>) -> Result<(), String> {
    let desired = requested.unwrap_or_default().into_iter().map(|(host, list)| {
        if !AG_NRPT_CORE.contains(&host) { return Err("NRPT target is outside the owned core".into()); }
        let servers: Vec<IpAddr> = list.iter().map(|s| s.parse().map_err(|_| "invalid NRPT server address")).collect::<Result<_, _>>()?;
        if servers.is_empty() { return Err("NRPT target has no eligible nameserver".into()); }
        Ok((host.into(), servers))
    }).collect::<Result<Desired, String>>()?;
    if !desired.is_empty() && desired.len() != AG_NRPT_CORE.len() { return Err("incomplete core NRPT plan".into()); }
    let journal = Journal::decode(writer.read()?)?;
    change(&mut Native { owner, writer }, journal, &desired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fixture {
        observed: BTreeMap<String, LocalRule>,
        foreign: Vec<LocalRule>,
        writes: Vec<String>,
        saved: Option<Journal>,
        fail_host: Option<&'static str>,
        unreceived_creation: bool,
    }

    fn rule(names: &[&str], indexes: u32, servers: &[IpAddr]) -> LocalRule {
        let id = format!("{{{indexes:08x}-0000-0000-0000-000000000000}}");
        LocalRule { comment: format!("AG_UNLOCKER_NRPT_OWNED_V1 {id}"), id,
            names: names.iter().map(|n| (*n).into()).collect(), servers: servers.to_vec(),
            properties: default_creation_properties() }
    }

    impl Backend for Fixture {
        fn observe(&mut self) -> Result<Snapshot, String> {
            let local: Vec<_> = self.observed.values().chain(&self.foreign).cloned().collect();
            let effective = local.iter().flat_map(|r| r.names.iter().map(|name| EffectiveRule {
                names: vec![name.clone()], servers: r.servers.clone(),
            })).collect();
            Ok(Snapshot { local, effective })
        }

        fn save(&mut self, journal: &Journal) -> Result<(), String> {
            self.saved = Some(journal.clone());
            Ok(())
        }

        fn nonce(&mut self) -> Result<String, String> {
            Ok(format!("{{{:08x}-0000-0000-0000-000000000000}}", 1000 + self.writes.len()))
        }

        fn effect(&mut self, intent: &Intent) -> Result<Option<LocalRule>, String> {
            let host = intent.host.as_str();
            let durable = self.saved.as_ref().unwrap().pending.as_ref().expect("plan durable before effect");
            assert_eq!(serde_json::to_value(durable).unwrap(), serde_json::to_value(intent).unwrap());
            if self.fail_host == Some(host) {
                self.fail_host = None;
                if self.unreceived_creation {
                    let Change::Create { comment, servers } = &intent.change else { panic!("creation expected"); };
                    let mut unexpected = rule(&[host], 99, servers);
                    unexpected.comment = comment.clone();
                    unexpected.properties.insert("DnsSecEnabled".into(), Value::Bool(true));
                    self.observed.insert(host.into(), unexpected);
                }
                return Err("synthetic native second effect failed".into());
            }
            let result = match &intent.change {
                Change::Create { comment, servers } => {
                    self.writes.push(format!("add {host}"));
                    let mut created = rule(&[host], self.writes.len() as u32, servers);
                    created.comment = comment.clone();
                    Some(created)
                }
                Change::Update { before: old, servers } => {
                    assert_eq!(self.observed.get(host), Some(old));
                    self.writes.push(format!("set {}", old.id));
                    let mut updated = old.clone(); updated.servers = servers.to_vec(); Some(updated)
                }
                Change::Remove { before: old } => {
                    assert_eq!(self.observed.get(host), Some(old));
                    self.writes.push(format!("remove {}", old.id));
                    None
                }
            };
            if let Some(rule) = &result { self.observed.insert(host.into(), rule.clone()); }
            else { self.observed.remove(host); }
            Ok(result)
        }
    }

    fn desired(ip: &str) -> Desired {
        AG_NRPT_CORE.iter().map(|&host| (host.into(), vec![ip.parse().unwrap()])).collect()
    }

    #[test]
    fn owned_cycle_adds_noops_updates_and_removes_exact_ids() {
        let foreign = rule(&["oauth2.googleapis.com"], 101, &[]);
        let mut backend = Fixture { foreign: vec![foreign.clone()], ..Default::default() };
        let first = desired("192.0.2.1");
        change(&mut backend, Journal::decode(None).unwrap(), &first).unwrap();
        assert_eq!(backend.writes.len(), 2);
        let owned = backend.saved.clone().unwrap();
        change(&mut backend, owned.clone(), &first).unwrap();
        assert_eq!(backend.writes.len(), 2);
        change(&mut backend, owned.clone(), &desired("198.51.100.1")).unwrap();
        assert_eq!(backend.writes.len(), 4);
        for (name, old) in owned.rules { assert_eq!(backend.observed[&name].id, old.id); }
        let after = backend.saved.clone().unwrap();
        change(&mut backend, after, &Desired::new()).unwrap();
        assert_eq!(backend.writes.len(), 6);
        assert!(backend.observed.is_empty());
        assert_eq!(backend.foreign, [foreign]);
    }

    #[test]
    fn foreign_exact_mixed_and_subtree_rows_hold_before_any_effect() {
        let name = AG_NRPT_CORE[0];
        for names in [vec![name], vec![name, "oauth2.googleapis.com"], vec![".googleapis.com"]] {
            let mut backend = Fixture { foreign: vec![rule(&names, 101, &[])], ..Default::default() };
            assert!(change(&mut backend, Journal::decode(None).unwrap(), &desired("192.0.2.1")).is_err());
            assert!(backend.writes.is_empty() && backend.saved.is_none());
        }
    }

    #[test]
    fn existing_nonce_on_unrelated_rule_holds_before_creating_any_rule() {
        let foreign = rule(&["oauth2.googleapis.com"], 1000, &[]);
        let mut backend = Fixture { foreign: vec![foreign.clone()], ..Default::default() };
        let err = change(&mut backend, Journal::decode(None).unwrap(), &desired("192.0.2.1")).unwrap_err();
        assert!(err.contains("nonce already exists"));
        assert!(backend.writes.is_empty() && backend.saved.is_none());
        assert_eq!(backend.foreign, [foreign]);
    }

    #[test]
    fn second_failure_rolls_back_the_first_acknowledged_creation() {
        let mut backend = Fixture { fail_host: Some(AG_NRPT_CORE[1]), ..Default::default() };
        let error = change(&mut backend, Journal::decode(None).unwrap(), &desired("192.0.2.1")).unwrap_err();
        assert!(error.contains("synthetic native second effect failed") && error.contains("restored"));
        assert!(backend.observed.is_empty() && backend.saved.unwrap().pending.is_none());
        assert_eq!(backend.writes.len(), 2);
    }

    #[test]
    fn unreceived_creation_remains_pending_and_is_never_adopted() {
        let mut backend = Fixture { fail_host: Some(AG_NRPT_CORE[1]), unreceived_creation: true, ..Default::default() };
        let error = change(&mut backend, Journal::decode(None).unwrap(), &desired("192.0.2.1")).unwrap_err();
        assert!(error.contains("synthetic native second effect failed") && error.contains("recovery required"));
        let pending = backend.saved.clone().unwrap();
        assert!(pending.pending.is_some() && pending.rules.len() == 1 && backend.observed.len() == 2);
        assert!(change(&mut backend, pending, &Desired::new()).is_err());
        assert_eq!(backend.writes.len(), 1);
    }

    #[test]
    fn off_removes_only_owned_ids_after_an_independent_suffix_appears() {
        let mut backend = Fixture::default();
        change(&mut backend, Journal::decode(None).unwrap(), &desired("192.0.2.1")).unwrap();
        let suffix = rule(&[".googleapis.com"], 101, &[]);
        backend.foreign.push(suffix.clone());
        let owned = backend.saved.clone().unwrap();
        change(&mut backend, owned, &Desired::new()).unwrap();
        assert!(backend.observed.is_empty());
        assert_eq!(backend.foreign, [suffix]);
        assert_eq!(backend.writes.len(), 4);
        let retired = backend.saved.clone().unwrap();
        change(&mut backend, retired, &Desired::new()).unwrap();
        assert_eq!(backend.writes.len(), 4);
    }

    #[test]
    fn interrupted_creation_recovery_uses_persisted_nonce_without_duplicate_add() {
        let host = AG_NRPT_CORE[0];
        let mut backend = Fixture::default();
        let selected = desired("192.0.2.1");
        let observed = rule(&[host], 20, &selected[host]);
        let mut journal = Journal::decode(None).unwrap();
        journal.pending = Some(Intent { host: host.into(), change: Change::Create {
            comment: observed.comment.clone(), servers: selected[host].clone(),
        }});
        backend.observed.insert(host.into(), observed.clone());
        let state = describe(&journal, &backend.observe().unwrap()).unwrap();
        assert!(state.recovery_pending && state.needs_retirement() && !state.core_applied);
        change(&mut backend, journal, &selected).unwrap();
        assert_eq!(backend.observed.get(host), Some(&observed));
        assert_eq!(backend.writes, [format!("add {}", AG_NRPT_CORE[1])]);
        assert!(backend.saved.unwrap().pending.is_none());
    }

    #[test]
    fn wire_demands_a_complete_typed_projection_without_effective_identity() {
        assert!(wire::<Snapshot>(b"{\"local\":[],\"effective\":[]}\r\nAG_END\r\n").is_ok());
        assert!(wire::<Snapshot>(b"{\"local\":[],\"effective\":[]}").is_err());
        assert!(wire::<Snapshot>(b"{\"local\":[],\"effective\":[{\"names\":[\"cloudcode-pa.googleapis.com\"],\"servers\":[\"127.0.0.53\"]}]}\nAG_END").is_ok());
        assert!(wire::<Snapshot>(b"{\"local\":[],\"effective\":[{\"id\":\"invented\",\"names\":[],\"servers\":[]}]}\nAG_END").is_err());
    }
}
