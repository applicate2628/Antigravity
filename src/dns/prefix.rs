//! Optional IPv4 preference with a machine-owned observed preimage.

use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
use crate::utils::{CommandOutcome, PreparedExec, bounded_output, powershell};
use super::{HELPER_LIMIT, machine_state::Writer, receive_command};

const PREFIX: &str = "::ffff:0:0/96";
const PREFERRED: u32 = 46;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy { precedence: u32, label: u32 }

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt { before: Policy, applied: Policy, confirmed: bool }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ipv6Observation { address: Ipv6Addr, state: AddressState, skip_as_source: bool }

#[derive(Deserialize)]
enum AddressState { Invalid, Tentative, Duplicate, Deprecated, Preferred }

fn usable_global(address: &Ipv6Observation) -> bool {
    let segments = address.address.segments();
    // The current global unicast allocation is 2000::/3. Treat uncertain
    // special-use unicast conservatively, apart from known documentation space.
    matches!(address.state, AddressState::Preferred) && !address.skip_as_source
        && segments[0] & 0xe000 == 0x2000
        && segments[..2] != [0x2001, 0x0db8]
        && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
}

fn query<T: serde::de::DeserializeOwned>(owner: &mut CommandOutcome, body: &str) -> Result<T, String> {
    let command = format!("$ErrorActionPreference='Stop'; {body}; 'AG_END'");
    let observation = powershell(owner, &command);
    receive_command(owner, observation)?;
    let parsed = (|| {
        let text = std::str::from_utf8(owner.stdout()).map_err(|_| "invalid IPv4 policy output encoding")?;
        let raw = text.trim().strip_suffix("\nAG_END").ok_or("incomplete IPv4 policy output")?.trim();
        serde_json::from_str(raw).map_err(|error| format!("IPv4 policy output: {error}"))
    })();
    drop(std::mem::take(owner));
    parsed
}

fn observe(owner: &mut CommandOutcome) -> Result<Option<Policy>, String> {
    let policy: Vec<Policy> = query(owner, &format!(r#"
        $rows=@(Get-NetPrefixPolicy -ErrorAction Stop | Where-Object {{$_.Prefix -eq '{PREFIX}'}} |
            ForEach-Object {{[pscustomobject]@{{precedence=$_.Precedence;label=$_.Label}}}});
        ConvertTo-Json -InputObject $rows -Compress
    "#))?;
    match policy.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(*only)),
        _ => Err("IPv4 prefix policy is ambiguous".into()),
    }
}

fn change(owner: &mut CommandOutcome, writer: &Writer, preimage: Policy, desired: Policy) -> Result<(), String> {
    if observe(owner)? != Some(preimage) { return Err("IPv4 prefix preimage changed".into()); }
    let command = PreparedExec::system(std::path::Path::new("netsh.exe"))?.args([
        "interface", "ipv6", "set", "prefixpolicy", PREFIX, &desired.precedence.to_string(), &desired.label.to_string(),
    ]);
    writer.bind_effect(owner);
    let observation = bounded_output(owner, command, HELPER_LIMIT);
    receive_command(owner, observation)?;
    drop(std::mem::take(owner));
    if observe(owner)? != Some(desired) { return Err("IPv4 prefix changed but independent readback differs".into()); }
    Ok(())
}

fn save(writer: &Writer, receipt: Option<Receipt>) -> Result<(), String> {
    writer.store_prefix(&serde_json::to_vec(&receipt).map_err(|e| format!("IPv4 receipt encoding: {e}"))?)
}

fn receive(writer: &Writer) -> Result<Option<Receipt>, String> {
    match writer.read_prefix()? {
        None => Ok(None),
        Some(bytes) => {
            let receipt: Option<Receipt> = serde_json::from_slice(&bytes).map_err(|e| format!("IPv4 owned receipt: {e}"))?;
            if receipt.is_some_and(|r| r.applied.precedence != PREFERRED || r.before.precedence == PREFERRED
                || r.before.label != r.applied.label) { return Err("IPv4 owned receipt is invalid".into()); }
            Ok(receipt)
        }
    }
}

pub(super) fn restore(owner: &mut CommandOutcome, writer: &Writer) -> Result<(), String> {
    let Some(receipt) = receive(writer)? else { return Ok(()); };
    match observe(owner)? {
        Some(actual) if actual == receipt.before => {}
        Some(actual) if actual == receipt.applied && receipt.confirmed => change(owner, writer, receipt.applied, receipt.before)?,
        _ => return Err("IPv4 prefix has changed outside the owned operation; policy preserved".into()),
    }
    save(writer, None)
}

pub(super) fn apply(owner: &mut CommandOutcome, writer: &Writer) -> Result<(), String> {
    let addresses: Vec<Ipv6Observation> = query(owner, r#"
        $rows=@(Get-NetIPAddress -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.AddressFamily -eq 'IPv6' } | ForEach-Object {
                [pscustomobject]@{address=[string]$_.IPAddress;state=[string]$_.AddressState;skip_as_source=$_.SkipAsSource}
            });
        ConvertTo-Json -InputObject $rows -Compress
    "#)?;
    if addresses.iter().any(usable_global) { return restore(owner, writer); }
    let mut receipt = match receive(writer)? {
        Some(receipt) => receipt,
        None => {
            let Some(before) = observe(owner)? else { return Ok(()); };
            // A preexisting preferred value is not evidence of ownership.
            if before.precedence == PREFERRED { return Ok(()); }
            let receipt = Receipt { before, applied: Policy { precedence: PREFERRED, label: before.label }, confirmed: false };
            save(writer, Some(receipt))?;
            receipt
        }
    };
    match observe(owner)? {
        Some(actual) if actual == receipt.applied && receipt.confirmed => Ok(()),
        Some(actual) if actual == receipt.before => {
            receipt.confirmed = false;
            save(writer, Some(receipt))?;
            change(owner, writer, receipt.before, receipt.applied)?;
            receipt.confirmed = true;
            save(writer, Some(receipt))
        }
        _ => Err("IPv4 prefix ownership changed; policy preserved".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_usable_global_source_addresses_hold_the_ipv4_preference() {
        for local in ["fc00::123", "fd12::1", "fe80::1", "::1", "::", "2001:db8::1", "3fff::1"] {
            assert!(!usable_global(&Ipv6Observation { address: local.parse().unwrap(),
                state: AddressState::Preferred, skip_as_source: false }), "{local}");
        }
        let global = "2606:4700::1".parse().unwrap();
        for state in [AddressState::Tentative, AddressState::Duplicate, AddressState::Deprecated, AddressState::Invalid] {
            assert!(!usable_global(&Ipv6Observation { address: global, state, skip_as_source: false }));
        }
        assert!(!usable_global(&Ipv6Observation { address: global, state: AddressState::Preferred, skip_as_source: true }));
        assert!(usable_global(&Ipv6Observation { address: global, state: AddressState::Preferred, skip_as_source: false }));
    }
}
