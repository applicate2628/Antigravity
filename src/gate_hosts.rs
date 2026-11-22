//! Shared gate-host policy, independent of transport and application state.
const PRIVATE_GATE_HOSTS: [&str; 2] = ["cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com"];
const PUBLIC_AICODE_HOST: &str = "aicode.googleapis.com";

pub(crate) fn is_gate_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    PRIVATE_GATE_HOSTS.contains(&h.as_str())
}

pub(crate) fn is_public_dns_target(host: &str, port: u16) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    port == 443 && (PRIVATE_GATE_HOSTS.contains(&h.as_str()) || h == PUBLIC_AICODE_HOST)
}

pub(crate) fn public_dns_hosts() -> impl Iterator<Item = &'static str> {
    PRIVATE_GATE_HOSTS.into_iter().chain(std::iter::once(PUBLIC_AICODE_HOST))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_dns_targets_do_not_expand_private_gate_authority() {
        for host in public_dns_hosts() { assert!(is_public_dns_target(host, 443)); }
        assert!(is_public_dns_target("AiCode.GoogleAPIs.Com.", 443));
        assert!(!is_gate_host("aicode.googleapis.com"));
        assert!(!is_public_dns_target("aicode.googleapis.com", 80));
        assert!(!is_public_dns_target("x.aicode.googleapis.com", 443));
        assert!(!is_public_dns_target("other.googleapis.com", 443));
        assert!(is_gate_host("CLOUDCODE-PA.GOOGLEAPIS.COM."));
    }
}
