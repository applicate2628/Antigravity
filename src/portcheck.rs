//! Why a local port could not be bound, in words a user can act on.
//!
//! The relay listens on three loopback ports: the local proxy's TCP port, the
//! gate hosts' door on TCP `:443`, and the DNS relay's UDP `127.0.0.53:53`.
//! A UDP `:53` bind cannot be moved to another port (the NRPT rules that point
//! at the relay carry an IP address with no port), so for that listener the
//! diagnosis is the whole of what we can offer the user. When a bind fails the
//! relay used to log `os error 10013` and carry on without them, and Antigravity
//! went on hitting the 400 with nothing on screen saying why (P53). Three causes
//! cover what the field has shown, and each has a different fix:
//!
//! * **held** — another program already listens on that port (a local web
//!   server, VMware's shared VMs, Docker, IIS through HTTP.sys; on UDP `:53` the
//!   usual holder is Windows' Internet Connection Sharing (the `SharedAccess`
//!   service, which the Hyper-V default switch and the mobile hotspot both
//!   start), a local DNS proxy (AdGuard, DNSCrypt, Docker Desktop) or a
//!   competing tool). We can name it.
//! * **reserved** — the port lies in a range Windows has set aside, which is
//!   what Hyper-V, WSL 2 and Docker do inside the dynamic range (G31).
//! * **denied** — nothing holds it and nothing reserved it, and Windows still
//!   says `WSAEACCES`: security software refusing this program a listening
//!   socket. The fix is an exception for our exe in that software.

use std::net::{Ipv4Addr, SocketAddr};
use crate::utils::{CommandOutcome, CommandObservation, PreparedExec};

#[cfg(windows)]
fn received_probe(outcome: &CommandOutcome, observation: CommandObservation) -> Result<(), String> {
    match observation {
        CommandObservation::Complete if outcome.complete() && outcome.releasable() && outcome.exit().is_some_and(|status| status.success()) => Ok(()),
        CommandObservation::NotStarted => Err("port helper did not start; actual failure retained".into()),
        CommandObservation::Complete => Err("port helper failed or status is unknown".into()),
        CommandObservation::Deadline => Err("port helper deadline expired; outcome retained".into()),
        CommandObservation::Failed => Err("port helper failed; outcome retained".into()),
        CommandObservation::Pending => Err("port helper remains pending".into()),
    }
}

/// Which transport a failed bind was on. The listener tables and Windows'
/// excluded-port ranges are kept per protocol, so a diagnosis has to ask about
/// the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// What stopped a bind, as `gate::Blocker::cause` spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// Another program listens on the port; its image name when it could be
    /// read (a service run as SYSTEM may not tell an unelevated relay).
    Held(Option<String>),
    /// Inside a range Windows excluded from use.
    Reserved,
    /// Access denied with no holder and no reservation: security software.
    Denied,
    /// Anything else; the OS text says what.
    Other,
}

impl Cause {
    pub fn code(&self) -> &'static str {
        match self {
            Cause::Held(_) => "held",
            Cause::Reserved => "reserved",
            Cause::Denied => "denied",
            Cause::Other => "other",
        }
    }

    pub fn holder(&self) -> Option<&str> {
        match self {
            Cause::Held(name) => name.as_deref(),
            _ => None,
        }
    }

    /// The record the relay publishes for the window (`gate::set_blocker`).
    pub fn blocker(
        &self,
        what: &str,
        addr: SocketAddr,
        err: &std::io::Error,
    ) -> crate::gate::Blocker {
        crate::gate::Blocker {
            what: what.to_string(),
            addr: addr.to_string(),
            cause: self.code().to_string(),
            by: self.holder().unwrap_or_default().to_string(),
            error: err.to_string(),
        }
    }

    /// Whether moving to another port gets around it. Security software that
    /// refuses this program a socket refuses it every port.
    ///
    /// Windows only. On Linux nothing would carry a moved port into the
    /// `environment.d` drop-in (the relay's env thread is Windows'), so a move
    /// would leave the variable naming the old port; there the proxy keeps
    /// retrying its own port instead, which a borrowed ephemeral port frees.
    pub fn another_port_helps(&self) -> bool {
        cfg!(windows) && !matches!(self, Cause::Denied)
    }
}

/// Classifies a failed bind of `addr` on TCP.
pub fn diagnose(outcome: &mut CommandOutcome, addr: SocketAddr, err: &std::io::Error) -> Result<Cause, String> {
    diagnose_on(outcome, addr, err, Proto::Tcp)
}

/// Classifies a failed bind of `addr` on `proto`. Costs a table read and, only
/// when that finds no holder, one `netsh` call: once per failed bind, which
/// while a blocker lasts is the listener's one retry a minute.
pub fn diagnose_on(outcome: &mut CommandOutcome, addr: SocketAddr, err: &std::io::Error, proto: Proto) -> Result<Cause, String> {
    let port = addr.port();
    if let Some(pid) = listener_pid(addr, proto)? {
        return Ok(Cause::Held(process_name(outcome, pid)?));
    }
    if excluded_ranges(outcome, proto)?
        .iter()
        .any(|(lo, hi)| (*lo..=*hi).contains(&port))
    {
        return Ok(Cause::Reserved);
    }
    // 10013 on Windows, EACCES elsewhere.
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return Ok(Cause::Denied);
    }
    Ok(Cause::Other)
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// The image name of the program listening where `addr` points, when it can be
/// read. What tells our own proxy from somebody else's program answering on the
/// same port (`proxy::wait_for_our_listener`).
pub fn listener_image(outcome: &mut CommandOutcome, addr: SocketAddr) -> Result<Option<String>, String> {
    match listener_pid(addr, Proto::Tcp)? { Some(pid) => process_name(outcome, pid), None => Ok(None) }
}

/// The PID holding `addr` itself, or on the wildcard for its port - the two
/// that can stand in its way. A listener on another loopback address with the
/// same port does not, and blaming it would send the user after the wrong
/// program (a dev server on 127.0.0.1:443 while the door wants 127.65.71.1:443).
#[cfg(windows)]
fn listener_pid(addr: SocketAddr, proto: Proto) -> Result<Option<u32>, String> {
    Ok(listener_owners(addr, proto)?.into_iter().next().map(|(_, pid)| pid))
}

#[cfg(windows)]
pub(crate) fn listener_owners(addr: SocketAddr, proto: Proto) -> Result<Vec<(Ipv4Addr, u32)>, String> {
    let (port, want) = match addr {
        SocketAddr::V4(a) => (a.port(), *a.ip()),
        SocketAddr::V6(_) => return Err("listener observation requires an IPv4 address".into()),
    };
    use std::ffi::c_void;
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }
    const AF_INET: u32 = 2;
    const INSUFFICIENT_BUFFER: u32 = 122;
    let (width, address_index, port_index, pid_index) = match proto {
        Proto::Tcp => (6, 1, 2, 5),
        Proto::Udp => (3, 0, 1, 2),
    };
    let query = |ptr: *mut c_void, size: &mut u32| unsafe {
        match proto {
            Proto::Tcp => GetExtendedTcpTable(ptr, size, 0, AF_INET, 3, 0),
            Proto::Udp => GetExtendedUdpTable(ptr, size, 0, AF_INET, 1, 0),
        }
    };
    let mut size = 0u32;
    let rc = query(std::ptr::null_mut(), &mut size);
    if rc != INSUFFICIENT_BUFFER || size < 4 {
        return Err(format!("listener table sizing failed: {rc}, bytes={size}"));
    }
    let buf = loop {
        let mut words = vec![0u32; (size as usize).div_ceil(4)];
        let capacity = u32::try_from(words.len().checked_mul(4).ok_or("listener table size overflow")?)
            .map_err(|_| "listener table size overflow")?;
        let mut supplied = capacity;
        let rc = query(words.as_mut_ptr().cast(), &mut supplied);
        if rc == 0 { break words; }
        if rc != INSUFFICIENT_BUFFER || supplied <= capacity {
            return Err(format!("listener table receiving failed: {rc}, bytes={supplied}"));
        }
        size = supplied;
    };
    let count = buf[0] as usize;
    if count > (buf.len() - 1) / width { return Err("listener table truncated".into()); }
    let mut owners = Vec::new();
    for row in buf[1..1 + count * width].chunks_exact(width) {
        let local_port = u16::from_be((row[port_index] & 0xffff) as u16);
        let local = Ipv4Addr::from(row[address_index].to_ne_bytes());
        if local_port == port && (local == want || local.is_unspecified()) {
            owners.push((local, row[pid_index]));
        }
    }
    Ok(owners)
}

/// The image name of `pid`: the kernel's answer when this process may open the
/// other one, `tasklist`'s otherwise (it reads names across sessions and
/// privilege levels without elevation).
#[cfg(windows)]
fn process_name(outcome: &mut CommandOutcome, pid: u32) -> Result<Option<String>, String> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    // PID 4 is the kernel: a listener it owns is HTTP.sys, i.e. IIS or a
    // service that registered a URL with it. Its name would say nothing.
    if pid == 4 {
        return Ok(Some("служба Windows HTTP (IIS или похожая)".to_string()));
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if !h.is_null() {
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0;
            CloseHandle(h);
            if ok {
                let full = String::from_utf16_lossy(&buf[..len as usize]);
                return Ok(full.rsplit('\\').next().map(str::to_string));
            }
        }
    }
    let command = PreparedExec::system(std::path::Path::new("tasklist.exe"))?
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"]);
    let observation = crate::utils::bounded_output(
        outcome,
        command,
        std::time::Duration::from_secs(5),
    );
    received_probe(outcome, observation)?;
    let text = String::from_utf8_lossy(outcome.stdout());
    let name = text
        .lines()
        .next().unwrap_or("")
        .split(',')
        .next().unwrap_or("")
        .trim_matches('"')
        .trim();
    // An image name, not tasklist's "INFO: No tasks are running…" for a PID
    // that exited between the two reads (that line has a dot too).
    let result = name.to_ascii_lowercase()
        .ends_with(".exe")
        .then(|| name.to_string());
    drop(std::mem::take(outcome));
    Ok(result)
}

/// The port ranges Windows keeps from use for `proto`.
#[cfg(windows)]
fn excluded_ranges(outcome: &mut CommandOutcome, proto: Proto) -> Result<Vec<(u16, u16)>, String> {
    let proto_arg = match proto {
        Proto::Tcp => "protocol=tcp",
        Proto::Udp => "protocol=udp",
    };
    let command = PreparedExec::system(std::path::Path::new("netsh.exe"))?
        .args(["int", "ipv4", "show", "excludedportrange", proto_arg]);
    let observation = crate::utils::bounded_output(
        outcome,
        command,
        std::time::Duration::from_secs(5),
    );
    received_probe(outcome, observation)?;
    let result = parse_excluded_ranges(&String::from_utf8_lossy(outcome.stdout()));
    drop(std::mem::take(outcome));
    Ok(result)
}

/// `netsh`'s table, in whatever language Windows speaks: every line that opens
/// with two port numbers is a range, and nothing else in its output does.
fn parse_excluded_ranges(text: &str) -> Vec<(u16, u16)> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let lo = parts.next()?.parse::<u16>().ok()?;
            let hi = parts.next()?.parse::<u16>().ok()?;
            (lo <= hi).then_some((lo, hi))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Elsewhere: no reservations, and a holder would need /proc walking that no
// field report has asked for yet.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
fn listener_pid(_addr: SocketAddr, _proto: Proto) -> Result<Option<u32>, String> {
    Ok(None)
}

#[cfg(not(windows))]
fn process_name(_outcome: &mut CommandOutcome, _pid: u32) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(not(windows))]
fn excluded_ranges(_outcome: &mut CommandOutcome, _proto: Proto) -> Result<Vec<(u16, u16)>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netsh_ranges_are_read_in_any_language_and_nothing_else_is() {
        let english = "\nProtocol tcp Port Exclusion Ranges\n\nStart Port    End Port\n\
                       ----------    --------\n      5357        5357\n     50000       50059     *\n\
                       \n* - Administered port exclusions.\n";
        assert_eq!(
            parse_excluded_ranges(english),
            vec![(5357, 5357), (50000, 50059)]
        );
        let russian = "\nДиапазоны исключенных портов для протокола tcp\n\n\
                       Начальный порт    Конечный порт\n--------------    -------------\n\
                             53100            53199\n";
        assert_eq!(parse_excluded_ranges(russian), vec![(53100, 53199)]);
        assert!(parse_excluded_ranges("").is_empty());
        assert!(parse_excluded_ranges("  70000 70001\n  9 3\n").is_empty());
    }

    /// Live: a port this test holds is found, with this test's own name.
    #[test]
    #[cfg(windows)]
    fn a_port_we_listen_on_is_held_by_us() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let here = l.local_addr().unwrap();
        let pid = listener_pid(here, Proto::Tcp).unwrap().expect("our own listener in the table");
        assert_eq!(pid, std::process::id());
        let mut owner = CommandOutcome::default();
        let name = process_name(&mut owner, pid).unwrap().unwrap_or_default().to_ascii_lowercase();
        assert!(name.ends_with(".exe"), "{name}");
        // The same port on another loopback address is not in its way.
        let elsewhere = SocketAddr::from(([127, 65, 71, 9], here.port()));
        assert_eq!(listener_pid(elsewhere, Proto::Tcp).unwrap(), None);
    }

    #[test]
    #[cfg(windows)]
    fn a_udp_port_we_hold_is_found() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let here = s.local_addr().unwrap();
        let pid = listener_pid(here, Proto::Udp).unwrap().expect("our own UDP socket in the table");
        assert_eq!(pid, std::process::id());
        let mut owner = CommandOutcome::default();
        let name = process_name(&mut owner, pid).unwrap().unwrap_or_default().to_ascii_lowercase();
        assert!(name.ends_with(".exe"), "{name}");
        // The same port on another loopback address is not matched.
        let elsewhere = SocketAddr::from(([127, 65, 71, 9], here.port()));
        assert_eq!(listener_pid(elsewhere, Proto::Udp).unwrap(), None);
    }

    #[test]
    #[cfg(windows)]
    fn tcp_and_udp_tables_are_asked_separately() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        assert_eq!(listener_pid(tcp_addr, Proto::Udp).unwrap(), None);

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp.local_addr().unwrap();
        assert_eq!(listener_pid(udp_addr, Proto::Tcp).unwrap(), None);
    }
}
