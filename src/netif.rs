//! macOS route and interface observation, adapted from upstream 4c971180.
//! A connected UDP socket asks the kernel for a local address without sending
//! a packet. The IPv4 route table supplies the gateway and, when the default
//! path is a tunnel, the scoped route for the provider.

use std::io;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MacRelayEgress {
    provider: NonZeroU32,
    default: NonZeroU32,
    provider_gateway: String,
    provider_addresses: Vec<Ipv4Addr>,
    default_source: Ipv4Addr,
    default_gateway: Option<String>,
}

impl MacRelayEgress {
    pub(crate) fn pin(&self) -> u32 {
        if self.tunnel() { self.provider.get() } else { 0 }
    }

    pub(crate) fn tunnel(&self) -> bool {
        self.provider != self.default
    }
}

struct Interface {
    name: String,
    index: NonZeroU32,
    v4: Vec<Ipv4Addr>,
    point_to_point: bool,
}

impl Interface {
    fn is_tunnel(&self) -> bool {
        const TUNNEL_PREFIXES: &[&str] = &[
            "tun", "tap", "wg", "ppp", "utun", "ipsec", "awg", "amn", "nordlynx",
            "proton", "tailscale", "zt", "vpn", "outline", "gpd", "cscotun",
        ];
        let name = self.name.to_ascii_lowercase();
        self.point_to_point || TUNNEL_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
    }
}

struct DefaultRoute<'a> {
    interface: &'a str,
    gateway: &'a str,
    via_gateway: bool,
}

fn parse_netstat(text: &str) -> impl Iterator<Item = DefaultRoute<'_>> {
    text.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "default" { return None; }
        let gateway = fields.next()?;
        let flags = fields.next()?;
        let interface = fields.next()?;
        Some(DefaultRoute { interface, gateway, via_gateway: flags.contains('G') })
    })
}

fn default_interface(address: Ipv4Addr, interfaces: &[Interface]) -> Option<&Interface> {
    let mut owners = interfaces.iter().filter(|interface| interface.v4.contains(&address));
    let owner = owners.next()?;
    owners.next().is_none().then_some(owner)
}

fn select_egress(source: Ipv4Addr, interfaces: &[Interface], routes: &str) -> Option<MacRelayEgress> {
    let default = default_interface(source, interfaces)?;
    let (provider, gateway) = if default.is_tunnel() {
        parse_netstat(routes).filter(|route| route.via_gateway).find_map(|route| {
            let interface = interfaces.iter().find(|interface| {
                interface.name == route.interface && !interface.is_tunnel()
            })?;
            Some((interface, route.gateway))
        })?
    } else {
        let route = parse_netstat(routes).find(|route| route.via_gateway && route.interface == default.name)?;
        (default, route.gateway)
    };
    let mut provider_addresses = provider.v4.clone();
    provider_addresses.sort_unstable();
    provider_addresses.dedup();
    Some(MacRelayEgress {
        provider: provider.index,
        default: default.index,
        provider_gateway: gateway.to_string(),
        provider_addresses,
        default_source: source,
        default_gateway: parse_netstat(routes).find(|route| route.interface == default.name)
            .map(|route| route.gateway.to_string()),
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn observe(
    dest: Ipv4Addr,
    read_routes: impl FnOnce() -> Result<String, String>,
) -> Result<Option<MacRelayEgress>, String> {
    let Some(address) = local_addr_toward(dest)? else { return Ok(None); };
    let interfaces = interfaces()?;
    if default_interface(address, &interfaces).is_none() { return Ok(None); }
    let routes = read_routes()?;
    if local_addr_toward(dest)? != Some(address) { return Ok(None); }
    Ok(select_egress(address, &interfaces, &routes))
}

fn no_route(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable)
}

#[cfg(target_os = "macos")]
fn local_addr_toward(dest: Ipv4Addr) -> Result<Option<Ipv4Addr>, String> {
    use std::net::{IpAddr, SocketAddr, UdpSocket};

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("route observation socket bind: {error}"))?;
    if let Err(error) = socket.connect(SocketAddr::from((dest, 53))) {
        if no_route(&error) { return Ok(None); }
        return Err(format!("route observation socket connect: {error}"));
    }
    match socket.local_addr().map_err(|error| format!("route observation socket local address: {error}"))?.ip() {
        IpAddr::V4(address) if !address.is_unspecified() => Ok(Some(address)),
        IpAddr::V4(_) => Ok(None),
        IpAddr::V6(_) => Err("IPv4 route observation returned an IPv6 source address".into()),
    }
}

#[cfg(target_os = "macos")]
fn interfaces() -> Result<Vec<Interface>, String> {
    use std::ffi::CStr;

    let mut out: Vec<Interface> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes head, and the list is freed once below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(format!("getifaddrs: {}", std::io::Error::last_os_error()));
    }
    let mut current = head;
    while !current.is_null() {
        // SAFETY: the nodes and their address/name pointers remain live until freeifaddrs.
        let interface = unsafe { &*current };
        current = interface.ifa_next;
        if interface.ifa_name.is_null() || interface.ifa_addr.is_null()
            || interface.ifa_flags & libc::IFF_UP as u32 == 0
            || unsafe { (*interface.ifa_addr).sa_family } as i32 != libc::AF_INET {
            continue;
        }
        // SAFETY: a live, NUL-terminated interface name and an AF_INET socket address.
        let Some(index) = NonZeroU32::new(unsafe { libc::if_nametoindex(interface.ifa_name) }) else { continue; };
        let address = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in>() };
        let address = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
        if let Some(entry) = out.iter_mut().find(|entry| entry.index == index) {
            entry.v4.push(address);
        } else {
            out.push(Interface {
                name: unsafe { CStr::from_ptr(interface.ifa_name) }.to_string_lossy().into_owned(),
                index,
                v4: vec![address],
                point_to_point: interface.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0,
            });
        }
    }
    // SAFETY: the caller owns the list returned by the successful getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, index: u32, address: &str, point_to_point: bool) -> Interface {
        Interface { name: name.into(), index: NonZeroU32::new(index).unwrap(),
            v4: vec![address.parse().unwrap()], point_to_point }
    }

    #[test]
    fn follows_the_default_or_pins_the_first_usable_provider() {
        let interfaces = [
            interface("en0", 4, "192.0.2.1", false),
            interface("en1", 5, "192.0.2.2", false),
            interface("utun4", 22, "192.0.2.3", false),
            interface("other", 23, "192.0.2.4", true),
        ];
        let direct = select_egress(interfaces[0].v4[0], &interfaces, "default 192.0.2.5 UGSc en0").unwrap();
        assert_eq!(direct.pin(), 0);
        assert!(!direct.tunnel());
        let table = "Destination Gateway Flags Netif Expire\n\
            default link#22 UCSg utun4\n\
            default 192.0.2.5 UGSc other\n\
            default 192.0.2.5 UGSc missing\n\
            default 192.0.2.5 UGScIg en1\n\
            default 192.0.2.5 UGSc en0\n";
        let tunnel = select_egress(interfaces[2].v4[0], &interfaces, table).unwrap();
        assert_eq!(tunnel.pin(), 5);
        assert!(tunnel.tunnel());
        assert_ne!(tunnel, direct);
        assert!(select_egress(interfaces[2].v4[0], &interfaces, "default link#22 UCSg utun4").is_none());
    }

    #[test]
    fn same_index_cannot_hide_a_gateway_or_source_change() {
        let first = [interface("en0", 4, "192.0.2.1", false)];
        let second = [interface("en0", 4, "192.0.2.2", false)];
        let old = select_egress(first[0].v4[0], &first, "default 192.0.2.5 UGSc en0").unwrap();
        let gateway = select_egress(first[0].v4[0], &first, "default 192.0.2.6 UGSc en0").unwrap();
        let source = select_egress(second[0].v4[0], &second, "default 192.0.2.5 UGSc en0").unwrap();
        assert_ne!(old, gateway);
        assert_ne!(old, source);
        assert_eq!(old.pin(), gateway.pin());
        assert_eq!(old.pin(), source.pin());
    }

    #[test]
    fn expected_no_route_excludes_operational_socket_errors() {
        assert!(no_route(&io::ErrorKind::NetworkUnreachable.into()));
        assert!(no_route(&io::ErrorKind::HostUnreachable.into()));
        assert!(!no_route(&io::ErrorKind::PermissionDenied.into()));
        assert!(!no_route(&io::ErrorKind::AddrNotAvailable.into()));
    }

    #[test]
    fn duplicate_or_missing_local_address_cannot_prove_the_default_route() {
        let address = "192.0.2.1".parse().unwrap();
        let first = interface("en0", 4, "192.0.2.1", false);
        assert_eq!(default_interface(address, std::slice::from_ref(&first)).unwrap().index.get(), 4);
        assert!(default_interface(address, &[]).is_none());
        let second = interface("utun4", 22, "192.0.2.1", false);
        assert!(default_interface(address, &[first, second]).is_none());
    }
}
