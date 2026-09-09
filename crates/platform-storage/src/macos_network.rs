//! Read-only interface enumeration. Addresses are routing hints, never peer identity.

use std::{io, net::Ipv4Addr, ptr};

struct Interfaces(*mut libc::ifaddrs);

impl Drop for Interfaces {
    fn drop(&mut self) {
        // SAFETY: this list was returned by getifaddrs and is released exactly once.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

/// Returns a fresh snapshot of active broadcast-capable IPv4 interfaces.
/// No sockets, persistent state, or private keys are opened. Enumeration failure is distinct
/// from an empty snapshot so callers cannot turn a local failure into transport fallback.
pub fn ipv4_interface_subnets() -> io::Result<Vec<(Ipv4Addr, Ipv4Addr)>> {
    let mut head = ptr::null_mut();
    // SAFETY: head is a live, writable out pointer; libc owns the returned linked list.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let interfaces = Interfaces(head);
    let mut cursor = interfaces.0;
    let mut subnets = Vec::new();
    while !cursor.is_null() {
        // SAFETY: each node belongs to the live getifaddrs list, retained by interfaces.
        let entry = unsafe { &*cursor };
        if eligible_flags(entry.ifa_flags) {
            // SAFETY: non-null address pointers in this node belong to the same live list.
            if let (Some(address), Some(mask)) = unsafe {
                (
                    ipv4_address(entry.ifa_addr),
                    ipv4_address(entry.ifa_netmask),
                )
            } {
                subnets.push((address, mask));
            }
        }
        cursor = entry.ifa_next;
    }
    subnets.sort_unstable();
    subnets.dedup();
    Ok(subnets)
}

fn eligible_flags(flags: u32) -> bool {
    let required = (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_BROADCAST) as u32;
    let excluded = (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) as u32;
    flags & required == required && flags & excluded == 0
}

unsafe fn ipv4_address(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: caller guarantees the native sockaddr header. Read only the two header bytes
    // before requiring a full sockaddr_in; do not form a reference to a longer sockaddr.
    let (family, length) = unsafe {
        (
            ptr::addr_of!((*address).sa_family).read(),
            ptr::addr_of!((*address).sa_len).read(),
        )
    };
    if i32::from(family) != libc::AF_INET || usize::from(length) < size_of::<libc::sockaddr_in>() {
        return None;
    }
    // SAFETY: family and length were checked. Copy without assuming stronger pointer alignment.
    let value = unsafe { address.cast::<libc::sockaddr_in>().read_unaligned() };
    Some(Ipv4Addr::from(value.sin_addr.s_addr.to_ne_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_down_loopback_and_point_to_point_vpn_interfaces() {
        let active = (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_BROADCAST) as u32;
        assert!(eligible_flags(active));
        for flag in [libc::IFF_UP, libc::IFF_RUNNING, libc::IFF_BROADCAST] {
            assert!(!eligible_flags(active & !(u32::try_from(flag).unwrap())));
        }
        for flag in [libc::IFF_LOOPBACK, libc::IFF_POINTOPOINT] {
            assert!(!eligible_flags(active | u32::try_from(flag).unwrap()));
        }
    }

    #[test]
    fn validates_family_length_null_and_network_byte_order() {
        // SAFETY: all-zero sockaddr_in is valid plain data for this synthetic fixture.
        let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        address.sin_len = u8::try_from(size_of::<libc::sockaddr_in>()).unwrap();
        address.sin_family = u8::try_from(libc::AF_INET).unwrap();
        address.sin_addr.s_addr = u32::from_ne_bytes([192, 168, 10, 7]);
        // SAFETY: each pointer references the live fixture; null is explicitly supported.
        unsafe {
            assert_eq!(ipv4_address(ptr::null()), None);
            assert_eq!(
                ipv4_address((&raw const address).cast()),
                Some(Ipv4Addr::new(192, 168, 10, 7))
            );
            address.sin_family = u8::try_from(libc::AF_INET6).unwrap();
            assert_eq!(ipv4_address((&raw const address).cast()), None);
            address.sin_family = u8::try_from(libc::AF_INET).unwrap();
            address.sin_len = 2;
            assert_eq!(ipv4_address((&raw const address).cast()), None);
        }
    }

    #[test]
    fn native_snapshot_is_sorted_and_deduplicated() {
        let values = ipv4_interface_subnets().unwrap();
        assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
