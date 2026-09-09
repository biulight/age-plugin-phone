//! Interface enumeration and scoped UDP sends. Addresses are routing hints, never peer identity.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    ptr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Interface {
    pub index: u32,
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
}

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
pub fn ipv4_interfaces() -> io::Result<Vec<Ipv4Interface>> {
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
                    ipv4_netmask(entry.ifa_netmask),
                )
            } {
                if entry.ifa_name.is_null() {
                    return Err(io::Error::other("interface name unavailable"));
                }
                // SAFETY: ifa_name is a NUL-terminated name in the retained getifaddrs list.
                let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
                if index == 0 {
                    return Err(io::Error::last_os_error());
                }
                subnets.push(Ipv4Interface {
                    index,
                    address,
                    mask,
                });
            }
        }
        cursor = entry.ifa_next;
    }
    subnets.sort_unstable();
    subnets.dedup();
    Ok(subnets)
}

/// Sends through the enumerated interface, then restores unrestricted reception.
/// The socket must not be used concurrently: `IP_BOUND_IF` is socket-wide state.
/// Both a send failure and a failure to clear the binding are terminal.
pub fn send_on_interface(
    socket: &UdpSocket,
    index: u32,
    bytes: &[u8],
    target: &SocketAddr,
) -> io::Result<usize> {
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing interface index",
        ));
    }
    bind_interface(socket, index)?;
    let sent = socket.send_to(bytes, target);
    bind_interface(socket, 0)?;
    sent
}

fn bind_interface(socket: &UdpSocket, index: u32) -> io::Result<()> {
    // SAFETY: socket owns a live descriptor and index is a correctly sized IP_BOUND_IF value.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            (&raw const index).cast(),
            libc::socklen_t::try_from(size_of::<u32>()).expect("u32 socket option size"),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

// Darwin may truncate zero suffix bytes of a sockaddr netmask (e.g. /24 has sa_len=7).
// Unlike a full interface address, its storage must not be read as a sockaddr_in.
unsafe fn ipv4_netmask(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: caller guarantees a live sockaddr header in the retained interface list.
    let (family, length) = unsafe {
        (
            ptr::addr_of!((*address).sa_family).read(),
            ptr::addr_of!((*address).sa_len).read(),
        )
    };
    let offset = std::mem::offset_of!(libc::sockaddr_in, sin_addr);
    let length = usize::from(length);
    if ![libc::AF_INET, libc::AF_UNSPEC].contains(&i32::from(family))
        || length < offset
        || length > size_of::<libc::sockaddr_in>()
    {
        return None;
    }
    let count = (length - offset).min(4);
    let mut octets = [0_u8; 4];
    // SAFETY: only count bytes within the advertised storage are read. Omitted suffix bytes
    // are zero mask bits, not permission to dereference the larger sockaddr_in layout.
    unsafe {
        ptr::copy_nonoverlapping(address.cast::<u8>().add(offset), octets.as_mut_ptr(), count);
    }
    Some(Ipv4Addr::from(octets))
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
    fn compact_darwin_netmasks_zero_extend_without_reading_the_suffix() {
        for (length, expected) in [
            (5, [255, 0, 0, 0]),
            (6, [255, 255, 0, 0]),
            (7, [255, 255, 255, 0]),
            (8, [255, 255, 255, 255]),
        ] {
            let mut encoded = [255_u8; 8];
            encoded[0] = length;
            encoded[1] = u8::try_from(libc::AF_INET).unwrap();
            // SAFETY: the buffer contains the header and every advertised byte; bytes beyond
            // sa_len deliberately remain nonzero to detect accidental full-struct reads.
            unsafe {
                assert_eq!(
                    ipv4_netmask(encoded.as_ptr().cast()),
                    Some(Ipv4Addr::from(expected))
                );
            }
        }
        let mut encoded = [0_u8; 8];
        encoded[0] = 7;
        encoded[4..7].fill(255);
        // SAFETY: each call reads only the live eight-byte fixture, or the explicitly supported null.
        unsafe {
            assert_eq!(
                ipv4_netmask(encoded.as_ptr().cast()),
                Some(Ipv4Addr::new(255, 255, 255, 0))
            );
            encoded[1] = u8::try_from(libc::AF_INET6).unwrap();
            assert_eq!(ipv4_netmask(encoded.as_ptr().cast()), None);
            encoded[1] = 0;
            encoded[0] = 2;
            assert_eq!(ipv4_netmask(encoded.as_ptr().cast()), None);
            assert_eq!(ipv4_netmask(ptr::null()), None);
        }
    }

    fn bound_interface(socket: &UdpSocket) -> u32 {
        let mut index = 0_u32;
        let mut length = libc::socklen_t::try_from(size_of::<u32>()).unwrap();
        // SAFETY: both output pointers reference writable, correctly sized socket-option storage.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                (&raw mut index).cast(),
                &raw mut length,
            )
        };
        assert_eq!(result, 0);
        index
    }

    #[test]
    fn scoped_send_clears_binding_after_success_and_failure() {
        // SAFETY: the static C string is NUL-terminated and lives through the call.
        let index = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        assert_ne!(index, 0);
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        assert_eq!(
            send_on_interface(
                &sender,
                index,
                b"synthetic",
                &receiver.local_addr().unwrap()
            )
            .unwrap(),
            9
        );
        assert_eq!(bound_interface(&sender), 0);
        let mut buffer = [0_u8; 16];
        assert_eq!(receiver.recv_from(&mut buffer).unwrap().0, 9);
        // IPv6 is incompatible with this IPv4 socket; the failed send still clears IP_BOUND_IF.
        let wrong_family = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 9));
        assert!(send_on_interface(&sender, index, b"synthetic", &wrong_family).is_err());
        assert_eq!(bound_interface(&sender), 0);
        assert!(
            send_on_interface(&sender, 0, b"synthetic", &receiver.local_addr().unwrap()).is_err()
        );
        assert!(
            send_on_interface(
                &sender,
                u32::MAX,
                b"synthetic",
                &receiver.local_addr().unwrap()
            )
            .is_err()
        );
        assert_eq!(bound_interface(&sender), 0);
    }

    #[test]
    fn native_snapshot_is_sorted_and_deduplicated() {
        let values = ipv4_interfaces().unwrap();
        assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
