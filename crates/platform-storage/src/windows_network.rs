use std::{mem::size_of, net::Ipv4Addr};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::{GetIpAddrTable, MIB_IPADDRROW_XP, MIB_IPADDRTABLE},
};

const MAX_TABLE_BYTES: usize = 1_048_576;

/// Returns the IPv4 address and mask reported for each Windows interface.
///
/// This is route metadata only. Callers still decide which subnets are eligible and authenticate
/// every discovery response independently.
#[must_use]
pub fn ipv4_interface_subnets() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let mut bytes = 0_u32;
    // SAFETY: The documented sizing call accepts a null table and writes only `bytes`.
    let first = unsafe { GetIpAddrTable(std::ptr::null_mut(), &raw mut bytes, 0) };
    let byte_count = usize::try_from(bytes).unwrap_or(0);
    if first != ERROR_INSUFFICIENT_BUFFER
        || byte_count < size_of::<MIB_IPADDRTABLE>()
        || byte_count > MAX_TABLE_BYTES
    {
        return Vec::new();
    }

    let words = byte_count.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let table = storage.as_mut_ptr().cast::<MIB_IPADDRTABLE>();
    // SAFETY: `storage` is suitably aligned, writable, and at least `bytes` long.
    if unsafe { GetIpAddrTable(table, &raw mut bytes, 0) } != NO_ERROR {
        return Vec::new();
    }

    let returned_bytes = usize::try_from(bytes)
        .unwrap_or(0)
        .min(storage.len() * size_of::<usize>());
    // SAFETY: A successful call initialized the fixed table header.
    let count = unsafe { (*table).dwNumEntries as usize };
    let header_bytes = size_of::<u32>();
    if count > returned_bytes.saturating_sub(header_bytes) / size_of::<MIB_IPADDRROW_XP>() {
        return Vec::new();
    }
    // SAFETY: The count was bounded by the returned initialized buffer size.
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).table).cast::<MIB_IPADDRROW_XP>(),
            count,
        )
    };
    rows.iter()
        .map(|row| {
            (
                Ipv4Addr::from(row.dwAddr.to_ne_bytes()),
                Ipv4Addr::from(row.dwMask.to_ne_bytes()),
            )
        })
        .collect()
}
