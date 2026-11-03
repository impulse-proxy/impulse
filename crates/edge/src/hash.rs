use std::sync::atomic::AtomicU64;

pub(crate) static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
const FNV_OFFSET_BASIS_64: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME_64: u64 = 0x0000_0100_0000_01b3;

pub(crate) fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
}

#[cfg(test)]
pub(crate) fn stable_hash_socket_addr(addr: &std::net::SocketAddr) -> u64 {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let mut bytes = [0u8; 7];
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&v4.ip().octets());
            bytes[5..7].copy_from_slice(&v4.port().to_be_bytes());
            stable_hash64(&bytes)
        }
        std::net::SocketAddr::V6(v6) => {
            let mut bytes = [0u8; 31];
            bytes[0] = 6;
            bytes[1..17].copy_from_slice(&v6.ip().octets());
            bytes[17..19].copy_from_slice(&v6.port().to_be_bytes());
            bytes[19..23].copy_from_slice(&v6.flowinfo().to_be_bytes());
            bytes[23..27].copy_from_slice(&v6.scope_id().to_be_bytes());
            stable_hash64(&bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use super::{stable_hash_socket_addr, stable_hash64};

    #[test]
    fn stable_hash64_matches_known_fnv1a_vectors() {
        let cases = [
            (b"" as &[u8], 0xcbf2_9ce4_8422_2325u64),
            (b"a" as &[u8], 0xaf63_dc4c_8601_ec8cu64),
            (b"foobar" as &[u8], 0x8594_4171_f739_67e8u64),
            (b"hello world" as &[u8], 0x779a_65e7_023c_d2e7u64),
        ];

        for (input, expected) in cases {
            assert_eq!(
                stable_hash64(input),
                expected,
                "FNV-1a mismatch for {:?}",
                input
            );
        }
    }

    #[test]
    fn stable_hash_socket_addr_is_deterministic_for_ipv4_and_ipv6() {
        let ipv4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8443));
        let ipv6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            8443,
            7,
            3,
        ));

        assert_eq!(
            stable_hash_socket_addr(&ipv4),
            stable_hash_socket_addr(&ipv4)
        );
        assert_eq!(
            stable_hash_socket_addr(&ipv6),
            stable_hash_socket_addr(&ipv6)
        );
    }

    #[test]
    fn stable_hash_socket_addr_distinguishes_ipv4_from_ipv6() {
        let ipv4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8443));
        let ipv6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0));

        assert_ne!(
            stable_hash_socket_addr(&ipv4),
            stable_hash_socket_addr(&ipv6)
        );
    }
}
