use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use impulse_edge::runtime::backend::{
    resolution::RuntimeBackendResolution, store::RuntimeBackendResolutionStore,
};

#[test]
fn store_snapshot_preserves_seeded_resolution_state() {
    let store = RuntimeBackendResolutionStore::new([RuntimeBackendResolution::ip_literal(
        "127.0.0.1:8080".to_string(),
        "127.0.0.1".to_string(),
        8080,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)],
    )]);

    let snapshot = store.snapshot();
    let entry = snapshot.get("127.0.0.1:8080").expect("entry");
    assert_eq!(entry.resolution.authority_host, "127.0.0.1");
    assert_eq!(entry.resolution.authority_port, 8080);
    assert_eq!(entry.resolution.resolved_addrs.len(), 1);
}
