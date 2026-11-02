use super::*;

#[test]
fn connection_flood_is_rate_limited() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config_with_rate_limit(0, cert, key, "127.0.0.1:1".to_string(), 1, 1);
    let mut listener = Http3Service::new(config).expect("listener");
    let addr = listener.socket.local_addr().unwrap();

    const FLOOD_COUNT: usize = 10;
    let packets: Vec<Vec<u8>> = (0..FLOOD_COUNT)
        .map(|_| build_initial_packet(addr))
        .collect();
    for pkt in &packets {
        send_udp(addr, pkt);
    }
    for _ in 0..FLOOD_COUNT {
        listener.poll();
    }

    assert!(
        listener.connections().len() <= 1,
        "rate limiter must cap connections at burst=1, got {}",
        listener.connections().len()
    );
}

#[test]
fn active_connection_cap_rejects_excess_initial_packets() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config =
        make_config_with_rate_limit(0, cert, key, "127.0.0.1:1".to_string(), 10_000, 10_000);
    config.performance.max_active_connections = 1;
    let mut listener = Http3Service::new(config).expect("listener");
    let addr = listener.socket.local_addr().unwrap();

    const FLOOD_COUNT: usize = 8;
    for _ in 0..FLOOD_COUNT {
        let pkt = build_initial_packet(addr);
        send_udp(addr, &pkt);
        listener.poll();
    }

    assert!(
        listener.connections().len() <= 1,
        "active connection cap must keep at most one connection, got {}",
        listener.connections().len()
    );
    assert!(
        listener
            .metrics
            .connection_cap_rejects
            .load(Ordering::Relaxed)
            > 0,
        "connection cap should emit rejection metrics"
    );
}

#[test]
fn draining_mode_rejects_initial_when_no_connections_exist() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config_with_rate_limit(0, cert, key, "127.0.0.1:1".to_string(), 10_000, 20);
    let mut listener = Http3Service::new(config).expect("listener");
    let addr = listener.socket.local_addr().unwrap();

    listener.start_draining();

    let pkt = build_initial_packet(addr);
    send_udp(addr, &pkt);
    listener.poll();

    assert_eq!(listener.connections().len(), 0);
}

#[test]
fn draining_mode_rejects_new_initial_after_existing_connection() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config_with_rate_limit(0, cert, key, "127.0.0.1:1".to_string(), 10_000, 20);
    let mut listener = Http3Service::new(config).expect("listener");
    let addr = listener.socket.local_addr().unwrap();

    let first = build_initial_packet(addr);
    send_udp(addr, &first);
    listener.poll();
    assert_eq!(listener.connections().len(), 1);
    let known_connection_ids: std::collections::HashSet<Vec<u8>> = listener
        .connections()
        .keys()
        .map(|cid| cid.to_vec())
        .collect();

    listener.start_draining();

    for _ in 0..5 {
        let pkt = build_initial_packet(addr);
        send_udp(addr, &pkt);
        listener.poll();
    }

    let post_drain_ids: std::collections::HashSet<Vec<u8>> = listener
        .connections()
        .keys()
        .map(|cid| cid.to_vec())
        .collect();
    assert!(post_drain_ids.is_subset(&known_connection_ids));
}

#[test]
fn normal_traffic_below_rate_limit_is_unaffected() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config_with_rate_limit(0, cert, key, "127.0.0.1:1".to_string(), 10_000, 20);
    let mut listener = Http3Service::new(config).expect("listener");
    let addr = listener.socket.local_addr().unwrap();

    const REQUEST_COUNT: usize = 5;
    for _ in 0..REQUEST_COUNT {
        let pkt = build_initial_packet(addr);
        send_udp(addr, &pkt);
        listener.poll();
    }

    assert_eq!(listener.connections().len(), REQUEST_COUNT);
}
