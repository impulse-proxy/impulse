use super::*;

#[test]
fn lifecycle_churn_leaves_no_orphaned_state() {
    if !local_listener_bind_available() {
        return;
    }
    const ROUNDS: usize = 30;
    const IDLE_MS: u64 = 500;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend("ok\n"));

    let mut config = make_config(0, cert, key, backend_addr.to_string());
    config.performance.quic_max_idle_timeout_ms = IDLE_MS;
    config.performance.new_connections_per_sec = 10_000;
    config.performance.new_connections_burst = 1_000;

    let listener = Arc::new(Mutex::new(
        Http3Service::new(config).expect("failed to create listener"),
    ));
    let server_addr = listener.lock().unwrap().socket.local_addr().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = stop.clone();
    let listener_poll = listener.clone();
    let poll_handle = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            if let Ok(mut g) = listener_poll.lock() {
                g.poll();
            }
        }
    });

    for round in 0..ROUNDS {
        let (socket, _local_addr, mut conn, _h3) =
            stress_connect(server_addr).unwrap_or_else(|e| panic!("round {round}: connect: {e}"));

        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set_read_timeout");

        if round % 2 == 0 {
            stress_close_gracefully(&socket, &mut conn);
        }
    }

    thread::sleep(Duration::from_millis(IDLE_MS * 3));

    stop.store(true, Ordering::Relaxed);
    let _ = poll_handle.join();

    if let Ok(mut g) = listener.lock() {
        for _ in 0..20 {
            g.poll();
        }
    }

    let guard = listener.lock().expect("listener lock");
    assert_cid_sync_invariants(&guard);
    assert!(guard.connections().is_empty());
    assert!(guard.cid_routes().is_empty());
    assert!(guard.peer_routes().is_empty());
}
