use super::*;

#[test]
fn server_rotates_scids_for_active_connection() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let backend_addr = rt.block_on(start_h2_backend("ok\n"));
    let config = make_config(0, cert, key, backend_addr.to_string());
    let listener = Arc::new(Mutex::new(
        Http3Service::new(config).expect("failed to create listener"),
    ));
    let addr = listener
        .lock()
        .expect("listener lock")
        .socket
        .local_addr()
        .unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = stop.clone();
    let listener_task = listener.clone();

    let handle = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            if let Ok(mut guard) = listener_task.lock() {
                guard.poll();
            }
        }
    });

    let (max_spare_dcids, completed_requests) =
        run_h3_client_multiple_requests(addr, 12).expect("client requests failed");

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    let listener_guard = listener.lock().expect("listener lock");
    let rotations = listener_guard
        .metrics
        .scid_rotations
        .load(Ordering::Relaxed);

    assert!(
        max_spare_dcids > 0,
        "client never observed additional destination CIDs"
    );
    assert!(
        completed_requests > 0,
        "client did not complete any request"
    );
    assert!(rotations > 0, "server did not rotate any SCID");
    assert_cid_sync_invariants(&listener_guard);
}
