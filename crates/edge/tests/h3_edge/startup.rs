use super::*;

#[test]
fn http3_request_is_accepted_and_parsed() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config(0, cert, key, "127.0.0.1:1".to_string());
    let mut listener = Http3Service::new(config).expect("failed to create listener");
    let addr = listener.socket.local_addr().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = stop.clone();

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let handle = rt.spawn_blocking(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            listener.poll();
        }
    });

    let body = run_h3_client(addr).expect("client request failed");
    stop.store(true, Ordering::Relaxed);
    handle.abort();

    assert!(body.contains("upstream error"));
}

#[test]
fn invalid_backend_scheme_is_rejected_at_startup() {
    if !local_listener_bind_available() {
        return;
    }
    let dir = tempdir().expect("failed to create temp dir");
    let (cert, key) = write_test_certs(&dir);
    let config = make_config(0, cert, key, "ftp://127.0.0.1:8080".to_string());
    match Http3Service::new(config) {
        Ok(_) => panic!("invalid backend scheme should fail startup"),
        Err(err) => {
            assert!(
                err.to_string().contains("backend_address_invalid"),
                "unexpected startup error: {err}"
            );
        }
    }
}
