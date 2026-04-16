//! End-to-end IPC round trip: bind a unix socket, spawn a server task,
//! hit it with the client helper. No external processes, no sudo, no
//! libopenconnect involvement.
//!
//! Unix-only: requires Unix domain sockets.
#![cfg(unix)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use gp_ipc::{
    bind_server, build_snapshot, client_roundtrip, enumerate_live_instances, read_request,
    write_response, IpcError, Request, Response, SessionState, StateSnapshotBase,
};
use tokio::net::UnixListener;
use tokio::sync::oneshot;

/// Helper that picks a unique, per-test socket path inside the temp dir
/// so parallel tests don't collide.
fn temp_socket(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "gp-ipc-test-{}-{}-{}.sock",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    p
}

/// A minimal "server" that services exactly one request and then
/// returns, mirroring the shape the real pgn daemon uses.
async fn serve_once(
    listener: UnixListener,
    base: StateSnapshotBase,
    started_at: Instant,
    disconnect_tx: oneshot::Sender<()>,
) {
    let mut disconnect_tx = Some(disconnect_tx);
    loop {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let req = read_request(&mut stream).await.expect("read request");
        let resp = match req {
            Request::Status => Response::Status(build_snapshot(&base, started_at)),
            Request::Disconnect => {
                if let Some(tx) = disconnect_tx.take() {
                    let _ = tx.send(());
                }
                Response::Ok
            }
        };
        write_response(&mut stream, &resp)
            .await
            .expect("write response");
        // Keep serving until the test finishes with us.
        if matches!(resp, Response::Ok) {
            return;
        }
    }
}

fn base(instance: &str) -> StateSnapshotBase {
    StateSnapshotBase {
        instance: instance.to_string(),
        portal: "vpn.example.com".into(),
        gateway: "gw.example.com".into(),
        user: "alice@example.com".into(),
        reported_os: "win".into(),
        routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
        started_at_unix: 1_700_000_000,
        tun_ifname: Some("tun0".into()),
        local_ipv4: Some("10.0.0.42".into()),
        state: SessionState::Connected,
    }
}

#[tokio::test]
async fn status_returns_snapshot_fields_with_instance() {
    let path = temp_socket("status");
    let listener = bind_server(&path).await.expect("bind");
    let started_at = Instant::now();
    let (dx_tx, _dx_rx) = oneshot::channel::<()>();
    let base_for_srv = base("work");
    let server =
        tokio::spawn(async move { serve_once(listener, base_for_srv, started_at, dx_tx).await });

    let resp = client_roundtrip(&path, &Request::Status)
        .await
        .expect("roundtrip");
    match resp {
        Response::Status(s) => {
            assert_eq!(s.instance, "work");
            assert_eq!(s.portal, "vpn.example.com");
            assert_eq!(s.gateway, "gw.example.com");
            assert_eq!(s.user, "alice@example.com");
            assert_eq!(s.reported_os, "win");
            assert_eq!(s.routes, vec!["10.0.0.0/8", "192.168.1.0/24"]);
            assert_eq!(s.tun_ifname.as_deref(), Some("tun0"));
            assert_eq!(s.local_ipv4.as_deref(), Some("10.0.0.42"));
            assert_eq!(s.state, SessionState::Connected);
            assert!(s.uptime_seconds < 10);
        }
        other => panic!("expected Status, got {other:?}"),
    }

    let _ = client_roundtrip(&path, &Request::Disconnect).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn disconnect_fires_oneshot_and_returns_ok() {
    let path = temp_socket("disconnect");
    let listener = bind_server(&path).await.expect("bind");
    let started_at = Instant::now();
    let (dx_tx, dx_rx) = oneshot::channel::<()>();
    let base_for_srv = base("default");
    let server =
        tokio::spawn(async move { serve_once(listener, base_for_srv, started_at, dx_tx).await });

    let resp = client_roundtrip(&path, &Request::Disconnect)
        .await
        .expect("roundtrip");
    assert!(matches!(resp, Response::Ok));

    tokio::time::timeout(Duration::from_secs(2), dx_rx)
        .await
        .expect("dx_rx timeout")
        .expect("dx_rx closed");

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn client_without_server_reports_not_running() {
    let path = temp_socket("empty");
    // Don't bind anything — expect NotRunning.
    let err = client_roundtrip(&path, &Request::Status)
        .await
        .expect_err("should fail");
    assert!(
        matches!(err, IpcError::NotRunning(_)),
        "expected NotRunning, got {err:?}"
    );
}

#[tokio::test]
async fn bind_server_removes_stale_socket_file() {
    // A plain file lingering at the socket path with no listener
    // behind it — bind_server should unlink it and successfully
    // bind.
    let path = temp_socket("stale-file");
    std::fs::write(&path, b"not a socket").unwrap();
    let _listener = bind_server(&path).await.expect("bind over stale file");
    assert!(path.exists());
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn bind_server_refuses_when_live_peer_is_bound() {
    // Two servers claiming the same path: the second must refuse.
    let path = temp_socket("collision");
    let _listener = bind_server(&path).await.expect("first bind");

    let err = bind_server(&path).await.expect_err("second bind must fail");
    assert!(
        matches!(err, IpcError::AlreadyRunning(_)),
        "expected AlreadyRunning, got {err:?}"
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn enumerate_live_instances_finds_live_skips_stale() {
    // Build a throwaway "socket dir" under /tmp. The helper is
    // normally aimed at /run/pangolin but accepts any directory —
    // tests pass their own to stay hermetic.
    let dir = std::env::temp_dir().join(format!(
        "gp-ipc-dir-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let live_path = dir.join("live.sock");
    let stale_path = dir.join("stale.sock");
    let _listener = bind_server(&live_path).await.expect("bind live");
    // Stale: a plain file with the .sock extension.
    std::fs::write(&stale_path, b"").unwrap();

    let found = enumerate_live_instances(&dir).await;
    assert!(
        found.iter().any(|(n, _)| n == "live"),
        "live.sock should be enumerated, got {found:?}"
    );
    assert!(
        !found.iter().any(|(n, _)| n == "stale"),
        "stale.sock should be filtered out, got {found:?}"
    );

    let _ = std::fs::remove_file(&live_path);
    let _ = std::fs::remove_file(&stale_path);
    let _ = std::fs::remove_dir(&dir);
}

#[tokio::test]
async fn client_roundtrip_times_out_on_wedged_server() {
    // A server that accepts the connection but never reads or
    // writes must not hang the client. The full-operation timeout
    // is 5s; this test just needs to prove it fires.
    let path = temp_socket("wedged");
    let listener = UnixListener::bind(&path).expect("bind");

    let server = tokio::spawn(async move {
        // Accept once, then sit on the socket forever.
        let (_stream, _) = listener.accept().await.expect("accept");
        std::future::pending::<()>().await;
    });

    let start = std::time::Instant::now();
    let result = client_roundtrip(&path, &Request::Status).await;
    let elapsed = start.elapsed();

    server.abort();
    let _ = std::fs::remove_file(&path);

    assert!(
        result.is_err(),
        "wedged server must yield an error, got {result:?}"
    );
    // Must return within a bit more than CLIENT_REQUEST_TIMEOUT
    // (5s) — definitely not hang indefinitely. Generous upper
    // bound to avoid test flakes on a slow CI runner.
    assert!(
        elapsed < Duration::from_secs(8),
        "client_roundtrip took {elapsed:?} on a wedged server — timeout not firing"
    );
}

#[tokio::test]
async fn enumerate_live_instances_skips_non_socket_files() {
    let dir = std::env::temp_dir().join(format!(
        "gp-ipc-filter-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // A regular file with .sock extension — must NOT be probed
    // (would race with connect returning ConnectionRefused).
    let regular = dir.join("regular.sock");
    std::fs::write(&regular, b"").unwrap();

    // A subdirectory named *.sock — also must be skipped.
    let dir_sock = dir.join("dir.sock");
    std::fs::create_dir(&dir_sock).unwrap();

    // And one actual live socket, so we have a positive control.
    let live_path = dir.join("live.sock");
    let _listener = bind_server(&live_path).await.expect("bind live");

    let found = enumerate_live_instances(&dir).await;
    let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["live"],
        "only the live socket should be enumerated, got {names:?}"
    );

    let _ = std::fs::remove_file(&live_path);
    let _ = std::fs::remove_file(&regular);
    let _ = std::fs::remove_dir(&dir_sock);
    let _ = std::fs::remove_dir(&dir);
}

#[tokio::test]
async fn started_at_unix_is_stable_across_queries() {
    // build_snapshot must read `started_at_unix` from the base rather
    // than derive it from the wall clock, so two consecutive snapshots
    // with a small Instant gap in between still report the same value.
    use std::time::Instant;
    let base = base("default");
    let t0 = Instant::now();
    let s1 = build_snapshot(&base, t0);
    std::thread::sleep(Duration::from_millis(20));
    let s2 = build_snapshot(&base, t0);
    assert_eq!(s1.started_at_unix, s2.started_at_unix);
    assert_eq!(s1.started_at_unix, 1_700_000_000);
    assert_eq!(s1.instance, "default");
}
