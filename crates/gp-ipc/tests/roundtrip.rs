//! End-to-end IPC round trip: bind a unix socket, spawn a server task,
//! hit it with the client helper. No external processes, no sudo, no
//! libopenconnect involvement.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use gp_ipc::{
    bind_server, build_snapshot, client_roundtrip, read_request, write_response, Request,
    Response, StateSnapshotBase,
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

fn base() -> StateSnapshotBase {
    StateSnapshotBase {
        portal: "vpn.example.com".into(),
        gateway: "gw.example.com".into(),
        user: "alice@example.com".into(),
        reported_os: "win".into(),
        routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
        started_at_unix: 1_700_000_000,
    }
}

#[tokio::test]
async fn status_returns_snapshot_fields() {
    let path = temp_socket("status");
    let listener = bind_server(&path).await.expect("bind");
    let started_at = Instant::now();
    let (dx_tx, _dx_rx) = oneshot::channel::<()>();
    let base_for_srv = base();
    let server =
        tokio::spawn(async move { serve_once(listener, base_for_srv, started_at, dx_tx).await });

    let resp = client_roundtrip(&path, &Request::Status)
        .await
        .expect("roundtrip");
    match resp {
        Response::Status(s) => {
            assert_eq!(s.portal, "vpn.example.com");
            assert_eq!(s.gateway, "gw.example.com");
            assert_eq!(s.user, "alice@example.com");
            assert_eq!(s.reported_os, "win");
            assert_eq!(s.routes, vec!["10.0.0.0/8", "192.168.1.0/24"]);
            // uptime should be a small non-negative number.
            assert!(s.uptime_seconds < 10);
        }
        other => panic!("expected Status, got {other:?}"),
    }

    // Shut the server thread down by issuing a Disconnect so its loop exits.
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
    let base_for_srv = base();
    let server =
        tokio::spawn(async move { serve_once(listener, base_for_srv, started_at, dx_tx).await });

    let resp = client_roundtrip(&path, &Request::Disconnect)
        .await
        .expect("roundtrip");
    assert!(matches!(resp, Response::Ok));

    // The server's disconnect_tx should have fired.
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
        matches!(err, gp_ipc::IpcError::NotRunning(_)),
        "expected NotRunning, got {err:?}"
    );
}

#[tokio::test]
async fn started_at_unix_is_stable_across_queries() {
    // build_snapshot must read `started_at_unix` from the base rather
    // than derive it from the wall clock, so two consecutive snapshots
    // with a small Instant gap in between still report the same value.
    use std::time::Instant;
    let base = base();
    let t0 = Instant::now();
    let s1 = build_snapshot(&base, t0);
    std::thread::sleep(Duration::from_millis(20));
    let s2 = build_snapshot(&base, t0);
    assert_eq!(s1.started_at_unix, s2.started_at_unix);
    assert_eq!(s1.started_at_unix, 1_700_000_000);
}
