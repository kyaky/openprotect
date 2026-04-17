//! End-to-end IPC round trip: bind a unix socket, spawn a server task,
//! hit it with the client helper. No external processes, no sudo, no
//! libopenconnect involvement.
//!
//! Unix-only: requires Unix domain sockets.
#![cfg(unix)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use gp_ipc::{
    bind_server, build_snapshot, client_roundtrip, read_request, write_response, IpcError, Request,
    Response, SessionState, StateSnapshotBase,
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

/// Wrap a Path into the string the cross-platform API expects.
fn endpoint(path: &std::path::Path) -> String {
    path.to_string_lossy().to_string()
}

/// A minimal "server" that services exactly one request and then
/// returns, mirroring the shape the real opc daemon uses.
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

    let resp = client_roundtrip(&endpoint(&path), &Request::Status)
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

    let _ = client_roundtrip(&endpoint(&path), &Request::Disconnect).await;
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

    let resp = client_roundtrip(&endpoint(&path), &Request::Disconnect)
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
    let err = client_roundtrip(&endpoint(&path), &Request::Status)
        .await
        .expect_err("should fail");
    assert!(
        matches!(err, IpcError::NotRunning(_)),
        "expected NotRunning, got {err:?}"
    );
}

#[tokio::test]
async fn bind_server_removes_stale_socket_file() {
    let path = temp_socket("stale-file");
    std::fs::write(&path, b"not a socket").unwrap();
    let _listener = bind_server(&path).await.expect("bind over stale file");
    assert!(path.exists());
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn bind_server_refuses_when_live_peer_is_bound() {
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
async fn client_roundtrip_times_out_on_wedged_server() {
    let path = temp_socket("wedged");
    let listener = UnixListener::bind(&path).expect("bind");

    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept");
        std::future::pending::<()>().await;
    });

    let start = std::time::Instant::now();
    let result = client_roundtrip(&endpoint(&path), &Request::Status).await;
    let elapsed = start.elapsed();

    server.abort();
    let _ = std::fs::remove_file(&path);

    assert!(
        result.is_err(),
        "wedged server must yield an error, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "client_roundtrip took {elapsed:?} on a wedged server — timeout not firing"
    );
}

#[tokio::test]
async fn started_at_unix_is_stable_across_queries() {
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
