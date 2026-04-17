//! Prometheus metrics endpoint for a running `opc connect` session.
//!
//! This is deliberately hand-rolled: no `prometheus` crate, no Axum, no
//! Hyper — just a `TcpListener`, a one-shot GET parse, and a `String`
//! built via `writeln!`. The Prometheus text exposition format is
//! simple enough that the serialize path is ~50 lines, and keeping
//! the dependency count honest is part of the project's "minimal
//! deps" rule.
//!
//! # Metrics exposed
//!
//! * `openprotect_session_info{instance, portal, gateway, user,
//!   reported_os, tun_ifname}` — constant 1 gauge labeling the
//!   session. Prometheus idiom for "static metadata about this
//!   target".
//! * `openprotect_session_state{instance, state}` — one gauge per
//!   possible state with the value `1` for the live state and `0`
//!   for the rest. Easier to alert on than a multi-valued gauge.
//! * `openprotect_session_started_at_unix{instance}` — session start
//!   unix timestamp, stable across wall-clock jumps.
//! * `openprotect_session_uptime_seconds{instance}` — derived per
//!   scrape from a stored `Instant`, not the wall clock.
//! * `openprotect_session_routes{instance}` — number of split-tunnel
//!   routes installed by `gp-route`.
//! * `openprotect_reconnect_attempts_total{instance}` — monotonic
//!   counter bumped by the app-level reconnect loop every time
//!   libopenconnect's mainloop exits and we decide to retry.
//! * `openprotect_tunnel_restarts_total{instance}` — monotonic counter
//!   bumped once per *successful* tunnel re-establishment (handshake
//!   + setup_tun_device completed).
//!
//! # Authentication
//!
//! None. The listener binds to a CLI-configured port, defaults to
//! not listening at all (`--metrics-port` is off by default), and
//! is intended for `curl localhost:9100/metrics` or a local
//! Prometheus scrape. Binding to a non-loopback interface is the
//! operator's call — they'd be putting their portal/user/gateway
//! on the wire regardless, so no attempt is made to hide those.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use gp_ipc::{SessionState, StateSnapshotBase};

/// Shared, interior-mutable tunnel state — same alias as in main.rs.
/// Defined again here so the metrics module doesn't need a circular
/// import.
pub type SharedBase = Arc<RwLock<StateSnapshotBase>>;

/// Monotonic counters shared between the reconnect state machine
/// and the metrics endpoint. Every field is an `AtomicU64` so
/// counter bumps are lock-free and don't need to touch the metrics
/// task's event loop.
#[derive(Debug, Default)]
pub struct MetricsCounters {
    pub reconnect_attempts: AtomicU64,
    pub tunnel_restarts: AtomicU64,
}

impl MetricsCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// Everything the metrics serializer needs to render one scrape.
/// Cheap-to-clone: all `Arc`s or copyable scalars.
#[derive(Clone)]
pub struct MetricsState {
    pub base: SharedBase,
    pub started_at: Instant,
    pub counters: Arc<MetricsCounters>,
}

/// Render the current scrape body in Prometheus text exposition
/// format. Pure function; callers pass an Instant for `now` so
/// unit tests can be deterministic.
pub fn render_scrape(state: &MetricsState, now: Instant) -> String {
    // Short critical section: lock, clone out the fields we need,
    // release. Never awaits while the guard is held.
    let base = state
        .base
        .read()
        .expect("SharedBase RwLock poisoned")
        .clone();
    let base = &base;
    let instance = &base.instance;
    let uptime = now.saturating_duration_since(state.started_at).as_secs();

    let mut out = String::with_capacity(2048);

    // session_info: constant gauge carrying labels.
    out.push_str("# HELP openprotect_session_info Static metadata about the running opc session.\n");
    out.push_str("# TYPE openprotect_session_info gauge\n");
    out.push_str("openprotect_session_info{");
    write_labels(
        &mut out,
        &[
            ("instance", instance),
            ("portal", &base.portal),
            ("gateway", &base.gateway),
            ("user", &base.user),
            ("reported_os", &base.reported_os),
            ("tun_ifname", base.tun_ifname.as_deref().unwrap_or("")),
            ("local_ipv4", base.local_ipv4.as_deref().unwrap_or("")),
        ],
    );
    out.push_str("} 1\n");

    // session_state: one series per state, 1 for the live one.
    out.push_str("# HELP openprotect_session_state Current session state (one series per state).\n");
    out.push_str("# TYPE openprotect_session_state gauge\n");
    for (label, this) in [
        ("connecting", SessionState::Connecting),
        ("connected", SessionState::Connected),
        ("reconnecting", SessionState::Reconnecting),
    ] {
        let v = if base.state == this { 1 } else { 0 };
        out.push_str("openprotect_session_state{");
        write_labels(&mut out, &[("instance", instance), ("state", label)]);
        out.push_str(&format!("}} {v}\n"));
    }

    // started_at_unix: immune to NTP steps.
    out.push_str(
        "# HELP openprotect_session_started_at_unix Unix timestamp when the session started.\n",
    );
    out.push_str("# TYPE openprotect_session_started_at_unix gauge\n");
    out.push_str("openprotect_session_started_at_unix{");
    write_labels(&mut out, &[("instance", instance)]);
    out.push_str(&format!("}} {}\n", base.started_at_unix));

    // uptime_seconds: derived from a stored Instant.
    out.push_str("# HELP openprotect_session_uptime_seconds Seconds since the session started.\n");
    out.push_str("# TYPE openprotect_session_uptime_seconds gauge\n");
    out.push_str("openprotect_session_uptime_seconds{");
    write_labels(&mut out, &[("instance", instance)]);
    out.push_str(&format!("}} {uptime}\n"));

    // routes: count of split-tunnel routes installed.
    out.push_str("# HELP openprotect_session_routes Number of split-tunnel routes installed.\n");
    out.push_str("# TYPE openprotect_session_routes gauge\n");
    out.push_str("openprotect_session_routes{");
    write_labels(&mut out, &[("instance", instance)]);
    out.push_str(&format!("}} {}\n", base.routes.len()));

    // Counters.
    let reconnects = state.counters.reconnect_attempts.load(Ordering::Relaxed);
    let restarts = state.counters.tunnel_restarts.load(Ordering::Relaxed);

    out.push_str(
        "# HELP openprotect_reconnect_attempts_total Reconnect attempts driven by the app-level state machine.\n",
    );
    out.push_str("# TYPE openprotect_reconnect_attempts_total counter\n");
    out.push_str("openprotect_reconnect_attempts_total{");
    write_labels(&mut out, &[("instance", instance)]);
    out.push_str(&format!("}} {reconnects}\n"));

    out.push_str(
        "# HELP openprotect_tunnel_restarts_total Successful tunnel re-establishments (post-backoff).\n",
    );
    out.push_str("# TYPE openprotect_tunnel_restarts_total counter\n");
    out.push_str("openprotect_tunnel_restarts_total{");
    write_labels(&mut out, &[("instance", instance)]);
    out.push_str(&format!("}} {restarts}\n"));

    out
}

/// Write a `{name="value",name="value",...}` label block (without the
/// surrounding braces) into `out`. Values are escaped per the
/// Prometheus text format: `\`, `"`, and newline get backslash-
/// escaped; everything else goes through verbatim.
fn write_labels(out: &mut String, labels: &[(&str, &str)]) {
    let mut first = true;
    for (name, value) in labels {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(name);
        out.push_str("=\"");
        escape_label_value(value, out);
        out.push('"');
    }
}

fn escape_label_value(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
}

/// Spawn the metrics listener on `addr`. Returns a `JoinHandle` so
/// the caller can `abort()` it on tunnel teardown. The first
/// `bind()` that fails is surfaced as an error — we'd rather tell
/// the operator "port 9100 is in use" than silently not listen.
pub async fn spawn_metrics_server(
    addr: SocketAddr,
    state: MetricsState,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics listener at {addr}"))?;
    tracing::info!("metrics endpoint listening on http://{addr}/metrics");

    Ok(tokio::spawn(async move {
        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("metrics accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_scrape(&mut stream, state, peer).await {
                    tracing::debug!("metrics client {peer} error: {e}");
                }
            });
        }
    }))
}

/// Read exactly one HTTP request from the client, answer based on
/// the request-line path, close the connection. No Keep-Alive.
async fn handle_scrape(
    stream: &mut tokio::net::TcpStream,
    state: MetricsState,
    _peer: SocketAddr,
) -> Result<()> {
    let mut buf = [0u8; 512];
    // We only need the request-line — just read whatever the client
    // sends in one shot; a Prometheus scrape will fit in well under
    // 512 bytes.
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
        .await
        .context("request read timeout")?
        .context("request read error")?;

    // Parse the first line: `GET /path HTTP/1.1`.
    let head = &buf[..n];
    let first_line = head.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let first_line = std::str::from_utf8(first_line).unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let body = match path {
        "/metrics" => render_scrape(&state, Instant::now()),
        "/" => {
            // Friendly landing page — makes `curl http://host:9100/`
            // not look broken.
            "<html><body><a href=\"/metrics\">metrics</a></body></html>\n".to_string()
        }
        _ => {
            let body = format!("404 Not Found: {path}\n");
            let response = format!(
                "HTTP/1.1 404 Not Found\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    };

    let content_type = if path == "/metrics" {
        "text/plain; version=0.0.4; charset=utf-8"
    } else {
        "text/html; charset=utf-8"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(instance: &str) -> StateSnapshotBase {
        StateSnapshotBase {
            instance: instance.to_string(),
            portal: "vpn.example.com".to_string(),
            gateway: "gw.example.com".to_string(),
            user: "alice@example.com".to_string(),
            reported_os: "win".to_string(),
            routes: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
            started_at_unix: 1_700_000_000,
            tun_ifname: Some("tun0".into()),
            local_ipv4: Some("10.0.0.42".into()),
            state: SessionState::Connected,
        }
    }

    fn state(base: StateSnapshotBase) -> MetricsState {
        MetricsState {
            base: Arc::new(RwLock::new(base)),
            started_at: Instant::now(),
            counters: MetricsCounters::new(),
        }
    }

    #[test]
    fn render_includes_info_block_with_labels() {
        let s = state(base("work"));
        let out = render_scrape(&s, Instant::now());
        assert!(out.contains("openprotect_session_info{"));
        assert!(out.contains("instance=\"work\""));
        assert!(out.contains("portal=\"vpn.example.com\""));
        assert!(out.contains("user=\"alice@example.com\""));
        assert!(out.contains("tun_ifname=\"tun0\""));
        // Constant gauge value.
        assert!(out.contains("} 1\n"));
    }

    #[test]
    fn render_emits_one_state_series_per_value() {
        let s = state(base("work"));
        let out = render_scrape(&s, Instant::now());
        // Exactly one connected series.
        assert!(out.contains(r#"openprotect_session_state{instance="work",state="connected"} 1"#));
        assert!(out.contains(r#"openprotect_session_state{instance="work",state="connecting"} 0"#));
        assert!(out.contains(r#"openprotect_session_state{instance="work",state="reconnecting"} 0"#));
    }

    #[test]
    fn render_uptime_is_deterministic_from_instant() {
        let mut base = base("work");
        base.state = SessionState::Connected;
        let started = Instant::now();
        let s = MetricsState {
            base: Arc::new(RwLock::new(base)),
            started_at: started,
            counters: MetricsCounters::new(),
        };
        // `now == started_at` → 0 uptime.
        let out = render_scrape(&s, started);
        assert!(out.contains("openprotect_session_uptime_seconds{instance=\"work\"} 0\n"));
        // `now` in the past → saturates at 0, no underflow panic.
        let past = started
            .checked_sub(std::time::Duration::from_secs(5))
            .unwrap_or(started);
        let out = render_scrape(&s, past);
        assert!(out.contains("openprotect_session_uptime_seconds{instance=\"work\"} 0\n"));
    }

    #[test]
    fn render_counters_reflect_atomic_state() {
        let s = state(base("work"));
        s.counters.reconnect_attempts.store(7, Ordering::Relaxed);
        s.counters.tunnel_restarts.store(3, Ordering::Relaxed);
        let out = render_scrape(&s, Instant::now());
        assert!(out.contains("openprotect_reconnect_attempts_total{instance=\"work\"} 7\n"));
        assert!(out.contains("openprotect_tunnel_restarts_total{instance=\"work\"} 3\n"));
    }

    #[test]
    fn render_routes_count_matches_vec_len() {
        let mut b = base("work");
        b.routes = vec![];
        let out = render_scrape(&state(b), Instant::now());
        assert!(out.contains("openprotect_session_routes{instance=\"work\"} 0\n"));
        let mut b = base("work");
        b.routes = vec!["a".into(), "b".into(), "c".into()];
        let out = render_scrape(&state(b), Instant::now());
        assert!(out.contains("openprotect_session_routes{instance=\"work\"} 3\n"));
    }

    #[test]
    fn label_values_escape_quotes_and_backslashes() {
        let mut b = base("work");
        b.user = r#"al"ice\example"#.to_string();
        let out = render_scrape(&state(b), Instant::now());
        assert!(
            out.contains(r#"user="al\"ice\\example""#),
            "expected escaped quotes + backslashes, got: {out}"
        );
    }

    #[test]
    fn label_values_escape_newlines() {
        let mut b = base("work");
        b.portal = "vpn\nattack".to_string();
        let out = render_scrape(&state(b), Instant::now());
        assert!(out.contains(r#"portal="vpn\nattack""#));
    }

    #[test]
    fn render_output_ends_with_newline_for_prometheus_parser() {
        let s = state(base("work"));
        let out = render_scrape(&s, Instant::now());
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn render_emits_help_and_type_lines_for_every_metric() {
        let s = state(base("work"));
        let out = render_scrape(&s, Instant::now());
        for metric in [
            "openprotect_session_info",
            "openprotect_session_state",
            "openprotect_session_started_at_unix",
            "openprotect_session_uptime_seconds",
            "openprotect_session_routes",
            "openprotect_reconnect_attempts_total",
            "openprotect_tunnel_restarts_total",
        ] {
            assert!(
                out.contains(&format!("# HELP {metric} ")),
                "missing # HELP for {metric}"
            );
            assert!(
                out.contains(&format!("# TYPE {metric} ")),
                "missing # TYPE for {metric}"
            );
        }
    }

    #[tokio::test]
    async fn http_endpoint_serves_metrics_on_localhost() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // Bind first to discover the ephemeral port, then pass
        // into spawn_metrics_server by re-binding on the same
        // address. Simpler: bind an ephemeral-port listener
        // manually and hand-call handle_scrape once.
        let listener = TcpListener::bind(addr).await.unwrap();
        let actual = listener.local_addr().unwrap();
        let s = state(base("work"));
        let server_state = s.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let peer = stream.peer_addr().unwrap();
            let _ = handle_scrape(&mut stream, server_state, peer).await;
        });

        let mut client = tokio::net::TcpStream::connect(actual).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let body = String::from_utf8_lossy(&resp);
        assert!(body.starts_with("HTTP/1.1 200 OK\r\n"), "bad head: {body}");
        assert!(body.contains("openprotect_session_info{"));
        assert!(body.contains("instance=\"work\""));
        server.abort();
    }

    #[tokio::test]
    async fn http_endpoint_returns_404_for_unknown_path() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let actual = listener.local_addr().unwrap();
        let s = state(base("work"));
        let server_state = s.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let peer = stream.peer_addr().unwrap();
            let _ = handle_scrape(&mut stream, server_state, peer).await;
        });

        let mut client = tokio::net::TcpStream::connect(actual).await.unwrap();
        client
            .write_all(b"GET /wat HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let body = String::from_utf8_lossy(&resp);
        assert!(body.starts_with("HTTP/1.1 404 Not Found\r\n"));
        server.abort();
    }
}
