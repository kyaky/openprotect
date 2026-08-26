//! End-to-end check of the split-route conflict path against a real
//! kernel routing table.
//!
//! The unit tests drive a `CommandRunner` mock, which proves the argv
//! we emit but not that iproute2 accepts it. This does the other half:
//! it builds a Docker-style bridge that owns `172.20.0.0/16`, runs the
//! real `apply` + `revert`, and asserts the bridge's route comes back
//! byte-for-byte.
//!
//! It needs `CAP_NET_ADMIN`, which an unprivileged user namespace
//! provides — no root, no effect on the host's routing table:
//!
//! ```text
//! cargo build -p gp-route --example netns_smoke
//! unshare --user --map-root-user --net -- \
//!     target/debug/examples/netns_smoke
//! ```
//!
//! Not wired into `cargo test`: it would need the namespace, and CI
//! runners cannot be relied on to allow unprivileged user namespaces.

use gp_route::{apply, revert, RouteConflictPolicy, TunConfig};
use std::net::Ipv4Addr;
use std::process::Command;

fn sh(cmd: &str) {
    let out = Command::new("sh").arg("-c").arg(cmd).output().unwrap();
    if !out.status.success() {
        eprintln!(
            "setup `{cmd}` failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn show(cidr: &str) -> String {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "exact", cidr])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn main() {
    sh("ip link add tun0 type dummy && ip link set tun0 up");
    sh("ip link add br-81f0638ae4fb type bridge");
    sh("ip addr add 172.20.0.1/16 dev br-81f0638ae4fb");
    sh("ip link set br-81f0638ae4fb up");
    sh("ip link add eth0 type dummy && ip addr add 192.168.88.167/24 dev eth0 && ip link set eth0 up");
    sh("ip route add default via 192.168.88.1 dev eth0 metric 100");

    let before_docker = show("172.20.0.0/16");
    let before_default = show("0.0.0.0/0");
    println!("BEFORE docker : {before_docker}");
    println!("BEFORE default: {before_default}");
    assert!(before_docker.contains("br-81f0638ae4fb"));

    let config = TunConfig {
        ifname: "tun0".into(),
        ipv4: Some(Ipv4Addr::new(172, 26, 10, 113)),
        mtu: Some(1422),
        gateway_exclude: None,
        // 172.20.0.0/16 collides with the bridge; 0.0.0.0/0 does not
        // collide with the metric-100 default; 10.0.0.0/8 is free.
        routes: vec![
            "10.0.0.0/8".into(),
            "172.20.0.0/16".into(),
            "0.0.0.0/0".into(),
        ],
        route_conflict: RouteConflictPolicy::TakeOver,
    };

    let state = apply(&config).expect("apply must succeed despite the docker conflict");
    println!("AFTER  docker : {}", show("172.20.0.0/16"));
    println!(
        "displaced     : {:?}",
        state.displaced_cidrs().collect::<Vec<_>>()
    );
    assert!(
        show("172.20.0.0/16").contains("tun0"),
        "tunnel must own the prefix"
    );
    assert_eq!(
        state.displaced_cidrs().collect::<Vec<_>>(),
        ["172.20.0.0/16"]
    );

    let errs = revert(&state);
    let after_docker = show("172.20.0.0/16");
    let after_default = show("0.0.0.0/0");
    println!("REVERT errors : {errs:?}");
    println!("AFTER  docker : {after_docker}");
    println!("AFTER  default: {after_default}");
    assert!(errs.is_empty(), "revert reported errors: {errs:?}");
    assert_eq!(
        after_docker, before_docker,
        "docker route must be restored byte-for-byte"
    );
    assert_eq!(
        after_default, before_default,
        "default route must be untouched"
    );
    println!("\nOK: conflict taken over, restored exactly, uncontested default left alone");
}
