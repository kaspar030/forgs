//! Dependency guard: `forgs-client` runs on the fleet agent (armv7-musl), so
//! its normal dependency graph must hold no HTTP server framework, no
//! storage, no C crypto and no runtime features a client does not need.
//!
//! Shells out to `cargo tree`; skipped (not failed) when cargo is not usable,
//! e.g. an offline or vendored build.

use std::process::Command;

/// Crates whose presence means a server, storage or a C toolchain crept in.
const FORBIDDEN: &[&str] = &[
    "axum",
    "axum-core",
    "tower-http",
    "sqlx",
    "sqlx-core",
    "sqlx-sqlite",
    "libsqlite3-sys",
    "forgs-store",
    "aws-lc-rs",
    "aws-lc-sys",
    "openssl-sys",
    "native-tls",
];

fn cargo_tree(args: &[&str]) -> Option<(bool, String)> {
    let output = Command::new(env!("CARGO"))
        .arg("tree")
        .args(["-p", "forgs-client", "--offline"])
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    Some((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

#[test]
fn no_forbidden_crates_in_the_normal_graph() {
    for name in FORBIDDEN {
        let Some((ok, stdout)) = cargo_tree(&["--edges", "normal,build", "-i", name]) else {
            eprintln!("skipping: `cargo tree` could not be run");
            return;
        };
        // `cargo tree -i` fails when the package is absent from the graph —
        // the outcome we want.
        assert!(
            !ok || stdout.trim().is_empty(),
            "forgs-client depends on `{name}`, which must never reach the agent build:\n{stdout}"
        );
    }
}

#[test]
fn no_server_or_heavy_runtime_features() {
    let Some((ok, stdout)) = cargo_tree(&["--edges", "features,normal", "--prefix", "none"]) else {
        eprintln!("skipping: `cargo tree` could not be run");
        return;
    };
    if !ok {
        eprintln!("skipping: `cargo tree` failed");
        return;
    }
    for bad in [
        r#"hyper feature "server""#,
        r#"hyper-util feature "server""#,
        r#"tokio feature "rt-multi-thread""#,
        r#"tokio feature "process""#,
        r#"tokio feature "signal""#,
        r#"tokio feature "fs""#,
        r#"rustls feature "aws_lc_rs""#,
        r#"rustls feature "aws-lc-rs""#,
    ] {
        assert!(
            !stdout.contains(bad),
            "forgs-client's normal graph enables {bad}; the agent build must not"
        );
    }
    // Sanity: the check is looking at a real feature graph.
    assert!(stdout.contains(r#"hyper feature "client""#), "{stdout}");
}
