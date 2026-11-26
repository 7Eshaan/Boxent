//! Verification suite B12: egress through the host-side proxy, from inside real sandboxes. Runs
//! as root inside the Lima VM (`cargo xtask vm-test`) and needs the VM to reach example.com and
//! www.iana.org. Skipped anywhere else.

#![cfg(target_os = "linux")]

use std::time::Duration;

use boxent_core::{Engine, EngineConfig, ErrorCode, ExecSpec, Profile};
use boxent_driver_oci::DriverConfig;

fn enabled() -> bool {
    let on = std::env::var_os("BOXENT_VM_TESTS").is_some() && unsafe { libc::geteuid() } == 0;
    if !on {
        eprintln!("skipped: set BOXENT_VM_TESTS=1 and run as root (cargo xtask vm-test)");
    }
    on
}

fn profile(name: &str, allow: &[&str], ports: &[u16]) -> Profile {
    Profile {
        name: name.into(),
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        ports: ports.to_vec(),
    }
}

/// Names that resolve to non-public addresses, via the VM's /etc/hosts (the proxy resolves
/// names on the host side, so this is what it sees).
const HOSTS: &str = "10.11.12.13 private.boxent.test\n127.0.0.1 loopback.boxent.test\n169.254.169.254 metadata.boxent.test\n";

struct HostsGuard(String);

impl HostsGuard {
    fn install() -> Self {
        let original = std::fs::read_to_string("/etc/hosts").unwrap();
        std::fs::write("/etc/hosts", format!("{original}{HOSTS}")).unwrap();
        Self(original)
    }
}

impl Drop for HostsGuard {
    fn drop(&mut self) {
        let _ = std::fs::write("/etc/hosts", &self.0);
    }
}

async fn engine() -> Engine {
    let mut driver = DriverConfig::default();
    if let Ok(agent) = std::env::var("BOXENT_AGENT_BIN") {
        driver.agent_bin = agent.into();
    }
    Engine::start(EngineConfig {
        driver,
        pool_size: 2,
        profiles: vec![
            profile("web", &["example.com", "*.example.com"], &[443, 80]),
            profile(
                "private",
                &[
                    "private.boxent.test",
                    "loopback.boxent.test",
                    "metadata.boxent.test",
                ],
                &[443, 80],
            ),
        ],
        ..EngineConfig::default()
    })
    .await
    .expect("engine start")
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

async fn run(e: &Engine, id: &str, cmd: &str) -> Out {
    let r = e
        .exec(
            id,
            ExecSpec::Bash(cmd.into()),
            Some(Duration::from_secs(60)),
        )
        .await
        .unwrap_or_else(|err| panic!("{cmd}: {err}"));
    Out {
        code: r.exit_code,
        stdout: r.stdout.trim().to_owned(),
        stderr: r.stderr,
    }
}

/// HTTP status of a GET through the sandbox's proxy, or the curl error.
async fn status(e: &Engine, id: &str, url: &str) -> String {
    let o = run(
        e,
        id,
        &format!("curl -sS -m 20 -o /dev/null -w '%{{http_code}}' {url}"),
    )
    .await;
    if o.code == 0 {
        o.stdout
    } else {
        format!("curl error: {}", o.stderr.trim())
    }
}

const TLS_PROBE: &str = r#"
import socket, ssl, sys
host, sni = sys.argv[1], sys.argv[2]
s = socket.create_connection(("127.0.0.1", 3128), timeout=20)
s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
reply = s.recv(4096).decode()
assert reply.startswith("HTTP/1.1 200"), reply
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    ctx.wrap_socket(s, server_hostname=sni).close()
    print("handshake ok")
except (ssl.SSLError, OSError) as e:
    print(f"handshake failed: {e.__class__.__name__}")
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b12_egress_follows_the_sandbox_profile() {
    if !enabled() {
        return;
    }
    let _hosts = HostsGuard::install();
    let e = engine().await;
    let web = e.claim_with("web").await.unwrap();
    let none = e.claim().await.unwrap(); // the built-in default profile: nothing allowed

    // Allowed: HTTPS (CONNECT) and plain HTTP, from curl and from Python's standard library,
    // through the proxy variables every command gets.
    assert_eq!(status(&e, &web, "https://example.com/").await, "200");
    assert_eq!(status(&e, &web, "http://example.com/").await, "200");
    assert_eq!(status(&e, &web, "https://www.example.com/").await, "200");
    let py = run(&e, &web, "python3 -c \"import urllib.request; print(urllib.request.urlopen('https://example.com', timeout=20).status)\"").await;
    assert_eq!(py.stdout, "200", "{}", py.stderr);

    // The same URL from a sandbox on the default profile is refused, with a message that says why.
    assert!(
        status(&e, &none, "https://example.com/")
            .await
            .contains("403")
    );
    let body = run(&e, &none, "curl -s -m 20 http://example.com/")
        .await
        .stdout;
    assert!(
        body.contains("denied") && body.contains("profile 'default'"),
        "{body}"
    );

    // Refused: other hosts, IP literals, other ports.
    for url in [
        "https://www.iana.org/",
        "https://1.1.1.1/",
        "https://example.com:8443/",
        "https://example.com.evil.test/",
    ] {
        let s = status(&e, &web, url).await;
        assert!(s.contains("403"), "{url}: {s}");
    }
    let body = run(&e, &web, "curl -s -m 20 http://1.1.1.1/").await.stdout;
    assert!(body.contains("IP addresses are not allowed"), "{body}");

    // Allowed names that resolve to private, loopback or metadata addresses are refused.
    let private = e.claim_with("private").await.unwrap();
    for host in [
        "private.boxent.test",
        "loopback.boxent.test",
        "metadata.boxent.test",
    ] {
        let body = run(&e, &private, &format!("curl -s -m 20 http://{host}/"))
            .await
            .stdout;
        assert!(body.contains("non-public address"), "{host}: {body}");
    }

    // A tunnel opened for an allowed host cannot carry TLS for another one.
    e.write_file(&web, "/tmp/tls.py", TLS_PROBE.as_bytes().to_vec(), None)
        .await
        .unwrap();
    let ok = run(&e, &web, "python3 /tmp/tls.py example.com example.com").await;
    assert_eq!(ok.stdout, "handshake ok", "{}", ok.stderr);
    let bad = run(&e, &web, "python3 /tmp/tls.py example.com www.iana.org").await;
    assert!(
        bad.stdout.starts_with("handshake failed"),
        "{} {}",
        bad.stdout,
        bad.stderr
    );

    // Going around the proxy goes nowhere: no route, no resolver.
    let direct = run(
        &e,
        &web,
        "curl -sS -m 10 --noproxy '*' https://example.com/",
    )
    .await;
    assert_ne!(direct.code, 0);
    assert_ne!(run(&e, &web, "getent hosts example.com").await.code, 0);

    // Profiles are per sandbox and fixed at claim; unknown names list what exists.
    let err = e.claim_with("everything").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(
        err.message.contains("default") && err.message.contains("web"),
        "{err}"
    );
    assert_eq!(e.info(&web).unwrap().profile.name, "web");
    assert_eq!(e.info(&none).unwrap().profile.name, "default");

    e.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_connections_end_with_the_sandbox() {
    if !enabled() {
        return;
    }
    let e = engine().await;
    let id = e.claim_with("web").await.unwrap();
    // A long download in the background, then the sandbox is destroyed under it.
    run(
        &e,
        &id,
        "curl -s --limit-rate 1k -o /dev/null https://example.com/ >/dev/null 2>&1 &",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    e.destroy(&id).await.unwrap();
    // The engine keeps running; a new sandbox still has working egress.
    let again = e.claim_with("web").await.unwrap();
    assert_eq!(status(&e, &again, "https://example.com/").await, "200");
    e.shutdown().await;
}
