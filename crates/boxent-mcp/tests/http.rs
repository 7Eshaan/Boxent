//! Suite E6: MCP over Streamable HTTP against a real engine, inside the VM
//! (`cargo xtask vm-test`). A deliberately plain HTTP/1.1 client is used, so every header the
//! server sees is visible here. Skipped anywhere else.

#![cfg(target_os = "linux")]

use std::time::Duration;

use boxent_core::{Engine, EngineConfig};
use boxent_driver_oci::DriverConfig;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "test-token-0123456789abcdef0123456789abcdef";

fn enabled() -> bool {
    let on = std::env::var_os("BOXENT_VM_TESTS").is_some() && unsafe { libc::geteuid() } == 0;
    if !on {
        eprintln!("skipped: set BOXENT_VM_TESTS=1 and run as root (cargo xtask vm-test)");
    }
    on
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The JSON-RPC message with this id, from a JSON or SSE body.
    fn rpc(&self, id: u64) -> Value {
        let candidates: Vec<&str> = if self.body.trim_start().starts_with('{') {
            vec![self.body.as_str()]
        } else {
            self.body
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(str::trim)
                .collect()
        };
        candidates
            .iter()
            .filter_map(|c| serde_json::from_str::<Value>(c).ok())
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| panic!("no reply {id} in: {}", self.body))
    }
}

async fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_owned()
    };
    Resp {
        status,
        headers,
        body,
    }
}

fn dechunk(mut s: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = s.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 || rest.len() < n {
            break;
        }
        out.push_str(&rest[..n]);
        s = rest[n..].trim_start_matches("\r\n");
    }
    out
}

const AUTH: (&str, &str) = (
    "Authorization",
    "Bearer test-token-0123456789abcdef0123456789abcdef",
);

/// An MCP session over HTTP: initialize, then calls carrying the session id.
struct Session {
    port: u16,
    id: String,
    next: u64,
}

impl Session {
    async fn open(port: u16) -> Self {
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "e6", "version": "0"}}});
        let r = request(port, "POST", "/mcp", &[AUTH], &init.to_string()).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let id = r.header("mcp-session-id").expect("session id").to_owned();
        let s = Self { port, id, next: 2 };
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let r = s.post(&note).await;
        assert!(
            r.status == 202 || r.status == 200,
            "{} {}",
            r.status,
            r.body
        );
        s
    }

    async fn post(&self, msg: &Value) -> Resp {
        let headers = [
            AUTH,
            ("Mcp-Session-Id", self.id.as_str()),
            ("MCP-Protocol-Version", "2025-11-25"),
        ];
        request(self.port, "POST", "/mcp", &headers, &msg.to_string()).await
    }

    async fn tool(&mut self, name: &str, args: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let r = self
            .post(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}}))
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        let reply = r.rpc(id);
        assert!(reply["result"]["isError"] != true, "{reply}");
        reply["result"]["structuredContent"].clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e6_http_requires_a_token_refuses_browsers_and_keeps_sessions_apart() {
    if !enabled() {
        return;
    }
    let mut driver = DriverConfig::default();
    if let Ok(agent) = std::env::var("BOXENT_AGENT_BIN") {
        driver.agent_bin = agent.into();
    }
    let engine = Engine::start(EngineConfig {
        driver,
        pool_size: 2,
        ..EngineConfig::default()
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = CancellationToken::new();
    let server = tokio::spawn(boxent_mcp::serve_http_on(
        engine.clone(),
        listener,
        TOKEN.into(),
        stop.clone(),
    ));

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "e6", "version": "0"}}})
    .to_string();
    // No token, a wrong token: 401.
    assert_eq!(request(port, "POST", "/mcp", &[], &init).await.status, 401);
    let wrong = (
        "Authorization",
        "Bearer test-token-0123456789abcdef0123456789abcdeX",
    );
    assert_eq!(
        request(port, "POST", "/mcp", &[wrong], &init).await.status,
        401
    );
    // A browser page (any Origin) is refused even with the token.
    let r = request(
        port,
        "POST",
        "/mcp",
        &[AUTH, ("Origin", "http://evil.example")],
        &init,
    )
    .await;
    assert_eq!(r.status, 403, "{}", r.body);
    // A rebound DNS name (Host not loopback) is refused.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: evil.example:{port}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{init}",
        init.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    let status: u16 = raw.split(' ').nth(1).unwrap().parse().unwrap();
    assert!(
        (400..500).contains(&status),
        "rebinding Host accepted: {raw}"
    );

    // Two sessions: each has its own default sandbox, which persists within the session.
    let mut a = Session::open(port).await;
    let mut b = Session::open(port).await;
    let a1 = a
        .tool("run_bash", json!({"command": "echo a > who; cat who"}))
        .await;
    let b1 = b
        .tool(
            "run_bash",
            json!({"command": "cat who 2>/dev/null || echo none"}),
        )
        .await;
    assert_eq!(a1["stdout"], "a\n");
    assert_eq!(b1["stdout"], "none\n");
    assert_ne!(a1["sandbox_id"], b1["sandbox_id"]);
    let a2 = a.tool("run_bash", json!({"command": "cat who"})).await;
    assert_eq!(a2["sandbox_id"], a1["sandbox_id"]);
    assert_eq!(a2["stdout"], "a\n");
    // Snapshot and restore over HTTP too.
    let snap = a.tool("snapshot", json!({})).await;
    a.tool("run_bash", json!({"command": "rm who"})).await;
    a.tool("restore", json!({"snap_id": snap["snap_id"]})).await;
    assert_eq!(
        a.tool("run_bash", json!({"command": "cat who"})).await["stdout"],
        "a\n"
    );

    // Metrics: behind the same token.
    assert_eq!(request(port, "GET", "/metrics", &[], "").await.status, 401);
    let m = request(port, "GET", "/metrics", &[AUTH], "").await;
    assert_eq!(m.status, 200);
    for want in [
        "boxent_sandboxes{state=\"active\"} 2",
        "boxent_snapshots_total 1",
        "boxent_restores_total 1",
        "boxent_exec_duration_seconds_count",
    ] {
        assert!(m.body.contains(want), "missing {want} in\n{}", m.body);
    }

    stop.cancel();
    let _ = server.await;
    engine.shutdown().await;
}
