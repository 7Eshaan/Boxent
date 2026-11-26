//! MCP sessions against a real engine, inside the VM (`cargo xtask vm-test`): session routing,
//! cleanup when a session ends (C6), and latency through the MCP layer without the Mac relay
//! (A1-A3). Skipped anywhere else.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use boxent_core::{Engine, EngineConfig, ErrorCode};
use boxent_driver_oci::DriverConfig;
use boxent_mcp::serve_connection;
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};

fn enabled() -> bool {
    let on = std::env::var_os("BOXENT_VM_TESTS").is_some() && unsafe { libc::geteuid() } == 0;
    if !on {
        eprintln!("skipped: set BOXENT_VM_TESTS=1 and run as root (cargo xtask vm-test)");
    }
    on
}

async fn engine() -> Engine {
    let mut driver = DriverConfig::default();
    if let Ok(agent) = std::env::var("BOXENT_AGENT_BIN") {
        driver.agent_bin = agent.into();
    }
    Engine::start(EngineConfig {
        driver,
        pool_size: 4,
        ..EngineConfig::default()
    })
    .await
    .expect("engine start")
}

type Client = RunningService<RoleClient, ()>;

async fn connect(engine: &Engine, grace: Duration) -> Client {
    let (server, client) = tokio::net::UnixStream::pair().unwrap();
    tokio::spawn(serve_connection(engine.clone(), server, grace));
    ().serve(client).await.expect("MCP handshake")
}

async fn call(c: &Client, tool: &'static str, args: Value) -> Result<Value, String> {
    let r = c
        .call_tool(
            CallToolRequestParams::new(tool).with_arguments(args.as_object().unwrap().clone()),
        )
        .await
        .expect("tools/call");
    if r.is_error == Some(true) {
        return Err(format!("{:?}", r.content));
    }
    Ok(r.structured_content.expect("structured content"))
}

async fn wait_for_warm(e: &Engine) {
    let t = Instant::now();
    while e.stats().warm < e.config().pool_size {
        assert!(t.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c6_closing_a_session_destroys_its_sandboxes_after_the_grace_period() {
    if !enabled() {
        return;
    }
    let e = engine().await;
    // A sandbox owned by another session: using it here must not tie its life to this session.
    let other = connect(&e, Duration::from_secs(60)).await;
    let foreign = call(&other, "create_sandbox", json!({})).await.unwrap()["sandbox_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let c = connect(&e, Duration::from_secs(1)).await;
    let default = call(&c, "run_bash", json!({"command": "echo hi"}))
        .await
        .unwrap()["sandbox_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let extra = call(&c, "create_sandbox", json!({})).await.unwrap()["sandbox_id"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        &c,
        "run_bash",
        json!({"command": "true", "sandbox_id": foreign}),
    )
    .await
    .unwrap();
    c.cancel().await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        e.info(&default).is_ok(),
        "reaped before the grace period ended"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    for id in [&default, &extra] {
        assert_eq!(
            e.info(id).unwrap_err().code,
            ErrorCode::SandboxReaped,
            "{id} survived"
        );
    }
    assert!(
        e.info(&foreign).is_ok(),
        "another session's sandbox was destroyed"
    );
    other.cancel().await.unwrap();
    e.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reaped_default_sandbox_is_reported_once_then_replaced() {
    if !enabled() {
        return;
    }
    let e = engine().await;
    let c = connect(&e, Duration::from_secs(1)).await;
    let first = call(&c, "run_bash", json!({"command": "true"}))
        .await
        .unwrap()["sandbox_id"]
        .as_str()
        .unwrap()
        .to_owned();
    e.destroy(&first).await.unwrap(); // as if the reaper had taken it
    let err = call(&c, "run_bash", json!({"command": "true"}))
        .await
        .unwrap_err();
    assert!(err.contains("sandbox_reaped"), "{err}");
    let second = call(&c, "run_bash", json!({"command": "true"}))
        .await
        .unwrap();
    assert_ne!(second["sandbox_id"].as_str().unwrap(), first);
    c.cancel().await.unwrap();
    e.shutdown().await;
}

fn pct(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

fn report(name: &str, mut s: Vec<Duration>) -> Duration {
    s.sort();
    eprintln!(
        "{name}: n={} p50 {:?} p95 {:?} p99 {:?} max {:?}",
        s.len(),
        pct(&s, 50),
        pct(&s, 95),
        pct(&s, 99),
        s[s.len() - 1]
    );
    pct(&s, 99)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a1_to_a3_latency_through_the_mcp_layer() {
    if !enabled() {
        return;
    }
    let e = engine().await;
    wait_for_warm(&e).await;
    let mut a1 = Vec::new();
    for _ in 0..300 {
        let c = connect(&e, Duration::from_secs(1)).await;
        let t = Instant::now();
        let out = call(&c, "run_bash", json!({"command": "echo ok"}))
            .await
            .unwrap();
        a1.push(t.elapsed());
        assert_eq!(out["stdout"], "ok\n");
        call(&c, "destroy_sandbox", json!({})).await.unwrap();
        c.cancel().await.unwrap();
    }
    assert!(
        report("A1 claim + run_bash(echo) via MCP, in the VM", a1) < Duration::from_millis(200)
    );

    let c = connect(&e, Duration::from_secs(1)).await;
    call(&c, "run_bash", json!({"command": "true"}))
        .await
        .unwrap();
    let mut a2 = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        call(&c, "run_bash", json!({"command": "echo ok"}))
            .await
            .unwrap();
        a2.push(t.elapsed());
    }
    call(&c, "destroy_sandbox", json!({})).await.unwrap();
    c.cancel().await.unwrap();
    assert!(
        report("A2 run_bash(echo) in an active sandbox via MCP", a2) < Duration::from_millis(50)
    );

    let mut a3 = Vec::new();
    for _ in 0..100 {
        let c = connect(&e, Duration::from_secs(1)).await;
        let t = Instant::now();
        let out = call(&c, "run_python", json!({"code": "print(1)"}))
            .await
            .unwrap();
        a3.push(t.elapsed());
        assert_eq!(out["stdout"], "1\n");
        call(&c, "destroy_sandbox", json!({})).await.unwrap();
        c.cancel().await.unwrap();
    }
    assert!(report("A3 claim + run_python(print) via MCP", a3) < Duration::from_millis(200));
    e.shutdown().await;
}
