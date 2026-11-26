//! macOS host checks: Lima is installed, the Boxent VM exists with the safety settings we expect,
//! and the Linux checks pass inside it.

use std::process::{Command, Stdio};

use serde_json::Value;

use super::{Check, Section, Status, parse_lima_version};
use crate::vm::{self, INSTANCE};

const MIN_LIMA: (u32, u32, u32) = (2, 0, 0);
const GUEST_SOCKET: &str = "/run/boxent/boxent.sock";
const GUEST_BINARY: &str = "/usr/local/bin/boxent";

pub fn checks() -> Vec<Check> {
    let mut checks = vec![
        lima(),
        dev_tool("zig", &["version"]),
        dev_tool("cargo-zigbuild", &["--version"]),
    ];
    if checks[0].status == Status::Fail {
        return checks;
    }
    match vm::instance() {
        Ok(Some(inst)) => {
            checks.push(running(&inst));
            checks.push(daemon_socket(&inst));
            checks.extend(config_checks(inst.get("config").unwrap_or(&Value::Null)));
        }
        Ok(None) => checks.push(Check::fail(
            "vm",
            format!("no Lima instance named '{INSTANCE}'"),
            "boxent vm up",
        )),
        Err(e) => checks.push(Check::fail("vm", format!("{e:#}"), "check `limactl list`")),
    }
    checks
}

/// Runs `boxent doctor --json` inside the VM and returns its report.
pub fn vm_section() -> Section {
    let scope = "lima-vm".to_owned();
    let fail = |detail: String, fix: &str| Section {
        scope: scope.clone(),
        checks: vec![Check::fail("vm doctor", detail, fix)],
    };
    match vm::instance() {
        Ok(Some(inst)) if vm::str_field(&inst, "status") == "Running" => {}
        _ => return fail("the VM is not running".into(), "boxent vm up"),
    }
    let out = Command::new("limactl")
        .args([
            "shell",
            "--workdir",
            "/",
            INSTANCE,
            "sudo",
            GUEST_BINARY,
            "doctor",
            "--json",
        ])
        .stderr(Stdio::piped())
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return fail(
                format!("cannot run limactl shell: {e}"),
                "check `limactl list`",
            );
        }
    };
    match serde_json::from_slice::<Vec<Section>>(&out.stdout) {
        Ok(sections) => Section {
            scope,
            checks: sections.into_iter().flat_map(|s| s.checks).collect(),
        },
        Err(_) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let reason = stderr
                .lines()
                .last()
                .unwrap_or("no output")
                .trim()
                .to_owned();
            fail(
                format!("{GUEST_BINARY} did not produce a report ({reason})"),
                "cargo xtask vm-deploy",
            )
        }
    }
}

fn lima() -> Check {
    const NAME: &str = "lima";
    let out = Command::new("limactl").arg("--version").output();
    let Ok(out) = out else {
        return Check::fail(NAME, "limactl not found", "brew install lima");
    };
    let text = String::from_utf8_lossy(&out.stdout);
    match parse_lima_version(&text) {
        Some(v) if v >= MIN_LIMA => Check::pass(NAME, format!("{}.{}.{}", v.0, v.1, v.2)),
        Some(v) => Check::fail(
            NAME,
            format!("{}.{}.{} is older than 2.0", v.0, v.1, v.2),
            "brew upgrade lima",
        ),
        None => Check::warn(
            NAME,
            format!("unrecognised version: {}", text.trim()),
            "brew upgrade lima",
        ),
    }
}

/// Build tools only needed by people building Boxent from source.
fn dev_tool(binary: &str, args: &[&str]) -> Check {
    match Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .output()
    {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            Check::pass(binary, text.lines().next().unwrap_or("").trim().to_owned())
        }
        _ => Check::warn(
            binary,
            "not found (only needed to build Boxent from source)",
            if binary == "zig" {
                "brew install zig"
            } else {
                "cargo install --locked cargo-zigbuild"
            },
        ),
    }
}

fn running(inst: &Value) -> Check {
    let status = vm::str_field(inst, "status");
    if status == "Running" {
        Check::pass("vm", format!("'{INSTANCE}' is running"))
    } else {
        Check::fail("vm", format!("'{INSTANCE}' is {status}"), "boxent vm up")
    }
}

/// Safety-relevant settings of the instance's effective Lima config.
pub fn config_checks(config: &Value) -> Vec<Check> {
    let mut checks = Vec::new();

    let mounts = config
        .get("mounts")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    checks.push(if mounts == 0 {
        Check::pass("vm host mounts", "none: the VM cannot see any host files")
    } else {
        Check::fail(
            "vm host mounts",
            format!("{mounts} host directories are mounted into the VM"),
            "recreate the VM from the Boxent template: boxent vm delete --yes && boxent vm up",
        )
    });

    let forwards = config
        .get("portForwards")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_socket = forwards
        .iter()
        .any(|f| f.get("guestSocket").and_then(Value::as_str) == Some(GUEST_SOCKET));
    let ignores_rest = forwards.iter().any(|f| {
        f.get("ignore").and_then(Value::as_bool) == Some(true)
            && f.get("guestSocket").is_none()
            && f.get("guestIP").and_then(Value::as_str) == Some("0.0.0.0")
            && f.get("guestIPMustBeZero").and_then(Value::as_bool) == Some(false)
            && f.get("proto").and_then(Value::as_str) == Some("any")
    });
    checks.push(if has_socket && ignores_rest {
        Check::pass("vm port forwards", format!("only {GUEST_SOCKET}"))
    } else {
        Check::fail(
            "vm port forwards",
            "the engine socket is not forwarded, or other guest ports are forwarded too",
            "recreate the VM from the Boxent template",
        )
    });

    let loopback = config
        .get("networkOpts")
        .and_then(|n| n.get("hostLoopback"))
        .and_then(Value::as_bool);
    checks.push(if loopback == Some(false) {
        Check::pass(
            "vm host loopback",
            "blocked: the VM cannot reach services on the Mac's 127.0.0.1",
        )
    } else {
        Check::fail(
            "vm host loopback",
            "the VM can reach services listening on the Mac's 127.0.0.1",
            "recreate the VM from the Boxent template",
        )
    });

    let nested = config.get("nestedVirtualization").and_then(Value::as_bool) == Some(true);
    checks.push(if nested {
        Check::pass(
            "vm nested virtualization",
            "enabled (for the later microVM tier)",
        )
    } else {
        Check::warn(
            "vm nested virtualization",
            "disabled: only needed for the later Firecracker tier",
            "needs an M3 or newer Mac",
        )
    });
    checks
}

/// The daemon's socket, forwarded from the VM by Lima, accepts connections.
fn daemon_socket(inst: &Value) -> Check {
    const NAME: &str = "daemon socket";
    let dir = vm::str_field(inst, "dir");
    let path = std::path::Path::new(dir).join("sock").join("boxent.sock");
    match std::os::unix::net::UnixStream::connect(&path) {
        Ok(_) => Check::pass(NAME, format!("{} accepts connections", path.display())),
        Err(e) => Check::fail(
            NAME,
            format!("{}: {e}", path.display()),
            "cargo xtask vm-deploy (installs and starts boxentd in the VM)",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn safe_config_passes() {
        let cfg = json!({
            "mounts": [],
            "nestedVirtualization": true,
            "networkOpts": {"hostLoopback": false},
            "portForwards": [
                {"guestSocket": GUEST_SOCKET, "hostSocket": "/x/sock/boxent.sock"},
                {"guestIP": "0.0.0.0", "guestIPMustBeZero": false, "proto": "any", "ignore": true}
            ]
        });
        assert!(config_checks(&cfg).iter().all(|c| c.status == Status::Pass));
    }

    #[test]
    fn ignore_rule_limited_to_zero_address_fails() {
        let cfg = json!({
            "mounts": [],
            "networkOpts": {"hostLoopback": false},
            "portForwards": [
                {"guestSocket": GUEST_SOCKET},
                {"guestIP": "0.0.0.0", "guestIPMustBeZero": true, "proto": "any", "ignore": true}
            ]
        });
        assert_eq!(config_checks(&cfg)[1].status, Status::Fail);
    }

    #[test]
    fn mounted_home_fails() {
        let cfg = json!({"mounts": [{"location": "~"}], "portForwards": []});
        let checks = config_checks(&cfg);
        assert_eq!(checks[0].status, Status::Fail);
        assert_eq!(checks[1].status, Status::Fail);
        assert_eq!(checks[2].status, Status::Fail);
        assert_eq!(checks[3].status, Status::Warn);
    }
}
