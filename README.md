# Boxent

A local, self-hosted sandbox engine for AI coding agents, served as an MCP server. Each sandbox is a
disposable, isolated Linux environment with instant snapshot and restore of its workspace.

Status: milestones M0 (development environment) and M1 (in-sandbox agent and its protocol) are done.
Sandboxes, snapshots and the MCP tools arrive in M2 to M7.

## Layout

| Path | What it is |
| --- | --- |
| `crates/boxent-cli` | The `boxent` binary: `doctor`, `vm`, and later `daemon` and `mcp` |
| `crates/boxent-core` | Engine API, pool, lifecycle and reaper, CoW storage (M3, M5) |
| `crates/boxent-driver-oci` | crun-based isolation driver (M2) |
| `crates/boxent-egress` | Host-side egress proxy (M6) |
| `crates/boxent-agent` | PID 1 agent inside every sandbox: reaping, commands in per-command cgroups, file access as the sandbox user |
| `crates/boxent-proto` | Engine to agent wire protocol: length-prefixed CBOR frames, head/tail output capture |
| `crates/boxent-mcp` | MCP tools and transports (M4) |
| `deploy/lima/boxent.yaml` | Lima template for the VM that hosts the engine on macOS |
| `xtask` | Developer tasks: `cargo xtask build-linux`, `vm-deploy`, `vm-test`, `ci` |

## Development on macOS (Apple Silicon)

The engine needs a Linux kernel, so on macOS it runs in a Lima VM with no host mounts.

```bash
brew install lima zig
cargo install --locked cargo-zigbuild
cargo run -p boxent-cli -- vm up        # first run downloads Ubuntu and formats the Btrfs data disk
cargo xtask vm-deploy                   # cross-builds arm64 Linux binaries and installs them in the VM
cargo run -p boxent-cli -- doctor       # checks the Mac, then the kernel features inside the VM
```

`cargo xtask ci` runs formatting, clippy for macOS and Linux targets, and the unit tests.
`cargo xtask vm-test [FILTER]` runs the kernel-level tests as root inside the VM; they start the
agent as PID 1 of its own PID namespace and cgroup.

## Development on Linux

Needs kernel 6.8+, cgroup v2, crun, btrfs-progs, mmdebstrap, and a Btrfs filesystem with simple
quotas mounted at `/var/lib/boxent`. `sudo boxent doctor` checks all of these and prints a fix for
anything missing.
