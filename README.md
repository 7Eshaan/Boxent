# Boxent

A local, self-hosted sandbox engine for AI coding agents, served as an MCP server. Each sandbox is a
disposable, isolated Linux environment with instant snapshot and restore of its workspace.

Status: milestones M0 to M3 are done: development environment, in-sandbox agent and protocol,
isolated sandboxes with crun, and the engine with its warm pool and reaper. The MCP server arrives in
M4, snapshots in M5, egress in M6.

## Layout

| Path | What it is |
| --- | --- |
| `crates/boxent-cli` | The `boxent` binary: `doctor`, `vm`, `image`, `sandbox`, and later `daemon` and `mcp` |
| `crates/boxent-core` | Engine: warm pool, claim, exec, file ops, idle and TTL reaping, crash recovery (CoW storage in M5) |
| `crates/boxent-driver-oci` | Isolation driver: user and network namespaces, idmapped mounts, cgroups, seccomp, crun |
| `crates/boxent-egress` | Host-side egress proxy (M6) |
| `crates/boxent-agent` | PID 1 agent inside every sandbox: reaping, commands in per-command cgroups, file access as the sandbox user |
| `crates/boxent-proto` | Engine to agent wire protocol: length-prefixed CBOR frames, head/tail output capture |
| `crates/boxent-mcp` | MCP tools and transports (M4) |
| `deploy/lima/boxent.yaml` | Lima template for the VM that hosts the engine on macOS |
| `images/base/build.sh` | Recipe for the base root filesystem (Ubuntu 26.04, bash, python3, git, curl) |
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

Inside the VM, as root, `boxent image build` creates the base image (about 90 seconds, once) and
`boxent sandbox run 'uname -a; id'` creates a sandbox, runs one command and destroys it.

`cargo xtask ci` runs formatting, clippy for macOS and Linux targets, and the unit tests.
`cargo xtask vm-test [FILTER]` deploys the binaries and runs the kernel-level tests as root inside
the VM: the agent tests, isolation suite B against real sandboxes, and lifecycle suite C plus the
latency benchmark against the engine, each test followed by a leak check.

## Development on Linux

Needs kernel 6.8+, cgroup v2, crun, btrfs-progs, mmdebstrap, and a Btrfs filesystem with simple
quotas mounted at `/var/lib/boxent`. `sudo boxent doctor` checks all of these and prints a fix for
anything missing.
