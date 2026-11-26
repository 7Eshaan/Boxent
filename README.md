# Boxent

A local, self-hosted sandbox engine for AI coding agents, served as an MCP server. Each sandbox is a
disposable, isolated Linux environment with instant snapshot and restore of its workspace.

Status: milestones M0 to M4 are done: development environment, in-sandbox agent and protocol,
isolated sandboxes with crun, the engine with its warm pool and reaper, and the MCP server.
Snapshots arrive in M5, egress in M6, Streamable HTTP in M7.

## Use it from an MCP client

`boxent mcp` is a stdio MCP server. On macOS it relays to the daemon in the Lima VM and starts the
VM if it is stopped (about 6 seconds).

```bash
cargo install --path crates/boxent-cli --locked     # installs ~/.cargo/bin/boxent
```

Then register it with your client, for example in a project's `.mcp.json`:

```json
{ "mcpServers": { "boxent": { "command": "/Users/you/.cargo/bin/boxent", "args": ["mcp"] } } }
```

Tools: `run_bash`, `run_python`, `write_file`, `read_file`, `create_sandbox`, `destroy_sandbox`.
Calls without a `sandbox_id` share one sandbox per session, created on first use and destroyed 30
seconds after the session ends.

## Layout

| Path | What it is |
| --- | --- |
| `crates/boxent-cli` | The `boxent` binary: `doctor`, `vm`, `image`, `sandbox`, and later `daemon` and `mcp` |
| `crates/boxent-core` | Engine: warm pool, claim, exec, file ops, idle and TTL reaping, crash recovery (CoW storage in M5) |
| `crates/boxent-driver-oci` | Isolation driver: user and network namespaces, idmapped mounts, cgroups, seccomp, crun |
| `crates/boxent-egress` | Host-side egress proxy (M6) |
| `crates/boxent-agent` | PID 1 agent inside every sandbox: reaping, commands in per-command cgroups, file access as the sandbox user |
| `crates/boxent-proto` | Engine to agent wire protocol: length-prefixed CBOR frames, head/tail output capture |
| `crates/boxent-mcp` | MCP tools with strict schemas, session routing, the daemon's socket server |
| `deploy/lima/boxent.yaml` | Lima template for the VM that hosts the engine on macOS |
| `deploy/systemd/boxentd.service` | systemd unit for the daemon |
| `tests/e2e` | Black-box tests through `boxent mcp` with the official Python MCP SDK |
| `images/base/build.sh` | Recipe for the base root filesystem (Ubuntu 26.04, bash, python3, git, curl) |
| `xtask` | Developer tasks: `cargo xtask build-linux`, `vm-deploy`, `vm-test`, `e2e`, `ci` |

## Development on macOS (Apple Silicon)

The engine needs a Linux kernel, so on macOS it runs in a Lima VM with no host mounts.

```bash
brew install lima zig
cargo install --locked cargo-zigbuild
cargo run -p boxent-cli -- vm up        # first run downloads Ubuntu and formats the Btrfs data disk
cargo xtask vm-deploy                   # cross-builds arm64 Linux binaries, installs them, (re)starts boxentd
cargo run -p boxent-cli -- doctor       # checks the Mac, then the kernel features inside the VM
```

Inside the VM, as root, `boxent image build` creates the base image (about 90 seconds, once) and
`boxent sandbox run 'uname -a; id'` creates a sandbox, runs one command and destroys it.

`cargo xtask ci` runs formatting, clippy for macOS and Linux targets, and the unit tests.
`cargo xtask vm-test [FILTER]` deploys the binaries and runs the kernel-level tests as root inside
the VM: the agent tests, isolation suite B against real sandboxes, and lifecycle suite C plus the
latency benchmark against the engine, and MCP session tests, each followed by a leak check.
`cargo xtask e2e` runs the black-box MCP suite from the Mac, through the relay and Lima's socket
forwarding, using a local `.venv` with the official Python MCP SDK.

## Development on Linux

Needs kernel 6.8+, cgroup v2, crun, btrfs-progs, mmdebstrap, and a Btrfs filesystem with simple
quotas mounted at `/var/lib/boxent`. `sudo boxent doctor` checks all of these and prints a fix for
anything missing.
