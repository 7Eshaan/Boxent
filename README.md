# Boxent

A local, self-hosted sandbox engine for AI coding agents, served as an MCP server. Each sandbox is a
disposable, isolated Linux environment with instant snapshot and restore of its workspace.

Status: milestones M0 to M7 are done: development environment, in-sandbox agent and protocol,
isolated sandboxes with crun, the engine with its warm pool and reaper, the MCP server over stdio
and Streamable HTTP, snapshot/restore, egress allowlists, metrics and hardening. See
[docs/threat-model.md](docs/threat-model.md) for what Boxent defends against and how.

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

Tools: `run_bash`, `run_python`, `write_file`, `read_file`, `create_sandbox`, `destroy_sandbox`,
`snapshot`, `restore`, `list_snapshots`, `delete_snapshot`. A snapshot captures `/workspace` and
`/home/sandbox` at one instant (a read-only Btrfs snapshot, about 2 ms); `restore` rewinds them in
the running sandbox, after killing its processes. Each sandbox has a 2 GiB disk budget that covers
its files and all its snapshots, and holds up to 32 snapshots.

### Streamable HTTP and metrics

For daemons and several agents at once, the daemon can also serve MCP over Streamable HTTP. It is
off by default. Set `[http] listen = "127.0.0.1:7788"` in `/etc/boxent/boxent.toml` and restart
`boxentd`; Lima forwards that port to the Mac's loopback. Every request needs
`Authorization: Bearer <token>` (`boxent vm http` prints the URL and token), requests from web
pages (any `Origin` header) are refused, and `Host` must be a loopback name. Each MCP session gets
its own default sandbox. `GET /metrics` returns Prometheus metrics behind the same token.

### Network access

Sandboxes have no network interface besides loopback. Their only way out is an HTTP proxy at
`127.0.0.1:3128` (already set in `HTTP_PROXY`/`HTTPS_PROXY`), served by the daemon from outside
the sandbox. By default it refuses everything. The operator defines egress profiles in
`/etc/boxent/boxent.toml` (see `config/boxent.example.toml`), and an agent picks one with
`create_sandbox profile="pypi"`. The proxy allows HTTPS and plain HTTP to the listed hosts only,
resolves names itself, refuses names that resolve to private or local addresses, and checks that
TLS goes to the host the tunnel was opened for. To use the example profiles in the VM:

```bash
limactl copy config/boxent.example.toml boxent:/tmp/boxent.toml
limactl shell boxent sudo install -D -m 0644 /tmp/boxent.toml /etc/boxent/boxent.toml
limactl shell boxent sudo systemctl restart boxentd
```
Calls without a `sandbox_id` share one sandbox per session, created on first use and destroyed 30
seconds after the session ends.

## Layout

| Path | What it is |
| --- | --- |
| `crates/boxent-cli` | The `boxent` binary: `doctor`, `vm`, `image`, `sandbox`, and later `daemon` and `mcp` |
| `crates/boxent-core` | Engine: warm pool, claim, exec, file ops, snapshots, idle and TTL reaping, crash recovery |
| `crates/boxent-driver-oci` | Isolation driver: user and network namespaces, idmapped mounts, cgroups, seccomp, crun |
| `crates/boxent-egress` | Host-side egress proxy: allowlist profiles, private-address and SNI checks |
| `crates/boxent-agent` | PID 1 agent inside every sandbox: reaping, commands in per-command cgroups, file access as the sandbox user |
| `crates/boxent-proto` | Engine to agent wire protocol: length-prefixed CBOR frames, head/tail output capture |
| `crates/boxent-mcp` | MCP tools with strict schemas, session routing, the Unix-socket and Streamable HTTP servers |
| `deploy/lima/boxent.yaml` | Lima template for the VM that hosts the engine on macOS |
| `deploy/systemd/boxentd.service` | systemd unit for the daemon |
| `config/boxent.example.toml` | Daemon settings, sandbox limits and egress profiles |
| `tests/e2e` | Black-box tests through `boxent mcp` with the official Python MCP SDK |
| `docs/threat-model.md` | Assets, attackers, controls and the tests that prove them, residual risks |
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
latency benchmark against the engine, snapshot suite D, egress suite B12 (needs the VM to reach
example.com), and the MCP session and HTTP (E6) tests, each followed by a leak check.
`cargo xtask e2e` runs the black-box MCP suite from the Mac, through the relay and Lima's socket
forwarding, using a local `.venv` with the official Python MCP SDK; it includes a Hypothesis
model-based test of snapshot and restore (500 random sequences, about 2 minutes) and a daemon soak
of 1,300 full sandbox lifecycles that checks memory and file descriptors.

## Development on Linux

Needs kernel 6.8+, cgroup v2, crun, btrfs-progs, mmdebstrap, and a Btrfs filesystem with simple
quotas mounted at `/var/lib/boxent`. `sudo boxent doctor` checks all of these and prints a fix for
anything missing.
