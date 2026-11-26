# Boxent threat model

Boxent assumes that everything running inside a sandbox is hostile: the code an agent writes, the
packages it installs, and the agent itself if a prompt injection has turned it. This document
lists what Boxent protects, what it defends against, how, which test proves each control, and
what is left over.

## What is protected

| Asset | Why it matters |
| --- | --- |
| The Mac (or Linux host) and its user's files, keys and credentials | The point of a local sandbox |
| The VM and the Boxent daemon that runs as root in it | Control of the daemon is control of every sandbox |
| Other sandboxes' files, processes and network rights | Several agents may share one machine |
| The network beyond what the operator allowed | Exfiltration and attacks from the user's address |
| The machine's capacity (CPU, memory, disk, processes) | One runaway job must not stall the rest |

## Who attacks, and from where

1. **Code in a sandbox**: arbitrary binaries as UID 1000, any syscall the filter allows, unlimited
   attempts within its limits.
2. **The agent driving Boxent**, if manipulated: it can call any MCP tool with any arguments.
3. **A web page in the user's browser** reaching the optional HTTP endpoint on loopback.
4. Out of scope: anyone who already runs code as the Mac user (they can drive Lima directly), and
   a compromised kernel, hypervisor or Lima itself.

## Trust boundaries

```text
 sandbox code (hostile)
   │  syscalls: seccomp allowlist, Landlock, no capabilities, user namespace
   ▼
 Linux kernel of the VM ───────────────┐
   ▲                                   │  separate mount, PID, network, IPC, UTS, cgroup namespaces
   │ inherited socket (no path)        │
 agent (PID 1, root only in its userns; its replies are untrusted)
   │
 boxentd (root in the VM): engine, egress proxy, MCP
   │  Unix socket, forwarded by Lima          optional HTTP on loopback, bearer token
   ▼
 the Mac: `boxent mcp` relay, MCP clients
```

On macOS the VM is a second wall: a sandbox escape lands in a VM with no host mounts, no route to
the Mac's loopback services, and no SSH agent.

## Threats and controls

| Threat | Controls | Proved by |
| --- | --- | --- |
| Escape to the host through the kernel | User namespace with a unique 65,536-ID range per sandbox (root inside is an unused host UID); every capability dropped, bounding set empty; no-new-privs; seccomp allowlist without `io_uring`, `bpf`, `userfaultfd`, `perf_event_open`, key management, `ptrace`, namespace and mount syscalls; `clone3` returns ENOSYS so `clone` flags can be filtered; Landlock limits writes to the workspace, home, /tmp and /dev/shm; read-only, idmapped root filesystem; on macOS, the VM boundary | B7, B8, agent tests |
| Reading host secrets | No host paths in sandboxes besides the read-only agent binary; environment built from scratch; Lima VM has no host mounts, no SSH agent or keys, no access to the Mac's loopback, no proxy settings copied in | B2, B9, doctor (`vm host mounts`, `vm host loopback`) |
| Reaching the network | Own network namespace with only `lo`, owned by the host so sandbox root cannot add interfaces; no resolver; `AF_VSOCK` refused (a vsock socket would reach the hypervisor host) | B1, B2 |
| Exfiltration or attacks through allowed egress | One HTTP proxy per sandbox, served from outside it; operator-defined profiles only; IP literals and numeric host forms refused; DNS resolved by the proxy, any non-public answer refuses the name, and only checked addresses are dialled; TLS SNI must equal the tunnel host before the destination is contacted; plain HTTP and CONNECT only | B12, proxy tests |
| Attacking other sandboxes | Separate namespaces and cgroups; unguessable 128-bit sandbox and snapshot ids; snapshots usable only in their own sandbox; per-sandbox UID ranges and disk budgets | B10, D9 |
| Resource exhaustion | cgroup v2 CPU quota, memory with no swap, PID limit; per-command cgroups with whole-group OOM kills; tmpfs size caps; Btrfs simple-quota budget that also counts snapshots (no pinning loop); command timeouts with `cgroup.kill`; idle timeout and hard TTL; cap on sandboxes, snapshots and proxy connections | B3-B6, C1-C4, D8 |
| Turning the agent against the daemon | Agent reached only through an inherited socket; frame size capped before allocation; replies checked against the requested caps; engine-side deadlines (an unresponsive agent gets its sandbox reaped); file reads and writes run with the sandbox user's file permissions, refuse `..`, magic links, and writes outside the writable roots | agent tests, B11, "hung agent" test |
| A hostile agent misusing the tools | Strict argument schemas (unknown fields rejected); no tool changes limits or egress rules; profiles are chosen, not defined; paths validated in the agent | E1, E3 |
| A web page driving the HTTP endpoint | Off by default; loopback only; 256-bit bearer token (constant-time check); any request with an `Origin` header refused; `Host` must be a loopback name (DNS rebinding) | E6 |
| Leftovers after a crash | Crash-only design: an exclusive engine lock, and on start every container, mount, subvolume, budget, cgroup and UID slot from the previous run is removed; sandboxes are single-use | C5, leak checks after every test |
| Corrupting the MCP stream | Nothing but MCP frames on stdout; logs on stderr; output capped and made valid UTF-8 | E2, E4 |

## Residual risks

- **Shared kernel.** All sandboxes share the VM's kernel. A kernel exploit reachable through the
  allowed syscalls breaks out of the sandbox, though on macOS not out of the VM. Stronger tiers
  (gVisor, Firecracker microVMs) are the planned answer.
- **The daemon runs as root in the VM.** A bug in it is a VM-root bug. Its exposure to sandboxes is
  the agent protocol and the egress proxy, both written to treat input as hostile.
- **Allowed domains can carry data out.** A profile that allows `github.com` lets code push to any
  repository it can authenticate to. Profiles should be as narrow as the work needs.
- **One HTTP token for everyone.** All HTTP clients share the token, and stateless (2026-07-28)
  requests without a `sandbox_id` share one default sandbox. Agents that must not see each other's
  work should use `create_sandbox` and keep their ids to themselves.
- **Snapshots outlive deletions.** Data deleted from a workspace stays in its snapshots until they
  or the sandbox are deleted.
- **Timing side channels** between sandboxes on the same CPUs are not addressed.
- **Logs** record a hash and length of each command, not its text, but do record egress hosts.
