"""C7 at daemon level: 1,000 full sandbox lifecycles through MCP must not grow the daemon's memory
(RSS within 10%) or leak file descriptors. Measured inside the VM, after a warm-up."""

import subprocess

from conftest import ok, open_session


def daemon(stat: str) -> int:
    script = (
        "pid=$(systemctl show -p MainPID --value boxentd); "
        f"if [ {stat!r} = fds ]; then ls /proc/$pid/fd | wc -l; "
        "else awk '/^VmRSS/ {print $2}' /proc/$pid/status; fi"
    )
    out = subprocess.run(["limactl", "shell", "--workdir", "/", "boxent", "sudo", "bash", "-c", script],
                         capture_output=True, text=True, check=True)
    return int(out.stdout.strip())


async def cycle(session):
    sid = (await ok(session, "create_sandbox"))["sandbox_id"]
    await ok(session, "write_file", path="f.txt", content="data", sandbox_id=sid)
    snap = await ok(session, "snapshot", sandbox_id=sid)
    await ok(session, "run_bash", command="rm f.txt", sandbox_id=sid)
    await ok(session, "restore", snap_id=snap["snap_id"], sandbox_id=sid)
    out = await ok(session, "run_bash", command="cat f.txt", sandbox_id=sid)
    assert out["stdout"] == "data"
    await ok(session, "destroy_sandbox", sandbox_id=sid)


async def test_c7_daemon_soak_1000_cycles():
    async with open_session() as session:
        for _ in range(300):
            await cycle(session)
        rss, fds = daemon("rss"), daemon("fds")
        trace = []
        for i in range(1, 1001):
            await cycle(session)
            if i % 250 == 0:
                trace.append(daemon("rss"))
        rss2, fds2 = daemon("rss"), daemon("fds")
    print(f"\ndaemon RSS {rss} KiB, then every 250 cycles {trace} KiB; fds {fds} -> {fds2}")
    assert fds2 <= fds + 8, f"fd leak: {fds} -> {fds2}"
    assert rss2 * 10 <= rss * 11, f"daemon RSS grew more than 10%: {rss} -> {rss2} KiB"
