"""Verification suite A, measured on the client side of `boxent mcp`: on macOS this includes the
relay and Lima's socket forwarding into the VM (A4)."""

import statistics
import time

from conftest import ok, open_session

N = 300


def pct(samples, p):
    s = sorted(samples)
    return s[min(len(s) - 1, len(s) * p // 100)]


def report(name, samples):
    ms = [x * 1000 for x in samples]
    print(f"\n{name}: n={len(ms)} p50={pct(ms, 50):.1f}ms p95={pct(ms, 95):.1f}ms "
          f"p99={pct(ms, 99):.1f}ms max={max(ms):.1f}ms mean={statistics.mean(ms):.1f}ms")
    return pct(ms, 99)


async def test_a4_first_call_in_fresh_sessions():
    """Each session's first run_bash claims a sandbox from the warm pool."""
    samples = []
    for _ in range(N):
        async with open_session() as s:
            t = time.perf_counter()
            out = await ok(s, "run_bash", command="echo ok")
            samples.append(time.perf_counter() - t)
            assert out["stdout"] == "ok\n"
            await ok(s, "destroy_sandbox")
    assert report("A4 claim + run_bash(echo) from the Mac", samples) < 200


async def test_a2_calls_in_an_active_sandbox():
    async with open_session() as s:
        await ok(s, "run_bash", command="true")
        samples = []
        for _ in range(N):
            t = time.perf_counter()
            await ok(s, "run_bash", command="echo ok")
            samples.append(time.perf_counter() - t)
        await ok(s, "destroy_sandbox")
    assert report("A2 run_bash(echo) in an active sandbox", samples) < 50


async def test_a3_run_python_in_fresh_sessions():
    samples = []
    for _ in range(100):
        async with open_session() as s:
            t = time.perf_counter()
            out = await ok(s, "run_python", code="print(1)")
            samples.append(time.perf_counter() - t)
            assert out["stdout"] == "1\n"
            await ok(s, "destroy_sandbox")
    assert report("A3 claim + run_python(print) from the Mac", samples) < 200
