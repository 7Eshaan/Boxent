"""Verification suite D7: model-based test of snapshot and restore, through MCP from this machine.

Hypothesis generates random sequences of file writes, deletes, snapshots, restores and snapshot
deletions. After every step the sandbox's files must equal an in-memory model; on failure,
Hypothesis shrinks to the shortest sequence that breaks it.
"""

import asyncio
import concurrent.futures
import json
import threading

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, consumes, invariant, rule

from conftest import ok, open_session

PATHS = ["a.txt", "b.txt", ".hidden", "d/c.txt", "d/e/f.txt"]
LIST_FILES = """
import json, os
out = {}
for root, _, files in os.walk('.'):
    for f in files:
        p = os.path.relpath(os.path.join(root, f), '.')
        out[p] = open(p).read()
print(json.dumps(out, sort_keys=True))
"""


class Remote:
    """One MCP session, driven from synchronous Hypothesis code. The session lives in one task on
    a background event loop (the SDK's context managers must enter and exit in the same task)."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.queue = None
        ready = concurrent.futures.Future()
        self.done = asyncio.run_coroutine_threadsafe(self._serve(ready), self.loop)
        ready.result(60)

    async def _serve(self, ready):
        self.queue = asyncio.Queue()
        async with open_session() as session:
            ready.set_result(None)
            while (item := await self.queue.get()) is not None:
                fn, fut = item
                try:
                    fut.set_result(await fn(session))
                except Exception as e:  # handed back to the calling thread
                    fut.set_exception(e)

    def call(self, tool, **args):
        fut = concurrent.futures.Future()
        self.loop.call_soon_threadsafe(self.queue.put_nowait, (lambda s: ok(s, tool, **args), fut))
        return fut.result(120)

    def close(self):
        self.loop.call_soon_threadsafe(self.queue.put_nowait, None)
        self.done.result(60)
        self.loop.call_soon_threadsafe(self.loop.stop)


class SnapshotMachine(RuleBasedStateMachine):
    remote: Remote = None
    base: str = None
    snaps = Bundle("snaps")

    def __init__(self):
        super().__init__()
        # Every example starts from the same empty workspace, restored from a base snapshot.
        self.remote.call("restore", snap_id=self.base)
        self.model = {}
        self.saved = {}

    @rule(path=st.sampled_from(PATHS), content=st.text(alphabet="abc\n", max_size=8))
    def write(self, path, content):
        self.remote.call("write_file", path=path, content=content)
        self.model[path] = content

    @rule(path=st.sampled_from(PATHS))
    def delete(self, path):
        self.remote.call("run_bash", command=f"rm -f {path}")
        self.model.pop(path, None)

    @rule()
    def delete_dir(self):
        self.remote.call("run_bash", command="rm -rf d")
        self.model = {p: c for p, c in self.model.items() if not p.startswith("d/")}

    @rule(target=snaps)
    def snapshot(self):
        sid = self.remote.call("snapshot")["snap_id"]
        self.saved[sid] = dict(self.model)
        return sid

    @rule(sid=snaps)
    def restore(self, sid):
        if sid not in self.saved:
            return  # deleted earlier in this example
        self.remote.call("restore", snap_id=sid)
        self.model = dict(self.saved[sid])

    @rule(sid=consumes(snaps))
    def delete_snapshot(self, sid):
        if sid in self.saved:
            self.remote.call("delete_snapshot", snap_id=sid)
            del self.saved[sid]

    @invariant()
    def files_match_the_model(self):
        out = self.remote.call("run_python", code=LIST_FILES)
        assert json.loads(out["stdout"]) == self.model

    def teardown(self):
        for sid in self.saved:
            self.remote.call("delete_snapshot", snap_id=sid)


@pytest.fixture(scope="module")
def remote():
    r = Remote()
    r.call("run_bash", command="true")
    SnapshotMachine.remote = r
    SnapshotMachine.base = r.call("snapshot", label="empty")["snap_id"]
    yield r
    r.call("destroy_sandbox")
    r.close()


def test_d7_snapshot_restore_matches_a_model(remote):
    run = SnapshotMachine.TestCase
    run.settings = settings(
        max_examples=500,
        stateful_step_count=15,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    run().runTest()
