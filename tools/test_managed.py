#!/usr/bin/env python3
"""Updater contracts and real subprocess cutover/rollback on a local test port.

The fixture is our own tiny worker, not an APK patching acceptance substitute.
No GitHub writes, signing secrets, game data or installed applications are used.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("managed", ROOT / "deploy/run_managed.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

WORKER = r'''
import json, os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
c = json.loads(Path(os.environ["GGFM_PATCHER_CONFIG"]).read_text())
if os.environ.get("GGFM_PREPARE_ONLY"):
    if c.get("bad_prebuild"): raise SystemExit(17)
    Path(c["output"]).write_text(str(c["revision"]))
    raise SystemExit(0)
if c.get("bad_health"): raise SystemExit(18)
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"ok": True, "androidVersion": {"revision": c["revision"]}}).encode()
        self.send_response(200); self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass
host, port = c["listen"].split(":")
HTTPServer((host, int(port)), Handler).serve_forever()
'''


class ArchiveTests(unittest.TestCase):
    def test_historical_seed_requires_an_explicit_version_floor(self):
        with tempfile.TemporaryDirectory(prefix="ggfm-seed-test-") as tmp:
            config = Path(tmp) / "seed.json"
            generation = {"config": str(config)}
            config.write_text(json.dumps({"versions": {"revision": 1}}))
            self.assertEqual(m.initial_revision({"ok": True}, generation), 1)
            self.assertEqual(m.initial_revision({"androidVersion": {"revision": 9}}, generation), 9)
            for version in (None, 0, -1, True, "1", 2100000000):
                config.write_text(json.dumps({"versions": {"revision": version}}))
                with self.assertRaises(ValueError):
                    m.initial_revision({"ok": True}, generation)

    def test_counter_never_reuses_or_exceeds_android_range(self):
        self.assertEqual(m.next_revision(8, 8), 9)
        self.assertEqual(m.next_revision(8, 15), 15)
        self.assertEqual(m.next_revision(15, 8), 16)
        with self.assertRaises(ValueError):
            m.next_revision(2100000000 - 800000, 8)

    def test_exact_hash_manifest_and_commit_are_required(self):
        with tempfile.TemporaryDirectory(prefix="ggfm-release-test-") as tmp:
            archive = Path(tmp) / "release.zip"
            payload = b"our test fixture, not game code"
            commit = "a" * 40
            manifest = {"schema": 1, "kind": "test", "sourceCommit": commit,
                "files": {"worker": {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}}}
            def write(extra=False, data=payload):
                with zipfile.ZipFile(archive, "w") as z:
                    z.writestr("worker", data)
                    z.writestr("release-manifest.json", json.dumps(manifest))
                    if extra: z.writestr("../unexpected", b"no")
            write()
            m.verify_archive(archive, {"worker"}, "test", commit)
            with self.assertRaises(ValueError):
                m.verify_archive(archive, {"worker"}, "test", "b" * 40)
            write(data=b"tampered")
            with self.assertRaises(ValueError):
                m.verify_archive(archive, {"worker"}, "test", commit)
            write(extra=True)
            with self.assertRaises(ValueError):
                m.verify_archive(archive, {"worker"}, "test", commit)


class ProcessCutoverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ggfm-cutover-test-")
        self.root = Path(self.temp.name)
        self.script = self.root / "worker.py"
        self.script.write_text(WORKER, encoding="utf-8")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.original_start, self.original_run = m.start, m.run
        self.children = []
        import subprocess
        def start(generation):
            child = subprocess.Popen([sys.executable, str(self.script)], env=m.child_env(generation))
            self.children.append(child)
            return child
        def run(command, **kwargs):
            return self.original_run([sys.executable, self.script], **kwargs)
        self.patches = [patch.object(m, "start", start), patch.object(m, "run", run)]
        for p in self.patches: p.start()
        m.STOP = False
        self.old = self.generation(8)
        self.new = self.generation(9)
        self.state_path = self.root / "state.json"
        self.state = {"active": self.old, "counter": 9, "pair": "old",
                      "identity": {"applicationId": "test", "signer": "unchanged"}}
        m.atomic_json(self.state_path, self.state)
        self.child = m.start(self.old)
        self.assertTrue(m.ready(self.old, self.child))

    def generation(self, revision, **flags):
        config = self.root / f"{revision}.json"
        config.write_text(json.dumps({"listen": f"127.0.0.1:{self.port}", "revision": revision,
            "output": str(self.root / f"output-{revision}"), **flags}), encoding="utf-8")
        return {"config": str(config), "binary": sys.executable, "revision": revision}

    def tearDown(self):
        for child in self.children: m.stop(child)
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def test_prebuild_then_cutover_and_persistent_restart(self):
        active, child = m.activate(self.new, self.old, self.child, self.state, self.state_path, "new")
        self.assertEqual(active, self.new)
        self.assertEqual((self.root / "output-9").read_text(), "9")
        persisted = json.loads(self.state_path.read_text())
        self.assertEqual(persisted["previous"], self.old)
        self.assertEqual(persisted["pair"], "new")
        self.assertEqual(persisted["identity"]["signer"], "unchanged")
        m.stop(child)
        restarted = m.start(persisted["active"])
        self.assertEqual(m.ready(persisted["active"], restarted)["androidVersion"]["revision"], 9)

    def assert_rollback(self, candidate):
        active, child = m.activate(candidate, self.old, self.child, self.state, self.state_path, "new")
        self.assertEqual(active, self.old)
        self.assertEqual(m.ready(active, child)["androidVersion"]["revision"], 8)
        self.assertEqual(self.state["pair"], "old")
        self.assertEqual(json.loads(self.state_path.read_text())["pair"], "old")
        self.assertEqual(self.state["counter"], 9)

    def test_failed_prebuild_restores_old_worker(self):
        self.assert_rollback(self.generation(9, bad_prebuild=True))
        self.assertFalse((self.root / "output-9").exists())

    def test_failed_health_restores_old_worker(self):
        self.assert_rollback(self.generation(9, bad_health=True))

    def test_failed_state_commit_does_not_publish_candidate(self):
        with patch.object(m, "atomic_json", side_effect=OSError("fixture disk full")):
            self.assert_rollback(self.new)


if __name__ == "__main__":
    unittest.main()
