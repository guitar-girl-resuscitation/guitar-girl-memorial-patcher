"""Linux-only additive installer dry-run/apply/lock test in a disposable fixture."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import fcntl

repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="ggfm-lan-install-test-") as temp:
    root = Path(temp) / "deployment"
    package = Path(temp) / "package"
    package.mkdir()
    (root / "worker/deploy").mkdir(parents=True)
    (root / "private/updates/generations").mkdir(parents=True)
    (root / "run.py").write_text("original entry")
    (root / "private/signing-secret").write_text("fixture-not-a-real-key")
    (root / "worker/deploy/run_managed.py").write_text("old supervisor")
    identity = {"applicationId": "fixture", "signer": "test", "origin": "https://example.org"}
    config = {"listen": "127.0.0.1:19078", "applicationId": "fixture",
              "signing": {"fingerprint": "test"}, "security": {"publicOrigin": identity["origin"]}}
    generation = root / "private/updates/generations/17.json"
    generation.write_text(json.dumps(dict(config, versions={"deploymentRevision": 17})))
    base = root / "private/patcher.json"
    base.write_text(json.dumps(config))
    statefile = root / "private/updates/state.json"
    statefile.write_text(json.dumps({"identity": identity, "counter": 17, "pair": "unchanged",
                                   "active": {"config": str(generation), "binary": "old", "revision": 17}}))
    before = {p: p.read_bytes() for p in (base, statefile, generation, root / "run.py", root / "private/signing-secret")}
    shutil.copy2(repo / "deploy/install_lan_hotfix.py", package)
    shutil.copy2(repo / "deploy/run_managed.py", package)
    shutil.copy2(repo / "target/release/ggfm-patcher-web", package)
    (package / "SHA256.json").write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.iterdir()}))
    command = [sys.executable, str(package / "install_lan_hotfix.py"), "--root", str(root), "--proxy-ip", "10.0.0.1"]
    subprocess.run(command, check=True)
    assert all(p.read_bytes() == data for p, data in before.items())
    with (root / "private/updates/supervisor.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert subprocess.run(command + ["--apply"], capture_output=True).returncode != 0
        assert all(p.read_bytes() == data for p, data in before.items())
    subprocess.run(command + ["--apply"], check=True)
    updated = json.loads(base.read_text())
    assert updated["listen"] == "0.0.0.0:19078"
    assert updated["security"]["allowLanProxy"]
    state = json.loads(statefile.read_text())
    assert state["counter"] == 17 and state["pair"] == "unchanged" and state["identity"] == identity
    assert state["active"]["revision"] == 17
    assert state["active"]["config"] == str(generation)
    subprocess.run([state["active"]["binary"], "--network-capabilities"], check=True)
    for p in (generation, root / "run.py", root / "private/signing-secret"):
        assert p.read_bytes() == before[p]
    backups = list((root / "private").glob("lan-hotfix-backup-*"))
    assert len(backups) == 1
    assert (backups[0] / "state.json").read_bytes() == before[statefile]
    print("PASS: dry-run, running-supervisor refusal, additive install, backups, identity/counter/source preservation")
