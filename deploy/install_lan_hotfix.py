#!/usr/bin/env python3
"""Install an additive LAN hotfix. Dry-run unless --apply. Stop supervisor first."""
import argparse
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit


def atomic(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--proxy-ip", required=True, help="Actual private TCP peer IP of Nginx")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    package = Path(__file__).resolve().parent
    peer = ipaddress.ip_address(args.proxy_ip)
    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
    if not any(peer in ipaddress.ip_network(n) for n in networks if ipaddress.ip_network(n).version == peer.version):
        raise SystemExit("--proxy-ip must be the exact RFC1918/ULA address of Nginx")
    targets = [root / "private/patcher.json", root / "private/updates/state.json",
               root / "worker/deploy/run_managed.py"]
    for path in [root / "run.py", *targets]:
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise SystemExit(f"Missing or out-of-scope deployment file: {path}")
    manifest = json.loads((package / "SHA256.json").read_text())
    for name, expected in manifest.items():
        path = package / name
        if not path.resolve().is_relative_to(package):
            raise SystemExit("Invalid bundle path")
        if hashlib.file_digest(path.open("rb"), "sha256").hexdigest() != expected:
            raise SystemExit(f"Bundle checksum mismatch: {name}")
    base = json.loads(targets[0].read_text())
    state = json.loads(targets[1].read_text())
    origin = base.get("security", {}).get("publicOrigin", "")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise SystemExit("publicOrigin must be a plain HTTPS origin; no Markdown. Review deployment identity before changing it.")
    expected_identity = {"applicationId": base.get("applicationId"),
                         "signer": base["signing"]["fingerprint"], "origin": origin}
    if state.get("identity") != expected_identity:
        raise SystemExit("Deployment identity mismatch; not modifying state")
    active = state.get("active")
    if not active or not Path(active["config"]).is_file():
        raise SystemExit("Active generation config is missing")
    host, port = base["listen"].rsplit(":", 1)
    if not 0 < int(port) < 65536:
        raise SystemExit("Invalid configured port")
    base["listen"] = f"0.0.0.0:{port}"
    base["security"].update(allowLanProxy=True, requireTrustedProxy=True,
        clientIpHeader="cf-connecting-ip", trustedProxies=["127.0.0.1/32", "::1/128", f"{peer}/{peer.max_prefixlen}"])
    print("Existing files to back up and update:")
    for path in targets:
        print(f"  {path}")
    print(f"Listen: {base['listen']}; trusted Nginx: {peer}")
    print("Preserving XAPK, keys, cache, runtime artifacts, Android versions and generation snapshots.")
    if not args.apply:
        print("DRY RUN ONLY. Stop the Python project, then repeat with --apply.")
        return
    os.umask(0o077)
    lock = (root / "private/updates/supervisor.lock").open("a+")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Supervisor is running. Stop the Python project before applying.")
    probe = subprocess.run([str(package / "ggfm-patcher-web"), "--network-capabilities"],
                           capture_output=True, text=True, timeout=10, check=True)
    if not json.loads(probe.stdout).get("lanProxy"):
        raise SystemExit("Replacement binary does not support LAN mode")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = root / "private" / ("lan-hotfix-backup-" + stamp)
    backup.mkdir()
    names = ("patcher.json", "state.json", "run_managed.py")
    for path, name in zip(targets, names):
        shutil.copy2(path, backup / name)
        os.chmod(backup / name, 0o600)
    runtime = root / "private/updates/hotfixes" / stamp
    runtime.mkdir(parents=True)
    shutil.copy2(package / "ggfm-patcher-web", runtime / "ggfm-patcher-web")
    os.chmod(runtime / "ggfm-patcher-web", 0o755)
    state["active"]["binary"] = str(runtime / "ggfm-patcher-web")
    try:
        atomic(targets[2], (package / "run_managed.py").read_bytes(), 0o755)
        atomic(targets[0], json.dumps(base, indent=2).encode() + b"\n")
        atomic(targets[1], json.dumps(state, indent=2).encode() + b"\n")
    except Exception:
        for path, name in zip(targets, names):
            atomic(path, (backup / name).read_bytes(), 0o755 if name.endswith(".py") else 0o600)
        raise
    print(f"Installed. Backups: {backup}")
    print("Start the SAME Python project. Do not run setup again.")


if __name__ == "__main__":
    main()
