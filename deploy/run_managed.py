#!/usr/bin/env python3
"""Stable Linux supervisor. Only verified GitHub worker/runtime releases are executed.

Configuration, signing identity and original XAPK remain operator-owned. Each
generation is immutable; updates drain the old worker, prebuild, then switch.
No game input, signing secret or save is sent to GitHub.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
import zipfile

ORG = "guitar-girl-resuscitation"
WORKER = "guitar-girl-memorial-patcher"
PATCH = "guitar-girl-memorial-patch"
WORKER_FILES = {"ggfm-patcher", "ggfm-patcher-web", "patcher.example.json", "DEPLOYMENT.md", "LICENSE",
                "PUBLIC_DEPLOYMENT.md", "VERSIONING.md", "deploy/cloudflared.yml", "deploy/ggfm-patcher.service",
                "deploy/run_managed.py"}
PATCH_FILES = {"classes.dex", "libggfm_bootstrap.so", "libdobby.so", "libggfm_server.so",
               "memorial-policy.v1.json", "THIRD_PARTY_TERMINAL_FONT.md", "DOBBY-LICENSE", "dependencies.json", "LICENSE"}
MAX_ARCHIVE = 256 * 1024 * 1024
STOP = False


def log(message):
    print("[GGFM UPDATE] " + message, flush=True)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest().upper()


def atomic_json(path, value):
    temporary = path.with_suffix(".new")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def api(path):
    request = urllib.request.Request("https://api.github.com/" + path,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "GGFM-Deployment/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("GitHub metadata exceeds limit")
    return json.loads(data)


def release(repo, name):
    metadata = api(f"repos/{ORG}/{repo}/releases/tags/nightly")
    if metadata.get("draft") or not re.fullmatch(r"[0-9a-f]{40}", metadata.get("target_commitish", "")):
        raise ValueError("release is not tied to an exact source commit")
    asset = next(a for a in metadata["assets"] if a["name"] == name)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", "")) or not 0 < asset["size"] <= MAX_ARCHIVE:
        raise ValueError("release asset digest/size unavailable")
    return {"repo": repo, "commit": metadata["target_commitish"], "asset": asset}


def verify_archive(path, expected_files, kind, commit):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != len(expected_files) + 1 or {p.filename for p in entries} != expected_files | {"release-manifest.json"}:
            raise ValueError("unexpected release archive members")
        if sum(p.file_size for p in entries) > MAX_ARCHIVE:
            raise ValueError("expanded release exceeds limit")
        manifest = json.loads(archive.read("release-manifest.json"))
        if manifest.get("schema") != 1 or manifest["kind"] != kind or manifest["sourceCommit"] != commit:
            raise ValueError("release provenance mismatch")
        if set(manifest["files"]) != expected_files:
            raise ValueError("incomplete release hash manifest")
        for name, row in manifest["files"].items():
            with archive.open(name) as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest().upper()
            if actual != row["sha256"].upper() or archive.getinfo(name).file_size != row["size"]:
                raise ValueError("release member hash/size mismatch")
    return manifest


def download(item, directory, expected_files, kind):
    directory.mkdir(parents=True, exist_ok=True)
    archive_path = directory / "release.zip"
    expected = item["asset"]["digest"].split(":", 1)[1].upper()
    if not archive_path.exists():
        # Immutable asset ID; never fetch a second moving Nightly URL.
        request = urllib.request.Request(f"https://api.github.com/repos/{ORG}/{item['repo']}/releases/assets/{item['asset']['id']}",
            headers={"Accept": "application/octet-stream", "User-Agent": "GGFM-Deployment/1"})
        temporary = directory / "download.partial"
        with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as stream:
            total = 0
            deadline = time.monotonic() + 300
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE or time.monotonic() > deadline:
                    raise ValueError("release download limit exceeded")
                stream.write(chunk)
        if digest(temporary) != expected or total != item["asset"]["size"]:
            raise ValueError("GitHub asset hash mismatch")
        os.replace(temporary, archive_path)
    if digest(archive_path) != expected:
        raise ValueError("cached release hash mismatch")
    manifest = verify_archive(archive_path, expected_files, kind, item["commit"])
    with zipfile.ZipFile(archive_path) as archive:
        for name in sorted(expected_files):
            destination = directory / name  # names are a fixed flat allowlist
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                if digest(destination) != manifest["files"][name]["sha256"].upper():
                    raise ValueError("immutable release file was modified")
            else:
                with archive.open(name) as incoming, destination.open("xb") as output:
                    while chunk := incoming.read(1024 * 1024):
                        output.write(chunk)
    return manifest


def runtime_profile(base):
    # The source manifest is authoritative: never silently replace a V7 runtime
    # with the historical ARM64 default during an unattended update.
    profile = json.loads(Path(base["compatibilityManifest"]).read_text(encoding="utf-8"))
    abi = profile["source"].get("abi", "arm64-v8a")
    profiles = {"arm64-v8a": ("patch-android-arm64", "8.0.0.json"),
                "armeabi-v7a": ("patch-android-armv7", "8.0.0-armv7.json")}
    if abi not in profiles:
        raise ValueError("unsupported source Android ABI")
    return (abi, *profiles[abi])


def verify_runtime(directory, expected_abi="arm64-v8a"):
    dependencies = json.loads((directory / "dependencies.json").read_text())
    if dependencies.get("androidAbi", "arm64-v8a") != expected_abi or dependencies["server"].get("androidAbi", "arm64-v8a") != expected_abi:
        raise ValueError("runtime Android ABI mismatch")
    if dependencies.get("schema") != 1 or dependencies["server"]["serverAbi"] != 1:
        raise ValueError("unsupported runtime ABI")
    if digest(directory / "libggfm_server.so") != dependencies["server"]["sha256"].upper():
        raise ValueError("runtime Server pair mismatch")
    policy = digest(directory / "memorial-policy.v1.json")
    if policy != dependencies["policySha256"].upper() or policy != dependencies["server"]["policySha256"].upper():
        raise ValueError("runtime policy mismatch")
    return dependencies


def next_revision(previous, compiled):
    result = max(previous + 1, compiled)
    if not 0 < result <= 2100000000 - 800000:
        raise ValueError("deployment version counter exhausted")
    return result


def initial_revision(health, generation):
    # First distributed deployments predate version metadata in /healthz.
    # Only their explicit, operator-owned seed revision can establish a floor.
    version = health.get("androidVersion", {}).get("revision")
    if version is None:
        config = json.loads(Path(generation["config"]).read_text())
        versions = config.get("versions", {})
        version = versions.get("deploymentRevision", versions.get("revision"))
    if type(version) is not int or not 0 < version <= 2100000000 - 800000:
        raise ValueError("cannot establish installed deployment version floor")
    return version


def run(command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True, timeout=1800, **kwargs)


def load_native_overlay(config_path, base):
    """Read an additive private input descriptor; never rewrite operator config."""
    private = config_path.resolve().parent
    descriptor = private / "native-armv7.json"
    if not descriptor.exists():
        return base
    value = json.loads(descriptor.read_text(encoding="utf-8"))
    if set(value) != {"schema", "splitFile", "sha256"} or value["schema"] != 1:
        raise ValueError("invalid ARMv7 overlay descriptor")
    source = (private / value["splitFile"]).resolve(strict=True)
    if not source.is_file() or not source.is_relative_to(private) or source.stat().st_size > MAX_ARCHIVE:
        raise ValueError("ARMv7 overlay source is outside private directory or too large")
    expected = "49848F553811A72379385A90CCC7CB3BBB0622FD39D13AAA757C1319071C69E6"
    if value["sha256"].upper() != expected or digest(source) != expected:
        raise ValueError("ARMv7 overlay original split fingerprint mismatch")
    if runtime_profile(base)[0] != "arm64-v8a":
        raise ValueError("universal overlay requires the verified ARM64 primary source")
    result = copy.deepcopy(base)
    result["universalArmv7Source"] = str(source)
    log("Verified private ARMv7 input found; next compatible generation will build both ARM ABIs")
    return result


def stage(root, base, worker_release, patch_release, previous_revision, supplement_release=None):
    worker_dir = root / "artifacts" / worker_release["asset"]["digest"].split(":")[1]
    patch_dir = root / "artifacts" / patch_release["asset"]["digest"].split(":")[1]
    metadata = download(worker_release, worker_dir, WORKER_FILES, "patcher-linux-x64")
    if metadata.get("workerApiVersion") != 1:
        raise ValueError("worker needs a newer deployment entry point")
    if base.get("universalArmv7Source"):
        binary = worker_dir / "ggfm-patcher-web"
        binary.chmod(0o755)
        if not supports_universal_arm(binary):
            raise ValueError("worker lacks universal ARM support; keeping existing generation")
    if base.get("security", {}).get("allowLanProxy"):
        binary = worker_dir / "ggfm-patcher-web"
        binary.chmod(0o755)
        if not supports_lan_proxy(binary):
            log("Skipping release: worker lacks LAN proxy capability; active service remains online")
            raise ValueError("release lacks LAN proxy support; keeping active worker without interruption")
    abi, kind, profile_name = runtime_profile(base)
    download(patch_release, patch_dir, PATCH_FILES, kind)
    dependencies = verify_runtime(patch_dir, abi)
    source = root / "sources" / patch_release["commit"]
    if not source.exists():
        source.mkdir(parents=True)
        run(["git", "init", source])
        run(["git", "-C", source, "remote", "add", "origin", f"https://github.com/{ORG}/{PATCH}.git"])
    if not (source / ".git").is_dir():
        raise ValueError("runtime source is not a git checkout")
    # Only touch our commit-specific checkout; never mutate the operator's repo.
    head = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True)
    if head.returncode != 0:
        run(["git", "-C", source, "fetch", "--depth", "1", "origin", patch_release["commit"]])
        run(["git", "-C", source, "checkout", "--detach", "FETCH_HEAD"])
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() != patch_release["commit"]:
        raise ValueError("Patch checkout commit mismatch")
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"], text=True).strip():
        raise ValueError("Patch checkout is dirty")
    if digest(source / "policy/memorial-policy.v1.json") != dependencies["policySha256"].upper():
        raise ValueError("source policy differs from native runtime")
    config = copy.deepcopy(base)
    for name in ("ggfm-patcher", "ggfm-patcher-web"):
        (worker_dir / name).chmod(0o755)
    compiled = json.loads(subprocess.check_output([str(worker_dir / "ggfm-patcher"), "version"], text=True))["revision"]
    revision = next_revision(previous_revision, compiled)
    config["versions"] = {"patchCommit": patch_release["commit"], "patchVersion": patch_release["commit"],
        "serverVersion": dependencies["server"]["sourceCommit"], "serverAbi": 1, "deploymentRevision": revision}
    # Optional provenance: failure to look up dates must not prevent an update.
    for key, repo, commit in [("patchUpdatedAt", PATCH, patch_release["commit"]),
                             ("serverUpdatedAt", "guitar-girl-memorial-server", dependencies["server"]["sourceCommit"])]:
        try:
            config["versions"][key] = api(f"repos/{ORG}/{repo}/git/commits/{commit}")["committer"]["date"]
        except (OSError, ValueError, KeyError):
            log(f"Source date unavailable for {repo}; leaving it unknown")
    artifacts = config["artifacts"]
    artifacts["patchRoot"] = str(source)
    artifacts["policyManifest"] = str(source / "policy/memorial-policy.v1.json")
    artifacts["policySha256"] = dependencies["policySha256"]
    for field, hash_field, filename in [("bootstrapDex", "bootstrapDexSha256", "classes.dex"),
            ("bootstrapSo", "bootstrapSoSha256", "libggfm_bootstrap.so"), ("dobbySo", "dobbySha256", "libdobby.so"),
            ("serverSo", "serverSha256", "libggfm_server.so")]:
        artifacts[field] = str(patch_dir / filename)
        artifacts[hash_field] = digest(patch_dir / filename)
    config["compatibilityManifest"] = str(source / "compatibility" / profile_name)
    if runtime_profile(config)[0] != abi:
        raise ValueError("updated source profile changed Android ABI")
    if base.get("universalArmv7Source"):
        selected = supplement_release or release(PATCH, "ggfm-patch-android-armv7.zip")
        if selected["commit"] != patch_release["commit"]:
            raise ValueError("ARM runtime releases changed during update; retry with one exact commit")
        v7_dir = root / "artifacts" / selected["asset"]["digest"].split(":")[1]
        download(selected, v7_dir, PATCH_FILES, "patch-android-armv7")
        v7_dependencies = verify_runtime(v7_dir, "armeabi-v7a")
        if (v7_dependencies["server"]["sourceCommit"] != dependencies["server"]["sourceCommit"]
                or v7_dependencies["policySha256"] != dependencies["policySha256"]
                or digest(v7_dir / "classes.dex") != digest(patch_dir / "classes.dex")):
            raise ValueError("universal runtime Server/policy/DEX mismatch")
        artifacts["additionalNative"] = {
            "sourceSplit": base["universalArmv7Source"],
            "compatibilityManifest": str(source / "compatibility/8.0.0-armv7.json"),
            "bootstrapSo": str(v7_dir / "libggfm_bootstrap.so"),
            "bootstrapSoSha256": digest(v7_dir / "libggfm_bootstrap.so"),
            "dobbySo": str(v7_dir / "libdobby.so"), "dobbySha256": digest(v7_dir / "libdobby.so"),
            "serverSo": str(v7_dir / "libggfm_server.so"), "serverSha256": digest(v7_dir / "libggfm_server.so")}
    old_lock = Path(base["artifacts"]["patchRoot"]) / "tools/requirements.lock.txt"
    new_lock = source / "tools/requirements.lock.txt"
    if not old_lock.is_file() or digest(old_lock) != digest(new_lock):
        venv = root / "python" / digest(new_lock).lower()
        marker = venv / "ggfm-complete"
        if not marker.exists():
            run([sys.executable, "-m", "venv", venv])
            run([venv / "bin/pip", "install", "--no-cache-dir", "--only-binary=:all:", "--no-binary=tpk_ar", "-r", new_lock])
            marker.touch()
        config["tools"]["python"] = str(venv / "bin/python")
    path = root / "generations" / f"{revision}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ValueError("generation already exists; counter must not be reused")
    atomic_json(path, config)
    return {"binary": str(worker_dir / "ggfm-patcher-web"), "config": str(path), "revision": revision}


def child_env(generation):
    env = dict(os.environ, GGFM_PATCHER_CONFIG=generation["config"])
    env.pop("GGFM_PREPARE_ONLY", None)
    if "port" in generation:
        env["GGFM_ROUTE_REVISION"] = str(generation["revision"])
    return env


def supports_lan_proxy(binary):
    try:
        env = dict(os.environ)
        env.pop("GGFM_PATCHER_CONFIG", None)
        result = subprocess.run([str(binary), "--network-capabilities"], env=env,
                                capture_output=True, text=True, timeout=10, check=True)
        return json.loads(result.stdout).get("lanProxy") is True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def start(generation):
    return subprocess.Popen([generation["binary"]], env=child_env(generation))


def supports_universal_arm(binary):
    env = dict(os.environ)
    env.pop("GGFM_PATCHER_CONFIG", None)
    try:
        result = subprocess.run([str(binary), "--network-capabilities"], check=True,
                                capture_output=True, text=True, timeout=10, env=env)
        return json.loads(result.stdout).get("universalArm") is True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def inherit_network(base, active, root):
    """Overlay operator networking without mutating an immutable generation."""
    config = json.loads(Path(active["config"]).read_text())
    config["listen"] = base["listen"]
    security = config.setdefault("security", {})
    for key in ("trustedProxies", "clientIpHeader", "requireTrustedProxy", "allowLanProxy"):
        if key in base.get("security", {}):
            security[key] = copy.deepcopy(base["security"][key])
        else:
            security.pop(key, None)
    path = root / "runtime-active.json"
    atomic_json(path, config)
    return dict(active, config=str(path))


def health_url(listen):
    host, port = listen.rsplit(":", 1)
    ip = ipaddress.ip_address(host.strip("[]"))
    if ip.is_unspecified:
        ip = ipaddress.ip_address("127.0.0.1" if ip.version == 4 else "::1")
    return f"http://{'[' + str(ip) + ']' if ip.version == 6 else ip}:{port}/healthz"


def ready(generation, child):
    config = json.loads(Path(generation["config"]).read_text())
    headers = {"CF-Connecting-IP": "127.0.0.1", "x-real-ip": "127.0.0.1",
               "x-ggfm-client-ip": "127.0.0.1"}
    if os.environ.get("GGFM_GATEWAY_KEY"):
        headers["x-ggfm-gateway-key"] = os.environ["GGFM_GATEWAY_KEY"]
    origin = config.get("security", {}).get("publicOrigin")
    if origin:
        headers["Host"] = origin.split("://", 1)[1]
    deadline = time.monotonic() + 1800
    while not STOP and time.monotonic() < deadline and child.poll() is None:
        try:
            request = urllib.request.Request(health_url(config["listen"]), headers=headers)
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
                status = json.loads(response.read(8192))
                expected_revision = generation.get("revision", 0) if "port" in generation else 0
                if status.get("ok") and (not expected_revision or status.get("androidVersion", {}).get("revision") == expected_revision):
                    return status
        except (OSError, ValueError):
            pass
        time.sleep(1)
    return False


def stop(child):
    if child and child.poll() is None:
        child.terminate()  # worker drains HTTP requests and its single heavy task
        child.wait(timeout=3600)


def activate(candidate, active, child, state, state_path, pair):
    """Publish only after prebuild and health; restore the old worker on failure.

    The caller has already durably reserved the version counter. Keep that
    reservation even when prebuild fails, but never advertise the failed pair.
    """
    candidate_child = None
    try:
        stop(child)
        env = child_env(candidate)
        env["GGFM_PREPARE_ONLY"] = "1"
        run([candidate["binary"]], env=env)
        if STOP:
            return active, child
        candidate_child = start(candidate)
        if not ready(candidate, candidate_child):
            raise RuntimeError("candidate failed readiness")
        published = dict(state, previous=active, active=candidate, pair=pair)
        atomic_json(state_path, published)
        state.clear()
        state.update(published)
        log(f"READY: deployment revision {candidate['revision']}; new downloads and update notice enabled")
        return candidate, candidate_child
    except Exception as error:
        log(f"Update not activated ({type(error).__name__}); restoring previous generation")
        stop(candidate_child)
        if child.poll() is not None and not STOP:
            child = start(active)
            if not ready(active, child):
                stop(child)
                raise RuntimeError("previous generation failed to restart") from error
        return active, child


def supports_blue_green(binary):
    try:
        result = subprocess.run([str(binary), "--network-capabilities"], capture_output=True,
                                text=True, check=True, timeout=10)
        return json.loads(result.stdout).get("blueGreen") is True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


class BlueGreen:
    """Stable ingress + at most two worker processes. Only the ingress reads
    public headers. Backends use private ports and an ephemeral shared secret.
    """
    def __init__(self, root, base, binary, settle=30, retain=780):
        self.root, self.base, self.binary = root, base, binary
        self.settle, self.retain = settle, retain
        self.routes = root / "routes.json"
        self.retired = None
        self.gateway = None
        self.legacy = None
        os.environ["GGFM_GATEWAY_KEY"] = secrets.token_hex(32)
        os.environ["GGFM_BUILD_LOCK"] = str(root / "heavy-build.lock")

    def backend(self, generation):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = json.loads(Path(generation["config"]).read_text())
        config["listen"] = f"127.0.0.1:{port}"
        config.setdefault("security", {}).update(trustedProxies=["127.0.0.1/32"],
            clientIpHeader="cf-connecting-ip", requireTrustedProxy=True, allowLanProxy=False)
        path = self.root / f"runtime-{generation['revision']}-{port}.json"
        atomic_json(path, config)
        return dict(generation, config=str(path), port=port)

    def publish(self, active, old=None):
        targets = {str(active["revision"]): active["port"]}
        if old:
            targets[str(old["revision"])] = old["port"]
        atomic_json(self.routes, {"active": active["revision"], "targets": targets,
                                  "legacy": self.legacy if str(self.legacy) in targets else None})

    def start_gateway(self, active):
        self.publish(active)
        path = self.root / "gateway-config.json"
        atomic_json(path, self.base)
        env = dict(os.environ, GGFM_PATCHER_CONFIG=str(path), GGFM_GATEWAY_ROUTES=str(self.routes))
        self.gateway = subprocess.Popen([str(self.binary), "--gateway"], env=env)

    def activate(self, candidate, active, child, state, state_path, pair):
        if not supports_blue_green(candidate["binary"]):
            log("Candidate lacks shared build lock/routing capability; retaining old worker")
            return active, child
        candidate = self.backend(candidate)
        new_child = None
        try:
            # Prebuild happens inside startup, under the cross-process lock.
            # The old process and its streamed downloads remain untouched.
            new_child = start(candidate)
            if not ready(candidate, new_child):
                raise RuntimeError("candidate failed readiness")
            deadline = time.monotonic() + self.settle
            while time.monotonic() < deadline:
                if STOP or new_child.poll() is not None:
                    raise RuntimeError("candidate exited during stabilization")
                # Do not accept a process which merely bound the port once.
                if not ready(candidate, new_child):
                    raise RuntimeError("candidate health became unstable")
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            if STOP:
                raise RuntimeError("shutdown requested before cutover")
            published = dict(state, previous=active, active=candidate, pair=pair)
            atomic_json(state_path, published)
            try:
                self.publish(candidate, active)
            except Exception:
                atomic_json(state_path, state)
                raise
            self.retired = (active, child, time.monotonic(), time.monotonic(), state.get("pair"))
            state.clear()
            state.update(published)
            log(f"READY: revision {candidate['revision']}; traffic switched after {self.settle}s stable health; old tokens retained")
            return candidate, new_child
        except Exception as error:
            log(f"Candidate rejected ({type(error).__name__}); old worker never stopped")
            stop(new_child)
            return active, child

    def maintain(self, active, child, state, state_path):
        if self.gateway.poll() is not None:
            raise RuntimeError("stable gateway exited")
        if child.poll() is not None:
            if not self.retired or self.retired[1].poll() is not None:
                raise RuntimeError("active worker exited without healthy rollback target")
            old, old_child, _, _, old_pair = self.retired
            self.publish(old)
            state.update(active=old, pair=old_pair)
            atomic_json(state_path, state)
            self.retired = None
            log("Active worker exited; traffic rolled back to retained worker")
            return old, old_child
        if self.retired:
            old, old_child, since, last_busy, old_pair = self.retired
            stats = self.routes.with_suffix(".stats.json")
            try:
                counts = json.loads(stats.read_text())
                fresh = time.time() - stats.stat().st_mtime < 5
                busy = counts.get(str(old["revision"]), 0) != 0
            except (OSError, ValueError):
                fresh, busy = False, True
            now = time.monotonic()
            if busy or not fresh:
                last_busy = now
            self.retired = (old, old_child, since, last_busy, old_pair)
            # Challenges live 180s, download tokens 600s; a long request may
            # finish later and issue another token. Keep 600 quiet seconds too.
            if fresh and not busy and now - since >= self.retain and now - last_busy >= 600:
                self.publish(active)
                stop(old_child)  # graceful drain is a final safety net
                self.retired = None
                log("Retired worker drained; expired token window closed")
        return active, child

    def close(self):
        stop(self.gateway)
        if self.retired:
            stop(self.retired[1])


def main():
    import fcntl
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--no-updates", action="store_true",
                        default=os.environ.get("GGFM_AUTO_UPDATE", "1") == "0",
                        help="keep supervising the active generation without polling releases")
    args = parser.parse_args()
    if sys.platform != "linux" or args.interval < 300:
        raise SystemExit("Linux only; minimum update interval is 300 seconds")
    os.umask(0o077)
    root = args.state.resolve()
    root.mkdir(parents=True, exist_ok=True)
    lock = (root / "supervisor.lock").open("a+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    base = load_native_overlay(args.config, json.loads(args.config.read_text()))
    identity = {"applicationId": base.get("applicationId"), "signer": base["signing"]["fingerprint"],
                "origin": base.get("security", {}).get("publicOrigin")}
    state_path = root / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"identity": identity, "counter": 0}
    if state["identity"] != identity:
        raise SystemExit("deployment identity changed; keep the original config, application ID and signing key")
    active = state.get("active") or {"config": str(args.config.resolve()), "binary": str(args.binary.resolve()), "revision": 0}
    active = inherit_network(base, active, root)
    log(f"Operator network config applied: listen={base['listen']}; LAN proxy={bool(base.get('security', {}).get('allowLanProxy'))}")
    def stopping(_signal, _frame):
        global STOP
        STOP = True
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    gateway_binary = args.binary.parent / "ggfm-gateway"
    if gateway_binary.is_file():
        if not os.access(gateway_binary, os.X_OK):
            gateway_binary.chmod(0o755)
        if not supports_blue_green(gateway_binary):
            raise RuntimeError("installed gateway is incompatible; restore the verified overlay binary")
    if not gateway_binary.is_file() and supports_blue_green(args.binary):
        gateway_binary = args.binary
    blue = BlueGreen(root, base, gateway_binary) if gateway_binary.is_file() and supports_blue_green(gateway_binary) else None
    if blue:
        if not supports_blue_green(active["binary"]):
            blue.legacy = active["revision"]
        active = blue.backend(active)
    child = start(active)
    try:
        initial = ready(active, child)
        if not initial:
            raise RuntimeError("initial worker failed readiness")
        state["counter"] = max(state["counter"], initial_revision(initial, active))
        # Include generations allocated just before a power loss/state-file commit.
        for path in (root / "generations").glob("*.json"):
            if path.stem.isdigit():
                state["counter"] = max(state["counter"], int(path.stem))
        state["active"] = active
        atomic_json(state_path, state)
        if blue:
            blue.start_gateway(active)
            log("Stable ingress enabled; updates keep old downloads online")
        next_check = 0
        while not STOP:
            if blue:
                active, child = blue.maintain(active, child, state, state_path)
            elif child.poll() is not None:
                raise RuntimeError("active worker exited; service manager may restart this supervisor")
            if not args.no_updates and time.monotonic() >= next_check:
                next_check = time.monotonic() + args.interval
                candidate_child = None
                try:
                    worker_release = release(WORKER, "ggfm-patcher-linux-x64.zip")
                    patch_release = release(PATCH, "ggfm-" + runtime_profile(base)[1] + ".zip")
                    pair = worker_release["asset"]["digest"] + "/" + patch_release["asset"]["digest"]
                    supplement_release = None
                    if base.get("universalArmv7Source"):
                        supplement_release = release(PATCH, "ggfm-patch-android-armv7.zip")
                        if supplement_release["commit"] != patch_release["commit"]:
                            raise ValueError("ARM release pair changed; retaining active generation")
                        pair += "/universal-arm-v1/" + supplement_release["asset"]["digest"]
                    if pair != state.get("pair") and not (blue and blue.retired):
                        log("Verified-release update found; staging immutable runtime")
                        candidate = stage(root, base, worker_release, patch_release, state["counter"], supplement_release)
                        state["counter"] = candidate["revision"]
                        atomic_json(state_path, state)  # never reuse an allocated Android version
                        log("Preparing update; signing identity is unchanged")
                        if blue:
                            active, child = blue.activate(candidate, active, child, state, state_path, pair)
                        else:
                            active, child = activate(candidate, active, child, state, state_path, pair)
                except Exception as error:
                    log(f"Update not activated ({type(error).__name__}); retaining previous generation")
                    if candidate_child is not None:
                        stop(candidate_child)
                    if child.poll() is not None and not STOP:
                        child = start(active)
                        if not ready(active, child):
                            raise RuntimeError("previous generation failed to restart")
            time.sleep(1)
    finally:
        if blue:
            blue.close()
        stop(child)
        lock.close()


if __name__ == "__main__":
    main()
