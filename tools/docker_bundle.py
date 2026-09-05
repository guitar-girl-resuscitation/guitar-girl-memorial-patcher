"""Package an explicit resource-free Docker context from this CI build."""
import argparse
import json
from pathlib import Path
import subprocess
import zipfile

from release_artifacts import ROOT, digest, pack, verify_archive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    work = ROOT / "build/docker-context"
    work.mkdir(parents=True, exist_ok=False)
    runtime_lock = json.loads((runtime / "runtime-lock.json").read_text())
    commit = runtime_lock["patchCommit"]
    dependencies = json.loads((runtime / "dependencies.json").read_text())
    policy = digest(runtime / "memorial-policy.v1.json")
    if policy != dependencies["policySha256"] or digest(runtime / "libggfm_server.so") != dependencies["server"]["sha256"]:
        raise ValueError("Docker runtime pair/policy mismatch")
    if digest(runtime / "release.zip").lower() != runtime_lock["archiveSha256"]:
        raise ValueError("Runtime archive changed")
    metadata = verify_archive(runtime / "release.zip")
    if metadata["sourceCommit"] != commit:
        raise ValueError("Runtime source mismatch")
    notice = runtime / "THIRD_PARTY_TERMINAL_FONT.md"
    lock = work / "docker-lock.json"
    lock.write_text(json.dumps({"schema": 1, "patchCommit": commit, "policySha256": policy}, indent=2))
    files = {name: ROOT / "docker" / name for name in ("Dockerfile", "prepare.py", "entrypoint.py", "healthcheck.py")}
    files.update({name: runtime / name for name in ("classes.dex", "libggfm_bootstrap.so", "libdobby.so",
                                                   "libggfm_server.so", "dependencies.json", "DOBBY-LICENSE")})
    files.update({name: ROOT / "target/release" / name for name in ("ggfm-patcher", "ggfm-patcher-web")})
    files.update({"docker-lock.json": lock, "THIRD_PARTY_TERMINAL_FONT.md": notice,
                  "run_managed.py": ROOT / "deploy/run_managed.py",
                  "README.md": ROOT / "docker/README.md", "README.zh-CN.md": ROOT / "docker/README.zh-CN.md",
                  "VERSIONING.md": ROOT / "docs/VERSIONING.md"})
    pack("patcher-docker-linux-amd64", [f"{name}={path}" for name, path in files.items()], ROOT / "dist")
    # Exact allowlisted archive just verified by pack; no user-supplied ZIP.
    with zipfile.ZipFile(ROOT / "dist/ggfm-patcher-docker-linux-amd64.zip") as z:
        z.extractall(work)


if __name__ == "__main__":
    main()
