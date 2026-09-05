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
    commit = subprocess.check_output(["git", "-C", str(ROOT / "patch"), "rev-parse", "HEAD"], text=True).strip()
    dependencies = json.loads((runtime / "dependencies.json").read_text())
    policy = digest(ROOT / "patch/policy/memorial-policy.v1.json")
    if policy != dependencies["policySha256"] or digest(runtime / "libggfm_server.so") != dependencies["server"]["sha256"]:
        raise ValueError("Docker runtime pair/policy mismatch")
    server_archive = runtime / "ggfm-server-android-arm64.zip"
    metadata = verify_archive(server_archive)
    if metadata["sourceCommit"] != dependencies["server"]["sourceCommit"]:
        raise ValueError("Server source mismatch")
    notice = work / "THIRD_PARTY_TERMINAL_FONT.md"
    with zipfile.ZipFile(server_archive) as z:
        notice.write_bytes(z.read("THIRD_PARTY_TERMINAL_FONT.md"))
    lock = work / "docker-lock.json"
    lock.write_text(json.dumps({"schema": 1, "patchCommit": commit, "policySha256": policy}, indent=2))
    files = {name: ROOT / "docker" / name for name in ("Dockerfile", "prepare.py", "entrypoint.py", "healthcheck.py")}
    files.update({name: runtime / name for name in ("classes.dex", "libggfm_bootstrap.so", "libdobby.so",
                                                   "libggfm_server.so", "dependencies.json", "DOBBY-LICENSE")})
    files.update({name: ROOT / "target/release" / name for name in ("ggfm-patcher", "ggfm-patcher-web")})
    files.update({"docker-lock.json": lock, "THIRD_PARTY_TERMINAL_FONT.md": notice,
                  "README.md": ROOT / "docker/README.md", "README.zh-CN.md": ROOT / "docker/README.zh-CN.md",
                  "VERSIONING.md": ROOT / "docs/VERSIONING.md"})
    pack("patcher-docker-linux-amd64", [f"{name}={path}" for name, path in files.items()], ROOT / "dist")
    # Exact allowlisted archive just verified by pack; no user-supplied ZIP.
    with zipfile.ZipFile(ROOT / "dist/ggfm-patcher-docker-linux-amd64.zip") as z:
        z.extractall(work)


if __name__ == "__main__":
    main()
