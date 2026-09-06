#!/usr/bin/env python3
"""Pin the Patch submodule to a successfully published, verified upstream build."""
import json
from pathlib import Path
import subprocess
import tempfile
from release_artifacts import digest, verify_archive

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "guitar-girl-resuscitation/guitar-girl-memorial-patch"
EXPECTED_URL = f"https://github.com/{UPSTREAM}.git"

def out(*args):
    return subprocess.check_output(list(args), cwd=ROOT, text=True).strip()

def run(*args):
    subprocess.run(list(args), cwd=ROOT, check=True)

def main():
    if out("git", "status", "--porcelain"):
        raise SystemExit("update requires a clean checkout")
    url = out("git", "config", "-f", ".gitmodules", "--get", "submodule.patch.url")
    if url != EXPECTED_URL:
        raise SystemExit("unexpected Patch submodule remote")
    release = json.loads(out("gh", "api", f"repos/{UPSTREAM}/releases/tags/nightly"))
    asset = next(a for a in release["assets"] if a["name"] == "ggfm-patch-android-arm64.zip")
    with tempfile.TemporaryDirectory(prefix="ggfm-upstream-") as work:
        archive = Path(work) / asset["name"]
        with archive.open("xb") as stream:
            subprocess.run(["gh", "api", f"repos/{UPSTREAM}/releases/assets/{asset['id']}",
                            "-H", "Accept: application/octet-stream"], stdout=stream, check=True)
        if asset.get("digest") != "sha256:" + digest(archive).lower():
            raise SystemExit("upstream asset digest mismatch")
        metadata = verify_archive(archive)
        import zipfile
        with zipfile.ZipFile(archive) as packed:
            dependencies = json.loads(packed.read("dependencies.json"))
        commit = metadata["sourceCommit"]
        if metadata["kind"] != "patch-android-arm64" or release["target_commitish"] != commit:
            raise SystemExit("upstream artifact is not built from the release target")
        lock = {"schema": 1, "repository": UPSTREAM, "commit": commit,
                "releaseId": release["id"], "assetId": asset["id"],
                "archiveSha256": digest(archive)}
        server_commit = dependencies["server"]["sourceCommit"]
        lock.update(serverCommit=server_commit,
            patchUpdatedAt=json.loads(out("gh", "api", f"repos/{UPSTREAM}/git/commits/{commit}"))["committer"]["date"],
            serverUpdatedAt=json.loads(out("gh", "api", f"repos/guitar-girl-resuscitation/guitar-girl-memorial-server/git/commits/{server_commit}"))["committer"]["date"])
    run("git", "-C", "patch", "fetch", "--depth", "1", "origin", commit)
    run("git", "-C", "patch", "checkout", "--detach", commit)
    # This script is the explicitly authorized automated pin update. Never
    # changes application code or incorporates game inputs.
    (ROOT / "config/upstream-patch.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    run("git", "add", "--", "patch", "config/upstream-patch.json")
    print(f"Verified Patch commit {commit}")

if __name__ == "__main__":
    main()
