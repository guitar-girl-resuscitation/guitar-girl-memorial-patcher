#!/usr/bin/env python3
"""Allowlisted build archives and exact-source GitHub Releases. No game inputs."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

KINDS = {
    "server-android-arm64": {"libggfm_server.so", "ggfm_server.h", "memorial-policy.json", "THIRD_PARTY_TERMINAL_FONT.md"},
    "server-linux-x64": {"ggfm-server", "ggfm_server.h", "memorial-policy.json", "THIRD_PARTY_TERMINAL_FONT.md"},
    "server-windows-x64": {"ggfm-server.exe", "ggfm_server.h", "memorial-policy.json", "THIRD_PARTY_TERMINAL_FONT.md"},
    "patch-android-arm64": {"classes.dex", "libggfm_bootstrap.so", "libdobby.so", "memorial-policy.v1.json", "DOBBY-LICENSE", "dependencies.json"},
    "patcher-linux-x64": {"ggfm-patcher", "ggfm-patcher-web", "patcher.example.json", "DEPLOYMENT.md", "PUBLIC_DEPLOYMENT.md", "VERSIONING.md", "deploy/cloudflared.yml", "deploy/ggfm-patcher.service"},
    "patcher-windows-x64": {"ggfm-patcher.exe", "ggfm-patcher-web.exe", "patcher.example.json", "DEPLOYMENT.md", "PUBLIC_DEPLOYMENT.md", "VERSIONING.md", "deploy/cloudflared.yml", "deploy/ggfm-patcher.service"},
}
ROOT = Path(__file__).resolve().parents[1]


def validate_android_version(value, expected_revision=None):
    revision = value.get("revision")
    if type(revision) is not int or not 1 <= revision <= 2_099_200_000:
        raise ValueError("invalid Android release revision")
    if value != {"revision": revision, "versionCode": 800_000 + revision,
                 "versionName": f"8.0.0-memorial.{revision}"}:
        raise ValueError("inconsistent Android release identity")
    if expected_revision is not None and revision != int(expected_revision):
        raise ValueError("compiled Android revision differs from release workflow")
    return value


def newer_android_release_exists(releases, version_code):
    for release in releases:
        previous = re.search(r"(?m)^Android versionCode: ([0-9]+)$", release.get("body") or "")
        if previous and int(previous[1]) > version_code:
            return True
    return False

def output(*args):
    return subprocess.check_output(list(args), cwd=ROOT, text=True).strip()

def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest().upper()

def pack(kind, files, destination):
    commit = output("git", "rev-parse", "HEAD")
    if output("git", "status", "--porcelain", "--untracked-files=no"):
        raise SystemExit("refusing to label a dirty tracked tree as an exact-source release")
    members = {}
    for item in files:
        name, source = item.split("=", 1)
        if name in members:
            raise SystemExit("duplicate member")
        members[name] = Path(source).resolve()
    if set(members) != KINDS[kind]:
        raise SystemExit(f"exact members required: {sorted(KINDS[kind])}")
    members["LICENSE"] = ROOT / "LICENSE"
    for path in members.values():
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"not a regular build input: {path.name}")
    metadata = {
        "schema": 1, "kind": kind, "sourceCommit": commit,
        "repository": output("git", "config", "--get", "remote.origin.url"),
        "serverAbi": 1,
        "files": {name: {"sha256": digest(path), "size": path.stat().st_size}
                  for name, path in sorted(members.items())},
    }
    if kind.startswith("patcher-"):
        executable = members["ggfm-patcher.exe" if "windows" in kind else "ggfm-patcher"]
        metadata["androidVersion"] = validate_android_version(
            json.loads(output(str(executable), "version")),
            os.environ.get("GGFM_BUILD_REVISION"))
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f"ggfm-{kind}.zip"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name, path in sorted(members.items()):
            z.write(path, name)
        z.writestr("release-manifest.json", json.dumps(metadata, indent=2) + "\n")
    verify_archive(archive, commit)
    checksum = archive.with_suffix(".zip.sha256")
    with checksum.open("x", encoding="ascii") as stream:
        stream.write(f"{digest(archive)}  {archive.name}\n")
    print(f"Verified {archive.name}; source={commit}; sha256={digest(archive)}")

def verify_archive(path, commit=None):
    with zipfile.ZipFile(path) as z:
        if len(z.infolist()) > 16 or sum(i.file_size for i in z.infolist()) > 256 * 1024**2:
            raise ValueError("unexpected archive size")
        names = z.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate archive entries")
        metadata = json.loads(z.read("release-manifest.json"))
        allowed = KINDS[metadata["kind"]] | {"LICENSE", "release-manifest.json"}
        if set(names) != allowed or set(metadata["files"]) != allowed - {"release-manifest.json"}:
            raise ValueError("release contains an unapproved entry")
        if not re.fullmatch(r"[a-f0-9]{40}", metadata["sourceCommit"]):
            raise ValueError("invalid source commit")
        if commit and metadata["sourceCommit"] != commit:
            raise ValueError("release built from a different commit")
        if metadata["kind"].startswith("patcher-"):
            validate_android_version(metadata.get("androidVersion", {}))
        for name, entry in metadata["files"].items():
            with z.open(name) as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest().upper()
            if actual != entry["sha256"] or z.getinfo(name).file_size != entry["size"]:
                raise ValueError("member digest/size mismatch")
    return metadata

def publish(directory, tag):
    repo = os.environ["GITHUB_REPOSITORY"]
    commit = os.environ["GITHUB_SHA"]
    if commit != output("git", "rev-parse", "HEAD"):
        raise SystemExit("workflow checkout does not match triggering source")
    assets = sorted(directory.glob("*.zip"))
    if not assets:
        raise SystemExit("no compiled artifacts")
    android_version = None
    for archive in assets:
        metadata = verify_archive(archive, commit)
        if metadata["kind"].startswith("patcher-"):
            version = validate_android_version(metadata["androidVersion"], os.environ["GGFM_BUILD_REVISION"])
            if android_version is not None and version != android_version:
                raise SystemExit("release archives disagree on Android version")
            android_version = version
        if archive.with_suffix(".zip.sha256").read_text(encoding="ascii").split()[0] != digest(archive):
            raise SystemExit("archive checksum mismatch")
    flags = []
    if tag == "nightly":
        # Obsolete queued runs must never replace the current Nightly.
        head = json.loads(output("gh", "api", f"repos/{repo}/commits/main"))["sha"]
        if head != commit:
            print("Skipping obsolete Nightly: main advanced after this build.")
            return
        # Only this explicitly replaceable release is ever deleted.
        releases = json.loads(output("gh", "api", f"repos/{repo}/releases?per_page=100"))
        # A re-run of an older workflow on the same commit must not downgrade
        # the current Nightly. Compare our machine-readable published code.
        if android_version and newer_android_release_exists(releases, android_version["versionCode"]):
            print("Skipping obsolete Nightly: a higher Android version is already published.")
            return
        if any(r["tag_name"] == "nightly" for r in releases):
            subprocess.run(["gh", "release", "delete", "nightly", "--repo", repo,
                            "--yes", "--cleanup-tag"], check=True, cwd=ROOT)
        flags = ["--prerelease", "--latest=false"]
    elif not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?", tag):
        raise SystemExit("unsupported immutable release tag")
    else:
        flags = ["--verify-tag"]
    notes = ("Unofficial preservation tooling. No game package, game assets, "
             "decompiled code, saves or signing keys are included.\n\n"
             f"Exact source: {commit}\nEach archive includes a file-level SHA-256 manifest. "
             "Obtain the original game separately; these archives are not installable game packages.")
    if android_version:
        notes += (f"\n\nAndroid versionCode: {android_version['versionCode']}\n"
                  f"Android versionName: {android_version['versionName']}\n"
                  "Keep the deployment signing key and application ID for in-place updates.")
    subprocess.run(["gh", "release", "create", tag, "--repo", repo, "--target", commit,
                    "--title", "Nightly" if tag == "nightly" else tag, "--notes", notes,
                    *flags, *map(str, assets),
                    *[str(a.with_suffix(".zip.sha256")) for a in assets]], check=True, cwd=ROOT)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pack")
    p.add_argument("--kind", choices=KINDS, required=True)
    p.add_argument("--file", action="append", required=True)
    p.add_argument("--output", type=Path, default=ROOT / "dist")
    v = sub.add_parser("verify")
    v.add_argument("archive", type=Path)
    r = sub.add_parser("publish")
    r.add_argument("--directory", type=Path, default=ROOT / "dist")
    r.add_argument("--tag", required=True)
    args = parser.parse_args()
    if args.command == "pack":
        pack(args.kind, args.file, args.output)
    elif args.command == "verify":
        print(json.dumps(verify_archive(args.archive), indent=2))
    else:
        publish(args.directory, args.tag)

if __name__ == "__main__":
    main()
