#!/usr/bin/env python3
"""Fail closed on prohibited material in the exact Git index and reachable history.

This is a distribution guard, not a substitute for provenance review.
Run after staging and before publishing. It never changes files.
"""
from __future__ import annotations
import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ALLOWED_SUFFIXES = {".rs", ".toml", ".lock", ".json", ".md", ".txt", ".h", ".hpp",
                    ".cpp", ".c", ".java", ".py", ".mjs", ".html", ".kts", ".xml",
                    ".yml", ".yaml", ".sh", ".ps1", ".sql"}
ALLOWED_NAMES = {"LICENSE", "NOTICE", "CMakeLists.txt", ".gitignore", ".gitmodules",
                 ".gitattributes", "Dockerfile"}
FORBIDDEN_PARTS = {"reverse", "split_extract", "analysis", "captures", "saves",
                   "operator-source", "uploads", "cache", "target", "__pycache__"}
FORBIDDEN_NAMES = {"dump.cs", "script.json", "global-metadata.dat", "master.sqlite"}
MAX_SOURCE = 4 * 1024 * 1024
PATTERNS = [
    ("private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub credential", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("decompiled function", re.compile(rb"\b(?:__fast" rb"call|JUMP" rb"OUT|IL2CPP_" rb"Throw)\b")),
    ("IL2CPP dump", re.compile(rb"(?m)^\s*//\s*(?:RVA:|TypeDefIndex:)")),
    ("disassembly listing", re.compile(rb"(?m)^\s*(?:0x)?[0-9a-fA-F]{8,16}:\s+[0-9a-fA-F]{2}\s")),
]
MAGIC = (b"PK\x03\x04", b"\x7fELF", b"dex\n", b"MZ", b"SQLite format 3", b"UnityFS")

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])

def check_path(name):
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or any(x.lower() in FORBIDDEN_PARTS for x in p.parts):
        return "private/generated directory"
    if p.name.lower() in FORBIDDEN_NAMES:
        return "proprietary input"
    if p.name not in ALLOWED_NAMES and p.suffix not in ALLOWED_SUFFIXES:
        return "unapproved file type"
    return None

def check_blob(data):
    if data.startswith(MAGIC) or b"\x00" in data:
        return "binary content"
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "non-UTF-8 content"
    for label, pattern in PATTERNS:
        if pattern.search(data):
            return label
    return None

def scan(root, history):
    errors, checked = [], set()
    entries = []
    for record in git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, oid, stage = meta.decode().split()
        name = path.decode()
        if stage != "0":
            errors.append(f"{name}: unresolved merge")
        if mode == "160000":
            if name != "patch":
                errors.append(f"{name}: unexpected submodule")
            continue
        if mode not in {"100644", "100755"}:
            errors.append(f"{name}: links and special files are forbidden")
        entries.append((oid.decode() if isinstance(oid, bytes) else oid, name))
    if history:
        for line in git(root, "rev-list", "--objects", "--all").decode().splitlines():
            oid, _, name = line.partition(" ")
            if git(root, "cat-file", "-t", oid).strip() == b"blob":
                entries.append((oid, name))
    if not entries:
        errors.append("empty index; stage explicit reviewed paths before scanning")
    for oid, name in entries:
        problem = check_path(name)
        if problem:
            errors.append(f"{name}: {problem}")
        if oid in checked:
            continue
        checked.add(oid)
        size = int(git(root, "cat-file", "-s", oid))
        if size > MAX_SOURCE:
            errors.append(f"{name}: source blob exceeds {MAX_SOURCE} bytes")
            continue
        problem = check_blob(git(root, "cat-file", "blob", oid))
        if problem:
            errors.append(f"{name}: {problem}")
    return errors, len(checked)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    errors, count = scan(root, args.history)
    for message in sorted(set(errors)):
        print("BLOCKED:", message, file=sys.stderr)
    print(f"Reviewed {count} distinct source blobs; {len(set(errors))} finding(s).")
    raise SystemExit(bool(errors))

if __name__ == "__main__":
    main()
