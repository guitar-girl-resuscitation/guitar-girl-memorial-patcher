#!/usr/bin/env python3
"""Explicit, non-destructive Android install/cold-start release smoke test."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import tempfile
import time
import zipfile


PACKAGE = "org.guitargirlresuscitation.memorial"


def run(adb: str, serial: str, *arguments: str, capture: bool = False) -> str:
    command = [adb, "-s", serial, *arguments]
    completed = subprocess.run(
        command,
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE if capture else None,
    )
    return completed.stdout.strip() if capture else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("xapk", type=pathlib.Path)
    parser.add_argument("--serial", required=True, help="exact adb device serial")
    parser.add_argument("--package", default=PACKAGE, help="exact verified output application ID")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--no-streaming", action="store_true",
                        help="stage splits before package installation on flaky wireless ADB")
    parser.add_argument("--settle-seconds", type=int, default=12)
    arguments = parser.parse_args()
    package = arguments.package
    import re
    if not re.fullmatch(r"org\.guitargirlresuscitation\.memorial(?:\.[a-z][a-z0-9_]*)*", package):
        parser.error("unexpected memorial application ID")
    if not arguments.xapk.is_file():
        parser.error("XAPK does not exist")
    if not 1 <= arguments.settle_seconds <= 60:
        parser.error("--settle-seconds must be between 1 and 60")

    with tempfile.TemporaryDirectory(prefix="ggfm-smoke-") as temporary:
        root = pathlib.Path(temporary)
        with zipfile.ZipFile(arguments.xapk) as archive:
            names = [name for name in archive.namelist() if name.endswith(".apk")]
            if len(names) != 3 or any(pathlib.PurePosixPath(name).name != name for name in names):
                raise SystemExit("expected exactly three root-level APK splits")
            apks = []
            for name in names:
                output = root / name
                with archive.open(name) as source, output.open("xb") as destination:
                    while block := source.read(1024 * 1024):
                        destination.write(block)
                apks.append(output)

        install_options = ["--no-streaming"] if arguments.no_streaming else []
        run(arguments.adb, arguments.serial, "install-multiple", "-r", *install_options, *map(str, apks))
        paths = run(
            arguments.adb, arguments.serial, "shell", "pm", "path", package, capture=True
        ).splitlines()
        if len(paths) != 3 or any(not line.startswith("package:") for line in paths):
            raise SystemExit(f"unexpected installed split set: {paths!r}")
        run(arguments.adb, arguments.serial, "shell", "am", "force-stop", package)
        run(
            arguments.adb,
            arguments.serial,
            "shell",
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        )
        time.sleep(arguments.settle_seconds)
        pid = run(arguments.adb, arguments.serial, "shell", "pidof", package, capture=True)
        if not pid:
            raise SystemExit("memorial process did not survive cold start")
        print(f"smoke test passed: {package} pid={pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
