"""Fetch a complete verified GitHub Patch/Server pair, without native compilation."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("managed", ROOT / "deploy/run_managed.py")
managed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(managed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing an existing runtime output")
    selected = managed.release(managed.PATCH, "ggfm-patch-android-arm64.zip")
    managed.download(selected, args.output, managed.PATCH_FILES, "patch-android-arm64")
    managed.verify_runtime(args.output)
    (args.output / "runtime-lock.json").write_text(json.dumps({"patchCommit": selected["commit"],
        "archiveSha256": selected["asset"]["digest"].split(":")[1]}, indent=2))
    print("Verified precompiled runtime: " + selected["commit"])


if __name__ == "__main__":
    main()
