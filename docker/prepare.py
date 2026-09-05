"""Build-time tool installation and config generation. Never reads a game package."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request
import zipfile

BUNDLE = Path("/opt/ggfm/bundle")
PATCH = Path("/opt/ggfm/patch")
BUILD_TOOLS_URL = "https://dl.google.com/android/repository/build-tools_r35_linux.zip"
BUILD_TOOLS_SHA = "BD3A4966912EB8B30ED0D00B0CDA6B6543B949D5FFE00BEA54C04C81E1561D88"
APKTOOL_URL = "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar"
APKTOOL_SHA = "DBF930B076C6B9BE08D57C449CACEFC3BDD6B71EBD59B3066FC0E1F5B14F9423"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest().upper()


def fetch(url, destination, sha):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=120) as response, destination.open("xb") as stream:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 128 * 1024**2:
                raise ValueError("tool download exceeds limit")
            stream.write(chunk)
    if digest(destination) != sha:
        raise ValueError(f"tool digest mismatch: {destination.name}")


def make_config(lock, dependencies, manifest, patch=PATCH, bundle=BUNDLE):
    def file_sha(name):
        return manifest["files"][name]["sha256"]
    if file_sha("libggfm_server.so") != dependencies["server"]["sha256"]:
        raise ValueError("Server does not match Patch dependency")
    if dependencies["policySha256"] != lock["policySha256"]:
        raise ValueError("policy mismatch")
    return {
        "listen": "127.0.0.1:8081",
        "security": {"publicOrigin": "https://patch.example.org",
                     "trustedProxies": ["127.0.0.1/32", "::1/128"],
                     "clientIpHeader": "cf-connecting-ip", "requireTrustedProxy": True},
        "compatibilityManifest": str(patch / "compatibility/8.0.0.json"),
        "cacheRoot": "/data/cache", "workRoot": "/data/work",
        "tools": {"java": "/usr/bin/java", "apktoolJar": "/opt/ggfm/tools/apktool.jar",
                  "python": "/opt/ggfm/venv/bin/python",
                  **{name: f"/opt/android-sdk/android-15/{name}"
                     for name in ("aapt2", "zipalign", "apksigner")}},
        "artifacts": {
            "patchRoot": str(patch),
            "bootstrapDex": str(bundle / "classes.dex"), "bootstrapDexSha256": file_sha("classes.dex"),
            "bootstrapSo": str(bundle / "libggfm_bootstrap.so"), "bootstrapSoSha256": file_sha("libggfm_bootstrap.so"),
            "dobbySo": str(bundle / "libdobby.so"), "dobbySha256": file_sha("libdobby.so"),
            "serverSo": str(bundle / "libggfm_server.so"), "serverSha256": file_sha("libggfm_server.so"),
            "policyManifest": str(patch / "policy/memorial-policy.v1.json"),
            "policySha256": lock["policySha256"]},
        "signing": {"keystore": "/data/signing/memorial.p12", "alias": "memorial",
                    "storePasswordEnv": "GGFM_KEYSTORE_PASSWORD", "keyPasswordEnv": "GGFM_KEY_PASSWORD",
                    "fingerprint": "SET_AT_CONTAINER_START"},
        "versions": {"patchCommit": lock["patchCommit"], "patchVersion": lock["patchCommit"],
                     "serverVersion": dependencies["server"]["sourceCommit"], "serverAbi": 1},
        "prebuilt": {"operatorSourceXapk": "/input/original.xapk"},
    }


def main():
    manifest = json.loads((BUNDLE / "release-manifest.json").read_text())
    for path in BUNDLE.iterdir():
        if path.name == "release-manifest.json":
            continue
        expected = manifest["files"][path.name]
        if path.stat().st_size != expected["size"] or digest(path) != expected["sha256"]:
            raise ValueError(f"release member mismatch: {path.name}")
    lock = json.loads((BUNDLE / "docker-lock.json").read_text())
    commit = lock["patchCommit"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("invalid Patch commit")
    subprocess.run(["git", "init", str(PATCH)], check=True)
    subprocess.run(["git", "-C", str(PATCH), "remote", "add", "origin",
                    "https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patch.git"], check=True)
    subprocess.run(["git", "-C", str(PATCH), "fetch", "--depth", "1", "origin", commit], check=True)
    subprocess.run(["git", "-C", str(PATCH), "checkout", "--detach", commit], check=True)
    actual = subprocess.check_output(["git", "-C", str(PATCH), "rev-parse", "HEAD"], text=True).strip()
    if actual != commit or digest(PATCH / "policy/memorial-policy.v1.json") != lock["policySha256"]:
        raise ValueError("Patch source/policy mismatch")
    dependencies = json.loads((BUNDLE / "dependencies.json").read_text())
    config = make_config(lock, dependencies, manifest)
    Path("/opt/ggfm/config.template.json").write_text(json.dumps(config, indent=2))
    for name in ("ggfm-patcher", "ggfm-patcher-web"):
        (BUNDLE / name).chmod(0o755)
    version = json.loads(subprocess.check_output([str(BUNDLE / "ggfm-patcher"), "version"], text=True))
    if version != manifest["androidVersion"]:
        raise ValueError("compiled Android version mismatch")
    Path("/opt/ggfm/bin").mkdir()
    for name in ("ggfm-patcher", "ggfm-patcher-web"):
        (Path("/opt/ggfm/bin") / name).symlink_to(BUNDLE / name)
    fetch(APKTOOL_URL, Path("/opt/ggfm/tools/apktool.jar"), APKTOOL_SHA)
    archive = Path("/opt/ggfm/tools/build-tools.zip")
    fetch(BUILD_TOOLS_URL, archive, BUILD_TOOLS_SHA)
    target = Path("/opt/android-sdk")
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            path = target / item.filename
            if not path.resolve().is_relative_to(target.resolve()):
                raise ValueError("unsafe Android tool archive")
        z.extractall(target)
    for name in ("aapt2", "zipalign", "apksigner"):
        (target / "android-15" / name).chmod(0o755)
    print(f"Docker tools ready; Android {version['versionName']}")


if __name__ == "__main__":
    main()
