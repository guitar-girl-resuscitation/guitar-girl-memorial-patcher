"""Resource-free deployment bootstrap; optional original package is a read-only mount."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
import urllib.request
from urllib.parse import urlsplit

DATA = Path("/data")
CONFIG = DATA / "runtime/patcher.json"
stopping = False


def validate_signing_files(keystore, password_file, identity_file):
    # A partially lost data volume must never silently create a new signer.
    if not keystore.exists() and (password_file.exists() or identity_file.exists()):
        raise RuntimeError("signing keystore missing; restore the original key, do not regenerate")
    if keystore.exists() and not password_file.exists():
        raise RuntimeError("signing password missing; restore the data volume, do not regenerate a key")


def log(message):
    print(f"[GGFM] {message}", flush=True)


def run(arguments, env=None):
    subprocess.run(arguments, env=env, check=True, timeout=120,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def valid_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.path
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("GGFM_PUBLIC_ORIGIN must be https://your-host without a trailing slash")
    return value


def health(config):
    request = urllib.request.Request("http://127.0.0.1:8081/healthz", headers={
        "Host": urlsplit(config["security"]["publicOrigin"]).netloc,
        "CF-Connecting-IP": "127.0.0.1",
    })
    with urllib.request.urlopen(request, timeout=2) as response:
        if not json.load(response).get("ok"):
            raise RuntimeError("patcher is not ready")


def main():
    global stopping
    os.umask(0o077)
    origin = valid_origin(os.environ.get("GGFM_PUBLIC_ORIGIN", ""))
    for directory in [DATA / name for name in ("tmp", "work", "cache", "signing", "runtime")]:
        directory.mkdir(parents=True, exist_ok=True)
    # The lock remains held while the server and all patch subprocesses run.
    with (DATA / "instance.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config = json.loads(Path("/opt/ggfm/config.template.json").read_text())
        config["listen"] = "127.0.0.1:8081"
        config["security"]["publicOrigin"] = origin
        config["cacheRoot"] = str(DATA / "cache")
        config["workRoot"] = str(DATA / "work")
        config["prebuilt"]["operatorSourceXapk"] = "/input/original.xapk"
        config["artifacts"]["patchRoot"] = "/opt/ggfm/patch"
        password_file = DATA / "signing/password"
        keystore = DATA / "signing/memorial.p12"
        identity_file = DATA / "signing/identity.json"
        validate_signing_files(keystore, password_file, identity_file)
        if not password_file.exists():
            with password_file.open("x") as stream:
                stream.write(secrets.token_urlsafe(48))
        password = password_file.read_text().strip()
        if not password:
            raise RuntimeError("empty signing password; refusing replacement")
        env = dict(os.environ, GGFM_KEYSTORE_PASSWORD=password, GGFM_KEY_PASSWORD=password)
        if not keystore.exists():
            log("Creating this deployment's signing identity in /data/signing")
            run(["keytool", "-genkeypair", "-keystore", str(keystore), "-storetype", "PKCS12",
                 "-alias", "memorial", "-keyalg", "RSA", "-keysize", "3072", "-validity", "36500",
                 "-dname", "CN=Guitar Girl Memorial Self Hosted", "-storepass:env", "GGFM_KEYSTORE_PASSWORD",
                 "-keypass:env", "GGFM_KEY_PASSWORD"], env)
        certificate = DATA / "runtime/certificate.der"
        run(["keytool", "-exportcert", "-keystore", str(keystore), "-alias", "memorial",
             "-storepass:env", "GGFM_KEYSTORE_PASSWORD", "-file", str(certificate)], env)
        fingerprint = hashlib.sha256(certificate.read_bytes()).hexdigest().upper()
        app_id = os.environ.get("GGFM_APPLICATION_ID") or (
            "org.guitargirlresuscitation.memorial.selfhosted.k" + fingerprint[:12].lower())
        if not re.fullmatch(r"org\.guitargirlresuscitation\.memorial\.[a-z][a-z0-9_.]*", app_id):
            raise ValueError("GGFM_APPLICATION_ID must be a memorial self-hosted package suffix")
        identity = {"applicationId": app_id, "fingerprint": fingerprint}
        if identity_file.exists():
            if json.loads(identity_file.read_text()) != identity:
                raise RuntimeError("signing identity/application ID changed; preserve the existing data volume")
        else:
            with identity_file.open("x") as stream:
                json.dump(identity, stream)
        config["applicationId"] = app_id
        config["signing"]["keystore"] = str(keystore)
        config["signing"]["fingerprint"] = fingerprint
        temporary = CONFIG.with_suffix(".tmp")
        temporary.write_text(json.dumps(config, indent=2))
        os.replace(temporary, CONFIG)
        env["GGFM_PATCHER_CONFIG"] = str(CONFIG)
        log("Starting patcher; /input/original.xapk is optional. A valid original is prepared once before READY.")
        children = []

        def terminate(_signum, _frame):
            global stopping
            stopping = True

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        try:
            server = subprocess.Popen(["/opt/ggfm/venv/bin/python", "/opt/ggfm/docker/run_managed.py",
                "--config", str(CONFIG), "--binary", "/opt/ggfm/bin/ggfm-patcher-web",
                "--state", str(DATA / "updates")], env=env, start_new_session=True)
            children.append(server)
            deadline = time.monotonic() + 3600
            while not stopping:
                if server.poll() is not None:
                    raise RuntimeError(f"Patcher startup failed (exit {server.returncode}); see preceding logs")
                if time.monotonic() >= deadline:
                    raise RuntimeError("Initial preparation exceeded one hour")
                try:
                    health(config)
                    break
                except (OSError, ValueError, RuntimeError):
                    time.sleep(2)
            if not stopping:
                # Transport-only relay: Rust still accepts only loopback peers.
                # Publish this port to HOST LOOPBACK, behind the operator's proxy.
                relay = subprocess.Popen(["socat", "TCP-LISTEN:8080,reuseaddr,fork,max-children=40",
                                          "TCP:127.0.0.1:8081"], start_new_session=True)
                children.append(relay)
                log(f"READY: port 8080; cached output reused on restart; applicationId={app_id}")
                while not stopping:
                    if any(child.poll() is not None for child in children):
                        raise RuntimeError("A service process exited; stopping the container")
                    time.sleep(1)
        finally:
            for child in children:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
            for child in children:
                try:
                    child.wait(timeout=3600)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        # Never echo signing passwords or raw subprocess arguments.
        log(f"Tool failed: {Path(error.cmd[0]).name}, exit={error.returncode}")
        raise SystemExit(1)
