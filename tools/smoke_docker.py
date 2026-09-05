"""CI-only isolated container smoke test; no game package, host mounts or player data."""
import json
import subprocess
import sys
import time
import urllib.request


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def main(image):
    cid = output("docker", "run", "--rm", "-d", "--cpus", "2", "--memory", "4g",
                 "--pids-limit", "160", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "-p", "127.0.0.1::8080", "-e", "GGFM_PUBLIC_ORIGIN=https://patch.example.org", image)
    try:
        endpoint = "http://" + output("docker", "port", cid, "8080/tcp") + "/healthz"

        def ready():
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    request = urllib.request.Request(endpoint, headers={"Host": "patch.example.org",
                                                                         "CF-Connecting-IP": "127.0.0.1"})
                    with urllib.request.urlopen(request, timeout=2) as response:
                        return json.load(response)
                except (OSError, ValueError):
                    if output("docker", "inspect", "--format", "{{.State.Running}}", cid) != "true":
                        raise RuntimeError("smoke container exited")
                    time.sleep(2)
            raise RuntimeError("smoke startup timed out")

        health = ready()
        assert health["ok"] and not health["prebuiltEnabled"]
        version = json.loads(output("docker", "exec", cid, "/opt/ggfm/bin/ggfm-patcher", "version"))
        assert health["androidVersion"] == version
        identity = output("docker", "exec", cid, "cat", "/data/signing/identity.json")
        output("docker", "restart", cid)
        assert ready()["androidVersion"] == version
        assert output("docker", "exec", cid, "cat", "/data/signing/identity.json") == identity
        print("Docker smoke: upload-only healthy, embedded version verified, signing identity survives restart")
    finally:
        # Only the container ID just created by this test; --rm owns its temporary volume.
        subprocess.run(["docker", "logs", cid], check=False)
        subprocess.run(["docker", "inspect", "--format", "{{.Id}}", cid], check=False)
        subprocess.run(["docker", "stop", "--time", "30", cid], check=False)


if __name__ == "__main__":
    main(sys.argv[1])
