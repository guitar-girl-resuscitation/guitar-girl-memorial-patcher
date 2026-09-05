"""Portable Docker recipe/config contracts, without Docker, network or game files."""
import importlib.util
import json
from pathlib import Path
import unittest

from release_artifacts import KINDS

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("docker_prepare", ROOT / "docker/prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class DockerContract(unittest.TestCase):
    def config(self):
        names = ["classes.dex", "libggfm_bootstrap.so", "libdobby.so", "libggfm_server.so"]
        manifest = {"files": {name: {"sha256": "A" * 64} for name in names}}
        dependencies = {"server": {"sha256": "A" * 64, "sourceCommit": "b" * 40}, "policySha256": "C" * 64}
        lock = {"patchCommit": "d" * 40, "policySha256": "C" * 64}
        return lock, dependencies, manifest

    def test_config_uses_mounts_and_automatic_revision(self):
        config = prepare.make_config(*self.config())
        self.assertNotIn("revision", config["versions"])
        self.assertEqual(config["cacheRoot"], "/data/cache")
        self.assertEqual(config["prebuilt"]["operatorSourceXapk"], "/input/original.xapk")
        self.assertEqual(config["listen"], "127.0.0.1:8081")
        self.assertTrue(config["security"]["requireTrustedProxy"])
        self.assertEqual(config["versions"]["patchCommit"], "d" * 40)

    def test_mismatched_runtime_pair_is_rejected(self):
        lock, dependencies, manifest = self.config()
        dependencies["server"]["sha256"] = "B" * 64
        with self.assertRaises(ValueError):
            prepare.make_config(lock, dependencies, manifest)
        lock, dependencies, manifest = self.config()
        lock["policySha256"] = "D" * 64
        with self.assertRaises(ValueError):
            prepare.make_config(lock, dependencies, manifest)

    def test_image_does_not_copy_game_or_private_state(self):
        dockerfile = (ROOT / "docker/Dockerfile").read_text()
        self.assertNotIn("COPY . ", dockerfile)
        self.assertNotIn(".xapk", dockerfile.lower())
        self.assertNotIn("COPY private", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn('VOLUME ["/data"]', dockerfile)
        self.assertIn("EXPOSE 8080", dockerfile)
        members = KINDS["patcher-docker-linux-amd64"]
        self.assertFalse(any(name.endswith((".xapk", ".apk", ".p12", ".jks")) for name in members))
        self.assertIn("Dockerfile", members)
        self.assertIn("README.zh-CN.md", members)

    def test_bootstrap_supports_both_modes_and_retains_identity(self):
        source = (ROOT / "docker/entrypoint.py").read_text()
        self.assertIn('/input/original.xapk', source)
        self.assertIn('json.load(response).get("ok")', source)
        self.assertNotIn('json.load(response).get("prebuiltEnabled")', source)
        self.assertIn('fcntl.LOCK_EX | fcntl.LOCK_NB', source)
        self.assertIn('signing identity/application ID changed', source)
        self.assertNotIn('config["versions"]["revision"]', source)

    def test_tool_downloads_have_complete_pinned_hashes(self):
        for value in [prepare.APKTOOL_SHA, prepare.BUILD_TOOLS_SHA]:
            self.assertRegex(value, r"^[A-F0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
