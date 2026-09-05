#!/usr/bin/env python3
"""Portable deployment-contract checks; no network, services or firewall changes."""
import configparser
import json
from pathlib import Path
import unittest

from release_artifacts import KINDS

ROOT = Path(__file__).resolve().parents[1]


class DeploymentContract(unittest.TestCase):
    def test_public_example_is_local_cloudflare_only(self):
        config = json.loads((ROOT / "config/patcher.example.json").read_text())
        self.assertEqual(config["listen"], "127.0.0.1:8080")
        security = config["security"]
        self.assertTrue(security["publicOrigin"].startswith("https://"))
        self.assertTrue(security["requireTrustedProxy"])
        self.assertEqual(security["clientIpHeader"], "cf-connecting-ip")
        self.assertEqual(set(security["trustedProxies"]), {"127.0.0.1/32", "::1/128"})
        self.assertLessEqual(security["maxInFlight"], 32)
        self.assertEqual(security["failuresBeforeBan"], 8)
        self.assertEqual(security["banSeconds"], 900)

    def test_tunnel_template_contract(self):
        # This deliberately checks our small template, not a replacement YAML
        # parser. Operators must also run cloudflared ingress validate on theirs.
        text = (ROOT / "deploy/cloudflared.yml").read_text()
        self.assertIn("hostname: patch.example.org", text)
        self.assertIn("service: http://127.0.0.1:8080", text)
        self.assertTrue(text.rstrip().endswith("- service: http_status:404"))
        self.assertIn("metrics: 127.0.0.1:", text)
        self.assertIn("loglevel: fatal", text)
        self.assertNotIn("noTLSVerify", text)
        self.assertNotIn("0.0.0.0:8080", text)

    def test_service_is_unprivileged_and_resource_bounded(self):
        # systemd permits repeated Environment= assignments.
        config = configparser.ConfigParser(interpolation=None, strict=False)
        config.read(ROOT / "deploy/ggfm-patcher.service")
        service = config["Service"]
        self.assertEqual(service["User"], "ggfm")
        self.assertEqual(service["NoNewPrivileges"], "true")
        self.assertEqual(service["ProtectSystem"], "strict")
        self.assertEqual(service["KillMode"], "control-group")
        self.assertEqual(service["MemoryMax"], "4G")
        self.assertEqual(service["TasksMax"], "128")
        self.assertEqual(service["UMask"], "0077")

    def test_release_ships_exact_deployment_docs_and_templates(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        files = {
            "PUBLIC_DEPLOYMENT.md": "docs/PUBLIC_DEPLOYMENT.md",
            "deploy/cloudflared.yml": "deploy/cloudflared.yml",
            "deploy/ggfm-patcher.service": "deploy/ggfm-patcher.service",
        }
        for name, source in files.items():
            self.assertIn(name, KINDS["patcher-linux-x64"])
            self.assertIn(name, KINDS["patcher-windows-x64"])
            self.assertTrue((ROOT / source).is_file())
            self.assertIn(f"--file {name}={source}", workflow)
        self.assertIn("python tools/test_deployment.py", workflow)


if __name__ == "__main__":
    unittest.main()
