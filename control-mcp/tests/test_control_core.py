"""Tests for control-mcp/control_core.py: allow-listed actions, approvals, audit log, redaction, refusals.

Runs without the MCP SDK: python3 control-mcp/tests/test_control_core.py
"""
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import control_core as cc  # noqa: E402

# Built at runtime so secret scanners never see a token-shaped literal in the source.
FAKE_TOKEN = "gh" + "p_" + "A1b2C3d4" * 5
FAKE_AGE = "AGE-SECRET" + "-KEY-1" + "QQQQ" * 10
FAKE_PAIR = "pass" + "word=" + "fixture" * 3
FAKE_BEARER = "Authorization: " + "Bear" + "er " + "fixture" * 3

CONFIG = textwrap.dedent(
    """
    [settings]
    audit_log = "ops-log.md"
    timeout_seconds = 5
    max_output = 2000

    [actions.echo_name]
    kind = "read"
    description = "Echo a validated name."
    argv = ["echo", "name={name}"]
    [actions.echo_name.params]
    name = '^[a-z0-9.-]{1,63}$'

    [actions.leak]
    kind = "read"
    description = "Prints secret-looking text (test only)."
    argv = ["printf", "%s", "{text}"]
    [actions.leak.params]
    text = '^[ -~]{1,200}$'

    [actions.deploy]
    kind = "change"
    description = "A mutating action."
    argv = ["sh", "-c", "echo deployed $CONTROL_APPROVED_BY"]

    [actions.wipe]
    kind = "change"
    description = "Must be refused by the deny list."
    argv = ["echo", "tofu", "destroy"]

    [actions.slow]
    kind = "read"
    description = "Sleeps past the timeout."
    argv = ["sleep", "10"]
    """
)


class ControlCoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "control.toml").write_text(CONFIG, encoding="utf-8")
        self.cfg = cc.load(self.dir / "control.toml")

    def tearDown(self):
        self.tmp.cleanup()

    def log(self):
        path = self.dir / "ops-log.md"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_lists_actions_with_kind_and_params(self):
        listed = {a["name"]: a for a in cc.list_actions(self.cfg)}
        self.assertEqual(listed["echo_name"]["kind"], "read")
        self.assertEqual(listed["echo_name"]["params"], ["name"])
        self.assertEqual(listed["deploy"]["kind"], "change")

    def test_read_action_runs_without_approval_and_is_not_logged(self):
        result = cc.run(self.cfg, "echo_name", {"name": "example.org"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["output"].strip(), "name=example.org")
        self.assertEqual(self.log(), "")

    def test_unknown_action_and_bad_params_are_refused(self):
        self.assertEqual(cc.run(self.cfg, "rm_everything", {})["status"], "refused")
        self.assertEqual(cc.run(self.cfg, "echo_name", {"name": "a b; rm -rf /"})["status"], "refused")
        self.assertEqual(cc.run(self.cfg, "echo_name", {})["status"], "refused")
        self.assertEqual(cc.run(self.cfg, "echo_name", {"name": "ok", "extra": "x"})["status"], "refused")

    def test_change_needs_a_well_formed_approval(self):
        for approval in ("", "yes", "ok go ahead", "Owner: deploy now"):
            with self.subTest(approval=approval):
                self.assertEqual(cc.run(self.cfg, "deploy", {}, approved=approval)["status"], "refused")
        self.assertEqual(self.log(), "")

    def test_approved_change_runs_and_is_audited_before_and_after(self):
        result = cc.run(self.cfg, "deploy", {}, approved="Owner 2030-01-31: deploy release 1.2")
        self.assertEqual(result["status"], "ok")
        self.assertIn("deployed Owner", result["output"])
        log = self.log()
        self.assertIn("| deploy |", log)
        self.assertIn("Owner 2030-01-31: deploy release 1.2", log)
        self.assertIn("started", log)
        self.assertIn("exit 0", log)

    def test_deny_list_refuses_even_with_approval(self):
        result = cc.run(self.cfg, "wipe", {}, approved="Owner 2030-01-31: wipe it")
        self.assertEqual(result["status"], "refused")
        self.assertIn("deny", result["reason"])
        self.assertNotIn("exit 0", self.log())

    def test_output_is_redacted(self):
        for text in (FAKE_TOKEN, FAKE_AGE, FAKE_PAIR, FAKE_BEARER):
            with self.subTest(text=text[:12]):
                result = cc.run(self.cfg, "leak", {"text": text})
                self.assertEqual(result["status"], "ok")
                self.assertIn("[REDACTED", result["output"])
                self.assertNotIn(text.split("=")[-1].split(" ")[-1], result["output"])

    def test_timeout_is_reported(self):
        result = cc.run(self.cfg, "slow", {})
        self.assertEqual(result["status"], "failed")
        self.assertIn("timeout", result["reason"])

    def test_config_errors_are_caught_at_load(self):
        bad = self.dir / "bad.toml"
        bad.write_text('[actions.x]\nkind = "write"\nargv = ["echo"]\n', encoding="utf-8")
        with self.assertRaises(cc.ConfigError):
            cc.load(bad)
        bad.write_text('[actions.x]\nkind = "read"\nargv = "echo hi"\n', encoding="utf-8")
        with self.assertRaises(cc.ConfigError):
            cc.load(bad)
        bad.write_text('[actions.x]\nkind = "read"\nargv = ["echo", "{missing}"]\n', encoding="utf-8")
        with self.assertRaises(cc.ConfigError):
            cc.load(bad)

    def test_child_gets_no_inherited_secrets(self):
        os.environ["CONTROL_TEST_SECRET"] = "should-not-leak"
        try:
            cfg_path = self.dir / "env.toml"
            cfg_path.write_text('[actions.env]\nkind = "read"\nargv = ["sh", "-c", "echo [$CONTROL_TEST_SECRET]"]\n',
                                encoding="utf-8")
            result = cc.run(cc.load(cfg_path), "env", {})
            self.assertIn("[]", result["output"])
        finally:
            del os.environ["CONTROL_TEST_SECRET"]


if __name__ == "__main__":
    unittest.main()
