import io
import json
import unittest
from contextlib import redirect_stdout

from agent_guard import cli

from .helpers import make_home, write


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(args))
        return code, buf.getvalue()

    def test_json_report_and_fail_on(self):
        home = make_home()
        write(home / ".openclaw" / "openclaw.json", '{ gateway: { bind: "lan" } }')
        code, out = self.run_cli("--home", str(home), "--no-network", "--format", "json", "--fail-on", "high")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertGreaterEqual(data["summary"]["high"], 1)
        names = {a["agent"]: a["found"] for a in data["agents"]}
        self.assertEqual(names, {"hermes": False, "openclaw": True})

    def test_nothing_installed_exits_zero(self):
        code, out = self.run_cli("--home", str(make_home()), "--no-network", "--fail-on", "info")
        self.assertEqual(code, 0)
        self.assertIn("not found", out)

    def test_markdown_and_min_severity(self):
        home = make_home()
        write(home / ".openclaw" / "openclaw.json", '{ gateway: { bind: "lan" } }')
        _, out = self.run_cli("--home", str(home), "--no-network", "--format", "markdown", "--min-severity", "high")
        self.assertIn("[HIGH]", out)
        self.assertNotIn("[MEDIUM]", out)

    def test_never_writes_into_agent_dirs(self):
        home = make_home()
        write(home / ".hermes" / "config.yaml", "")
        before = sorted(p.name for p in (home / ".hermes").rglob("*"))
        self.run_cli("--home", str(home), "--no-network")
        self.assertEqual(before, sorted(p.name for p in (home / ".hermes").rglob("*")))


if __name__ == "__main__":
    unittest.main()
