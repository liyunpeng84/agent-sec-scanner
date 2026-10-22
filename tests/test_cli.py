import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_sec_scanner.cli import main

ROOT = Path(__file__).resolve().parent.parent
VULN = ROOT / "examples" / "vulnerable"
CLEAN = ROOT / "examples" / "clean"


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


class CliTests(unittest.TestCase):
    def test_vulnerable_examples_fail_ci(self):
        code, out = run(str(VULN), "-f", "json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(len(data["scanned_files"]), 7)
        rules = {f["rule_id"] for f in data["findings"]}
        for r in ["ASC001", "ASC002", "ASC003", "ASC004", "ASC010", "ASC020", "ASC021", "ASC022",
                  "ASC030", "ASC031", "ASC040", "ASC041", "ASC050"]:
            self.assertIn(r, rules)
        # no raw example secret ever appears in output
        self.assertNotIn("ghp_EXAMPLE0fake0token0for0tests0only000", out)
        self.assertNotIn("Zq8vN3kL0pW7rT2xY5mB9cJ4hF6dS1aE", out)

    def test_clean_examples_pass(self):
        code, out = run(str(CLEAN), "-f", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])

    def test_fail_on_none(self):
        code, _ = run(str(VULN), "--fail-on", "none", "-f", "json")
        self.assertEqual(code, 0)

    def test_sarif(self):
        code, out = run(str(VULN), "-f", "sarif", "--fail-on", "none")
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        res = sarif["runs"][0]["results"]
        self.assertTrue(res and all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in res))

    def test_markdown_and_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.md"
            run(str(VULN), "-f", "markdown", "-o", str(out), "--fail-on", "none")
            self.assertIn("| Severity | Rule |", out.read_text())

    def test_ignore_file(self):
        with tempfile.TemporaryDirectory() as d:
            ig = Path(d) / ".agentsecignore"
            ig.write_text("ASC021  # accepted risk\nASC010 *codex-config.toml\n")
            _, out = run(str(VULN), "-f", "json", "--ignore-file", str(ig), "--fail-on", "none")
            fs = json.loads(out)["findings"]
            self.assertFalse(any(f["rule_id"] == "ASC021" for f in fs))
            self.assertFalse(any(f["rule_id"] == "ASC010" and f["file"].endswith("codex-config.toml") for f in fs))
            self.assertTrue(any(f["rule_id"] == "ASC010" for f in fs))

    def test_min_severity(self):
        _, out = run(str(VULN), "-f", "json", "--min-severity", "critical", "--fail-on", "none")
        self.assertTrue(all(f["severity"] == "critical" for f in json.loads(out)["findings"]))

    def test_bad_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mcp.json"
            p.write_text("{not json")
            code, out = run(str(p))
            self.assertEqual(code, 2)
            self.assertIn("ERROR", out)

    def test_list_rules(self):
        code, out = run("--list-rules")
        self.assertEqual(code, 0)
        self.assertGreaterEqual(len(out.strip().splitlines()), 13)


if __name__ == "__main__":
    unittest.main()
