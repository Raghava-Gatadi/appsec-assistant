import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from appsec_assistant.cli import atomic_write, load_config, main
from appsec_assistant.reports import render
from appsec_assistant.rules import RULES
from appsec_assistant.scanner import Options, scan, scan_stdin

ROOT = Path(__file__).resolve().parents[1]


def check(source, name="app.py", **kwargs):
    return scan_stdin(source, name, Options(**kwargs))


def ids(result):
    return {f.rule_id for f in result.findings}


class PythonChecks(unittest.TestCase):
    CASES = {
        "PY001": 'from flask import request\ndef search(db):\n value = request.args["name"]\n query = "SELECT id FROM accounts WHERE name = " + value\n db.execute(query)\n',
        "PY002": 'import subprocess as sp\nfrom flask import request\nsp.run(request.args["command"], shell=True)',
        "PY003": 'from flask import request\neval(request.args["expression"])',
        "PY004": 'import pickle as serializer\nfrom flask import request\nserializer.loads(request.data)',
        "PY005": 'import yaml\nfrom flask import request\nyaml.load(request.data, Loader=yaml.Loader)',
        "PY006": 'import requests\nrequests.get("https://example.invalid", verify=False)',
        "PY007": 'from hashlib import md5 as digest\ndigest(b"content")',
        "PY008": 'import random\nreset_token_secret = random.randint(1, 1000)',
        "PY009": 'import tempfile\nfilename = tempfile.mktemp()',
        "PY010": 'app.run(debug=True)',
        "PY011": 'from flask import request, render_template_string\nrender_template_string(request.args["template"])',
        "PY012": 'from markupsafe import Markup\ndef show(data):\n return Markup(data)',
        "PY013": 'from flask import request\nimport requests\nurl = request.args["url"]\nrequests.get(url)',
        "PY014": 'from flask import request\nopen(request.args["file"])',
        "PY015": 'archive.extractall("destination")',
        "PY016": 'import jwt\njwt.decode(token, options={"verify_signature": False})',
        "PY017": 'from flask import request, redirect\nredirect(request.args["next"])',
        "CFG001": 'DEBUG = True', "CFG002": 'SESSION_COOKIE_SECURE = False',
        "CFG003": 'SESSION_COOKIE_HTTPONLY = False', "CFG004": 'ALLOWED_HOSTS = ["*"]',
        "CFG005": 'CORS_ALLOW_ALL_ORIGINS = True', "SEC001": 'api_key = "not-a-real-credential"',
    }

    def test_all_python_rules(self):
        for rule, source in self.CASES.items():
            with self.subTest(rule=rule):
                result = check(source)
                self.assertTrue(result.complete, result.diagnostics)
                self.assertIn(rule, ids(result))

    def test_safe_alternatives(self):
        cases = [
            ('def search(db, value):\n db.execute("SELECT id FROM users WHERE name = ?", (value,))', "PY001"),
            ('import subprocess\nsubprocess.run(["tool", value], shell=False)', "PY002"),
            ('import yaml\nyaml.safe_load(data)', "PY005"),
            ('from yaml import load, SafeLoader as Safe\nload(data, Loader=Safe)', "PY005"),
            ('import requests\nrequests.get(url, verify=True)', "PY006"),
            ('import hashlib\nhashlib.md5(b"checksum", usedforsecurity=False)', "PY007"),
            ('app.run(debug=False)', "PY010"),
            ('import jwt\njwt.decode(token, key, algorithms=["RS256"])', "PY016"),
            ('archive.extractall("dest", filter="data")', "PY015"),
            ('api_key = "example_not_real_key"', "SEC001"),
            ('api_key = os.environ["API_KEY"]', "SEC001"),
            ('eval = custom_parser\neval(value)', "PY003"),
            ('def f(eval, value):\n return eval(value)', "PY003"),
        ]
        for source, rule in cases:
            with self.subTest(rule=rule, source=source):
                self.assertNotIn(rule, ids(check(source)))

    def test_trace_and_classification(self):
        f = next(f for f in check(self.CASES["PY001"]).findings if f.rule_id == "PY001")
        self.assertEqual((f.confidence, f.classification, f.function), ("high", "likely-vulnerability", "search"))
        self.assertTrue(any(t.kind == "external" for t in f.trace))
        self.assertTrue(any(t.label.startswith("Assigned") for t in f.trace))
        self.assertEqual(f.trace[-1].kind, "sink")

    def test_parameter_trust_unknown(self):
        f = check('def parse(text):\n return eval(text)').findings[0]
        self.assertEqual((f.confidence, f.classification), ("medium", "review-hotspot"))

    def test_branch_union(self):
        result = check('from flask import request\nimport requests\nif flag:\n url=request.args["url"]\nelse:\n url="https://example.invalid"\nrequests.get(url)')
        self.assertIn("PY013", ids(result))
        self.assertEqual(result.findings[0].confidence, "high")

    def test_reassignment(self):
        result = check('from flask import request\nimport requests\nurl=request.args["url"]\nurl="https://example.invalid"\nrequests.get(url)')
        self.assertNotIn("PY013", ids(result))

    def test_session_alias(self):
        result = check('import requests\nfrom flask import request\nsession=requests.Session()\nsession.request("GET", request.args["url"], verify=False)')
        self.assertTrue({"PY006", "PY013"} <= ids(result))

    def test_unknown_verify_option_is_hotspot(self):
        result = check('client.get(value, verify=False)')
        f = next(f for f in result.findings if f.rule_id == "PY006")
        self.assertEqual((f.confidence, f.classification), ("low", "review-hotspot"))

    def test_match_union(self):
        result = check('from flask import request\nimport requests\nmatch choice:\n case 1:\n  url=request.args["url"]\n case _:\n  url="https://example.invalid"\nrequests.get(url)')
        self.assertIn("PY013", ids(result))

    def test_common_hardcoded_password(self):
        self.assertIn("SEC001", ids(check('password="password123"')))

    def test_scope_isolation(self):
        result = check('from flask import request\nimport requests\ndef one():\n url=request.args["url"]\ndef two():\n requests.get(url)')
        self.assertNotIn("PY013", ids(result))

    def test_loop_zero_iterations(self):
        result = check('from flask import request\nimport requests\nurl=request.args["url"]\nfor x in values:\n url="https://example.invalid"\nrequests.get(url)')
        self.assertIn("PY013", ids(result))

    def test_long_trace(self):
        source = 'from flask import request\nx0=request.args["value"]\n' + '\n'.join(f'x{i}=x{i-1}' for i in range(1, 40)) + '\neval(x39)'
        f = next(f for f in check(source).findings if f.rule_id == "PY003")
        self.assertEqual(f.confidence, "high")
        self.assertLessEqual(len(f.trace), 13)

    def test_unicode_columns(self):
        source = '"é"; eval(input())'
        f = next(f for f in check(source).findings if f.rule_id == "PY003")
        self.assertEqual(f.column, source.index("eval") + 1)

    def test_safe_sink_in_map(self):
        result = check('@app.get("/items")\ndef items(db):\n db.execute("SELECT id FROM items")')
        self.assertNotIn("PY001", ids(result))
        self.assertTrue({"entry point", "function", "database query"} <= {m["category"] for m in result.code_map})
        self.assertEqual(result.review_queue[0]["function"], "items")

    def test_parser_errors_and_limits(self):
        self.assertFalse(check('def broken(:\n return 1').complete)
        self.assertFalse(check('a=1\nb=2\nc=3', max_nodes=3).complete)


class LexicalChecks(unittest.TestCase):
    CASES = {
        "JS001": 'function parse(value) { return eval(value); }',
        "JS002": 'import { exec as run } from "node:child_process"; run(command);',
        "JS003": 'node.innerHTML = value;',
        "JS004": 'const client = new Client({rejectUnauthorized: false});',
        "JS005": 'db.query(`SELECT id FROM users WHERE name = ${name}`);',
        "JS006": 'const view = <div dangerouslySetInnerHTML={{__html: value}} />;',
    }

    def test_all_js_rules(self):
        for rule, source in self.CASES.items():
            with self.subTest(rule=rule):
                result = check(source, "app.tsx")
                self.assertTrue(result.complete)
                self.assertIn(rule, ids(result))
                self.assertTrue(all(f.classification == "review-hotspot" for f in result.findings))

    def test_comments_and_strings(self):
        source = '// eval(value)\n/* node.innerHTML = text; */\nconst text = "eval(value)";\nconst s = `node.innerHTML = value`;'
        self.assertFalse(check(source, "app.js").findings)

    def test_regex_exec(self):
        self.assertNotIn("JS002", ids(check('const m = pattern.exec(value);', "app.js")))

    def test_child_process_aliases(self):
        for source in ['const cp = require("child_process"); cp.exec(cmd);', 'const {exec: run} = require("child_process"); run(cmd);', 'import * as cp from "child_process"; cp.execSync(cmd);']:
            self.assertIn("JS002", ids(check(source, "app.js")))

    def test_sql_parameter_vs_interpolation(self):
        safe = check('db.query("SELECT id FROM users WHERE name = ?", [`${name}`]);', "app.js")
        self.assertNotIn("JS005", ids(safe))
        self.assertTrue(any(m["category"] == "database query" for m in safe.code_map))
        self.assertIn("JS005", ids(check('db.query(\n "SELECT id FROM users WHERE id=" +\n value\n);', "app.ts")))

    def test_other_languages(self):
        samples = {
            "handler.php": '<?php function read($p) { return file_get_contents($p); }',
            "Handler.java": 'public String query(String q) { return db.executeQuery(q); }',
            "Handler.cs": 'public string Query(string q) { return db.Execute(q); }',
            "handler.go": 'func query(q string) { db.Query(q) }',
            "handler.rb": 'def query(q)\n db.execute(q)\nend',
        }
        for name, source in samples.items():
            with self.subTest(name=name):
                result = check(source, name)
                self.assertTrue(result.complete)
                self.assertTrue(any(m["kind"] == "review-hotspot" for m in result.code_map))
                self.assertFalse(result.findings)

    def test_docker_final_user(self):
        safe = 'FROM build AS builder\nUSER root\nFROM runtime\nUSER root\nUSER 1000\n'
        self.assertNotIn("CFG006", ids(check(safe, "Dockerfile")))
        self.assertIn("CFG006", ids(check('FROM runtime\nUSER root\n', "Dockerfile")))

    def test_secrets_redacted_everywhere(self):
        secret, token = "not-a-real-sensitive-value", "ghp_" + "A" * 36
        result = check(f'API_KEY="{secret}"\nPROVIDER_TOKEN="{token}"\n-----BEGIN PRIVATE KEY-----', ".env")
        self.assertTrue({"SEC001", "SEC002", "SEC003"} <= ids(result))
        for format in ["text", "json", "html", "sarif"]:
            self.assertNotIn(secret, render(result, format))
            self.assertNotIn(token, render(result, format))

    def test_config_locations(self):
        f = next(f for f in check('\n\nDEBUG=true\n', '.env').findings if f.rule_id == "CFG001")
        self.assertEqual(f.line, 3)


class WorkflowChecks(unittest.TestCase):
    def test_no_execution_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "executed.marker"
            (root / "app.py").write_text(f'open({str(marker)!r}, "w").write("executed")\neval(input())')
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignore.js").write_text('eval(value)')
            (root / "linked.py").symlink_to(root / "app.py")
            result = scan(root, Options())
            self.assertTrue(result.complete)
            self.assertEqual(result.files_scanned, 1)
            self.assertFalse(marker.exists())
            self.assertTrue(any("symlink" in d["reason"].lower() for d in result.diagnostics))

    def test_missing_empty_unsupported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertFalse(scan(root / "missing", Options()).complete)
            self.assertFalse(scan(root, Options()).complete)
            (root / "blob.bin").write_bytes(b"binary")
            self.assertFalse(scan(root, Options()).complete)

    def test_resource_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.py").write_text("x=1\n" * 20)
            (root / "b.py").write_text("x=2\n")
            for opts in [Options(max_file_bytes=5), Options(max_files=1), Options(max_total_bytes=10)]:
                self.assertFalse(scan(root, opts).complete)

    def test_stable_baseline(self):
        first = check('import requests\nrequests.get(url, verify=False)')
        fingerprint = first.findings[0].fingerprint
        second = check('\n# unrelated\nimport requests\nrequests.get(url, verify=False)', baseline={fingerprint})
        self.assertEqual(second.findings[0].status, "existing")
        self.assertFalse(second.active)

    def test_repeated_lines_distinct(self):
        self.assertEqual(len({f.fingerprint for f in check('eval(input())\neval(input())').findings}), 2)

    def test_suppression_stays_visible(self):
        result = check('eval(input())', suppressions=[{"rule_id": "PY003", "path": "app.py", "reason": "Reviewed isolated fixture"}])
        self.assertEqual(result.findings[0].status, "suppressed")
        self.assertFalse(result.active)
        self.assertIn("Reviewed isolated fixture", render(result, "text"))

    def test_filter_count(self):
        result = check('import hashlib\nhashlib.md5(b"text")', min_severity="high")
        self.assertFalse(result.findings)
        self.assertEqual(result.filtered_findings, 1)

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            for bad in [{"unknown": True}, {"suppressions": [{"rule_id": "PY003", "path": "*"}]}, {"suppressions": [{"rule_id": "PY003", "path": "*", "reason": "fixture", "expires": "2000-01-01"}]}]:
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    load_config(path)

    def test_manifest_inventory_no_credentials(self):
        result = check(json.dumps({"dependencies": {"example": "^1.2.3", "private-package": "https://user:do-not-echo@host/repo"}}), "package.json")
        self.assertEqual(len(result.inventory), 2)
        self.assertEqual(result.inventory[0]["specifier"], "^1.2.3")
        self.assertNotIn("do-not-echo", render(result, "json"))
        self.assertTrue(all(d["advisory_status"] == "not checked" for d in result.inventory))
        self.assertEqual(len(check('[project]\ndependencies=["example>=1.0"]', 'pyproject.toml').inventory), 1)
        self.assertFalse(check('{broken', 'package.json').complete)

    def test_report_injection_protection(self):
        result = check('eval(input())', '<script>alert(1)</script>.py')
        html = render(result, "html")
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('Content-Security-Policy', html)
        self.assertNotIn('\x1b', render(check('eval(input())', '\x1b[31mapp.py'), 'text'))

    def test_sarif_structure(self):
        report = json.loads(render(check(PythonChecks.CASES["PY001"]), "sarif"))
        self.assertEqual(report["version"], "2.1.0")
        run = report["runs"][0]
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        for f in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][f["ruleIndex"]]["id"], f["ruleId"])
            self.assertGreater(f["locations"][0]["physicalLocation"]["region"]["startLine"], 0)
        self.assertIn("codeMap", run["properties"])

    def test_cli_exit_codes_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, baseline = root / "app.py", root / "baseline.json"
            source.write_text('eval(input())')
            def run(*args):
                return subprocess.run([sys.executable, str(ROOT / "scan.py"), str(source), *args], text=True, capture_output=True)
            self.assertEqual(run().returncode, 1)
            self.assertEqual(run("--fail-on", "none").returncode, 0)
            self.assertEqual(run("--write-baseline", str(baseline)).returncode, 1)
            self.assertTrue(baseline.exists())
            self.assertEqual(run("--baseline", str(baseline)).returncode, 0)
            source.write_text('def broken(:')
            self.assertEqual(run("--fail-on", "none").returncode, 2)

    def test_cli_output_and_source_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, report = root / "app.py", root / "report.html"
            source.write_text('x=1')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(root), "-o", str(report)]), 0)
                self.assertTrue(report.read_text().startswith("<!doctype html>"))
                self.assertEqual(main([str(source), "-o", str(source)]), 2)
            self.assertEqual(source.read_text(), "x=1")

    def test_output_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real, link = root / "real.json", root / "link.json"
            real.write_text("keep")
            link.symlink_to(real)
            with self.assertRaises(ValueError):
                atomic_write(link, "replace")
            self.assertEqual(real.read_text(), "keep")

    def test_all_rules_covered(self):
        covered = set(PythonChecks.CASES) | set(LexicalChecks.CASES) | {"CFG006", "SEC002", "SEC003"}
        self.assertEqual(covered, set(RULES))


if __name__ == "__main__":
    unittest.main()
