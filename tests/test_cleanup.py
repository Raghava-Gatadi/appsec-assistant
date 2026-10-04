"""Cleanup regressions: synthetic source is inspected, never executed."""
import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from appsec_assistant.cli import main
from benchmarks.score import score
from appsec_assistant.models import Trace
from appsec_assistant.priorities import finding_key, finding_rank, meets_gate, navigation_rank
from appsec_assistant.reports import render
from appsec_assistant.scanner import Options, dependency_inventory, language, scan, scan_stdin


def check(source, name="app.py", **kwargs):
    return scan_stdin(source, name, Options(**kwargs))


def secrets(source, name):
    return [f for f in check(source, name).findings if f.rule_id == "SEC001"]


class CleanupTests(unittest.TestCase):
    def test_test_exclusions_and_override(self):
        excluded = ["tests/a.php", "test/a.js", "__tests__/a.ts", "spec/a.rb",
                    "test_app.py", "app_test.py", "conftest.py", "a.test.js",
                    "a.test.ts", "a.spec.js", "a.spec.ts", "a_test.go", "a.test.tsx"]
        included = ["test.php", "sqli/test.php", "contest/a.php", "app.py", "a.js"]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in excluded + included:
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('password="password123"')
            result = scan(root, Options())
            self.assertTrue(result.complete)
            self.assertEqual(result.test_files_excluded, len(excluded))
            self.assertEqual({f["path"] for f in result.file_inventory}, set(included))
            self.assertTrue(any(f"{len(excluded)} test files excluded" in m["reason"] for m in result.diagnostics))
            full = scan(root, Options(include_tests=True))
            self.assertEqual(full.files_scanned, len(excluded + included))
            self.assertEqual(full.test_files_excluded, 0)
            explicit = scan(root / "tests", Options())
            self.assertTrue(explicit.complete)
            self.assertEqual(explicit.test_files_excluded, 1)
            self.assertEqual(explicit.files_scanned, 0)
            self.assertEqual(scan(root / "tests/a.php", Options()).test_files_excluded, 1)
        self.assertEqual(check('eval(input())', 'test_app.py').files_scanned, 0)
        self.assertTrue(check('eval(input())', 'test_app.py', include_tests=True).findings)
        self.assertTrue(check('<?php $password="password123";', 'test.php').findings)

    def test_template_suffixes(self):
        for ext, lang, source in [("py", "python", 'eval(input())'), ("ts", "javascript/typescript", 'eval(value)'),
                                  ("php", "php", '<?php echo $_GET["x"];')]:
            for suffix in ("dist", "example", "sample", "template"):
                name = f"config.{ext}.{suffix}"
                with self.subTest(name=name):
                    self.assertEqual(language(name), lang)
                    result = check(source, name)
                    self.assertTrue(result.complete)
                    self.assertEqual(result.files_scanned, 1)
                    self.assertEqual(result.file_inventory[0]["path"], name)
        self.assertIsNone(language('app.png.dist'))
        self.assertEqual(language('config.py.example.dist'), 'python')
        self.assertEqual(check('eval(input())', 'test_config.py.dist').test_files_excluded, 1)
        self.assertEqual(len(dependency_inventory('{"dependencies":{"a":"^1.0"}}', 'package.json.example')), 1)

    def test_direct_credentials_across_languages(self):
        for name, bad, good in [
            ('app.py', 'password="password123"', 'value="password123"\npassword=value'),
            ('app.js', 'const password = "password123";', 'const password = process.env.PASSWORD;'),
            ('app.ts', 'config["password"] = "password123";', 'const password = "prefix000" + value;'),
            ('app.php', '<?php $password="password123";', '<?php $sql = "UPDATE users SET password = \'password123\'";'),
            ('App.java', 'String password="password123";', 'String password=loadSecret();'),
            ('app.cs', 'var password="password123";', 'var password=Environment.GetEnvironmentVariable("PASSWORD");'),
            ('app.rb', 'password = "password123"', 'password = ENV["PASSWORD"]'),
            ('app.go', 'password := "password123"', 'password := os.Getenv("PASSWORD")'),
            ('config.json', '{"password":"password123"}', '{"query":"password = \'password123\'"}'),
            ('config.yaml', 'password: "password123"', '# password: "password123"'),
            ('.env', 'PASSWORD=password123', 'PASSWORD=${PASSWORD}'),
        ]:
            with self.subTest(language=name):
                self.assertTrue(secrets(bad, name))
                self.assertFalse(secrets(good, name))
        for source in ['// password="password123";', '/* password="password123" */',
                       'const query="password = \'password123\'";', 'password == "password123";',
                       'password = "prefix000" + suffix;', 'password = get("password123");',
                       'password = "prefix000${value}";', 'password = "example_password";']:
            self.assertFalse(secrets(source, 'app.js'), source)
        self.assertFalse(secrets('<?php $password="value000 $variable";', 'app.php'))
        self.assertFalse(secrets('value="password123"\nconfig={"password":value}', 'app.py'))
        self.assertTrue(secrets('<?php $_CONFIG["db_password"] = "password123";', 'config.php.dist'))

    def test_priority_precedence_and_ties(self):
        f = check('eval(input())').findings[0]
        likely = replace(f, classification='likely-vulnerability', severity='low', confidence='low', trace=[])
        hotspot = replace(f, classification='review-hotspot', severity='critical', confidence='high')
        self.assertGreater(finding_rank(likely), finding_rank(hotspot))
        base = replace(hotspot, severity='high', confidence='medium', trace=[], engine='text-pattern')
        self.assertGreater(finding_rank(replace(base, confidence='high')), finding_rank(base))
        self.assertGreater(finding_rank(replace(base, trace=[Trace(1, 'Input', 'external')])), finding_rank(base))
        command = replace(base, rule_id='JS002')
        db = replace(base, rule_id='JS005')
        file = replace(base, rule_id='PY014')
        outbound = replace(base, rule_id='PY013')
        self.assertEqual(sorted([outbound, db, command, file], key=finding_key), [command, db, file, outbound])
        for value in [likely, hotspot, base, command]:
            self.assertTrue(0 <= finding_rank(value) <= 100)
        self.assertLess(finding_key(replace(base, path='a.py')), finding_key(replace(base, path='z.py')))
        self.assertLess(finding_key(replace(base, line=1)), finding_key(replace(base, line=2)))
        self.assertGreater(navigation_rank('command execution', True), navigation_rank('database query', True))
        self.assertGreater(navigation_rank('database query', True), navigation_rank('filesystem access', True))
        self.assertGreater(navigation_rank('filesystem access', True), navigation_rank('outbound request', True))

    def test_scope_queue_and_overflow(self):
        source = '\n'.join(f'def f{i}(db):\n db.execute("SELECT 1")' for i in range(25))
        result = check(source)
        self.assertEqual(len(result.review_queue), 25)
        self.assertEqual(result.to_dict()['review_queue_omitted'], 5)
        self.assertIn('+5 more scopes', render(result, 'html'))
        self.assertIn('f24', render(result, 'html'))
        self.assertIn('+5 more scopes', render(result, 'text'))
        likely = check('eval(input())')
        self.assertEqual(likely.review_queue[0]['rank'], finding_rank(likely.findings[0]))
        self.assertEqual(json.loads(render(likely, 'sarif'))['runs'][0]['results'][0]['rank'], likely.review_queue[0]['rank'])

    def test_php_catalog_and_scope(self):
        source = '''<?php
$x = $_POST['name'];
echo $x; print $x; printf($x);
header("Location: " . $x);
include $x; require($x);
unserialize($x); move_uploaded_file($x, $dest);
$password = md5($x); $password = sha1($x);
rand(); mt_rand();
intval($x); $n = (int)$x; escapeshellarg($x);
htmlspecialchars($x); basename($x); in_array($x, $allow);
$stmt = $db->prepare($sql); $stmt->bindParam(1, $x);
?><?= $x ?>'''
        result = check(source, 'app.php')
        cats = {m['category'] for m in result.code_map}
        self.assertTrue({'input', 'entry point', 'template/HTML output', 'redirect', 'dynamic execution',
                         'deserialization', 'filesystem access', 'authentication/crypto', 'mitigation'} <= cats)
        self.assertTrue(all(m['function'] == '<file: app.php>' for m in result.code_map))
        notes = [m for m in result.code_map if m['category'] == 'mitigation']
        self.assertGreaterEqual(len(notes), 8)
        self.assertTrue(all(m['kind'] == 'note' for m in notes))
        self.assertEqual(len(result.review_queue), 1)
        self.assertTrue(any(m['category'] == 'template/HTML output' for m in check('<?php ECHO $x;', 'app.php').code_map))
        safe = check('''<?php
require "fixed.php"; include("fixed.php"); require "semi;colon.php";
header("Content-Type: text/plain");
$checksum = md5($contents);
// echo $_GET['x'];
$text = "shell_exec($x)";
htmlspecialchars($value);''', 'clean.php')
        self.assertEqual({m['category'] for m in safe.code_map}, {'mitigation'})
        self.assertFalse(safe.review_queue)
        self.assertFalse(safe.findings)
        self.assertTrue(any(m['category'] == 'dynamic execution' for m in check('<?php include "dir/" . $file;', 'app.php').code_map))

    def test_superglobal_reads_and_writes(self):
        # Request superglobals create entry-point hints; server-side state never does.
        for name in ('_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES'):
            with self.subTest(name=name):
                read = check(f'<?php $x = ${name}["key"];', 'app.php')
                self.assertTrue(any(m['category'] == 'entry point' for m in read.code_map))
                write = check(f'<?php ${name}["key"] = 1;', 'app.php')
                self.assertFalse(any(m['category'] == 'entry point' for m in write.code_map))
        for name in ('_SESSION', '_ENV', '_SERVER', 'GLOBALS'):
            with self.subTest(name=name):
                read = check(f'<?php $x = ${name}["key"];', 'app.php')
                self.assertFalse(any(m['category'] == 'entry point' for m in read.code_map))
                self.assertTrue(any(m['category'] == 'state' for m in read.code_map))
                write = check(f'<?php ${name}["key"] = 1;', 'app.php')
                self.assertFalse(write.code_map)
        self.assertFalse(check('<?php $x = "$_POST[anything]";', 'app.php').code_map)

    def test_cross_language_mitigations_are_notes(self):
        for name, source in [('app.py', 'import html\nhtml.escape(value)\nint(value)'),
                              ('app.ts', 'DOMPurify.sanitize(value); parseInt(value);')]:
            result = check(source, name)
            self.assertTrue(result.code_map)
            self.assertTrue(all(m['kind'] == 'note' for m in result.code_map))
            self.assertFalse(result.review_queue)
        result = check('from flask import request\nimport html\nhtml.escape(request.args["x"])\neval(request.args["x"])')
        self.assertEqual(result.findings[0].classification, 'likely-vulnerability')

    def test_grouping_locations_and_review_states(self):
        source = 'function show(x) {\n a.innerHTML=x;\n b.innerHTML=x;\n}\nfunction other(x) {\n c.innerHTML=x;\n}'
        result = check(source, 'app.js')
        self.assertEqual(len(result.findings), 3)
        self.assertEqual([len(g.locations) for g in result.finding_groups], [2, 1])
        data = result.to_dict()
        self.assertEqual(data['schema_version'], 2)
        self.assertEqual((data['summary']['new'], data['summary']['occurrences']), (2, 3))
        sarif = json.loads(render(result, 'sarif'))['runs'][0]['results']
        self.assertEqual([len(f['locations']) for f in sarif], [2, 1])
        self.assertEqual(len(sarif[0]['properties']['occurrenceFingerprints']), 2)
        html = render(result, 'html')
        self.assertEqual(html.count('<article class="finding"'), 2)
        self.assertIn('2 location(s): 2:3, 3:3', html)
        self.assertIn('Likely vulnerabilities', html)
        self.assertNotIn('High / critical priority', html)
        mixed = check(source, 'app.js', baseline={result.findings[0].fingerprint}, suppressions=[
            {'fingerprint': result.findings[1].fingerprint, 'reason': 'Reviewed fixture'}])
        self.assertEqual({g.primary.status for g in mixed.finding_groups}, {'new', 'existing', 'suppressed'})
        repeated = check('def f():\n eval(input())\ndef f():\n eval(input())')
        self.assertEqual(len(repeated.finding_groups), 2)
        self.assertEqual(len(repeated.review_queue), 2)

    def test_input_rows_are_collapsed_and_full_json_retained(self):
        result = check('from flask import request\na=request.args["x"]\nb=request.args["y"]')
        html = render(result, 'html')
        self.assertIn('<details id="map-inputs">', html)
        self.assertNotIn('<details id="map-inputs" open', html)
        self.assertIn('Input and state locations (2)', html)
        self.assertEqual(len(result.to_dict()['code_map']), 2)
        self.assertEqual(html.count('Identify the trust boundary'), 1)

    def test_composer_inventory(self):
        manifest = json.dumps({'require': {'vendor/lib': '^1.2', 'php': '>=8.1'}, 'require-dev': {'vendor/test': '~2.0'},
                               'repositories': [{'url': 'https://user:credential@example.invalid'}]})
        result = check(manifest, 'composer.json.dist')
        self.assertEqual(len(result.inventory), 3)
        self.assertTrue(result.complete)
        for format in ('text', 'json', 'html', 'sarif'):
            self.assertNotIn('credential@example', render(result, format))
        locked = check('{"packages":[{"name":"vendor/lib","version":"v1.2.3"}],"packages-dev":[]}', 'composer.lock')
        self.assertEqual(locked.inventory[0]['specifier'], 'v1.2.3')
        for invalid in ('[]', '{"require":[]}', '{invalid'):
            self.assertFalse(check(invalid, 'composer.json').complete)
        self.assertFalse(check('{"packages":[{}]}', 'composer.lock').complete)
        self.assertFalse(check('{}', 'composer.json').inventory)

    def test_grouped_baseline_keeps_every_occurrence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / 'app.py'
            source.write_text('def parse():\n eval(input())\n eval(input())')
            baseline = root / 'baseline.json'
            report = root / 'report.json'
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(source), '--write-baseline', str(baseline), '--fail-on', 'none']), 0)
                self.assertEqual(len(json.loads(baseline.read_text())['fingerprints']), 2)
                self.assertEqual(main([str(source), '--baseline', str(baseline), '-o', str(report)]), 0)
            data = json.loads(report.read_text())
            self.assertEqual(data['summary']['existing'], 1)
            self.assertEqual(data['findings'][0]['occurrence_count'], 2)

    def test_benchmark_separates_navigation_from_findings(self):
        expected = {'cases': [
            {'path': 'app.php', 'cwe': 'CWE-89', 'navigation_category': 'database query', 'expected_vulnerable': True},
            {'path': 'safe.php', 'cwe': 'CWE-89', 'navigation_category': 'database query', 'expected_vulnerable': False}]}
        report = {'code_map': [{'path': p, 'category': 'database query'} for p in ('app.php', 'safe.php')], 'findings': []}
        counts = score(report, expected)['counts']
        self.assertEqual((counts['finding_matches'], counts['navigation_matches'], counts['false_positives']), (0, 1, 0))
        report['findings'] = [{'path': p, 'cwe': 'CWE-89', 'classification': 'likely-vulnerability'} for p in ('app.php', 'safe.php')]
        counts = score(report, expected)['counts']
        self.assertEqual((counts['finding_matches'], counts['likely_matches'], counts['false_positives']), (1, 1, 1))

    def test_gate_confidence_label_and_status(self):
        f = check('eval(input())').findings[0]
        for classification, confidence, expected in [('review-hotspot', 'low', False),
                                                      ('review-hotspot', 'medium', True),
                                                      ('likely-vulnerability', 'low', True)]:
            candidate = replace(f, severity='high', classification=classification, confidence=confidence)
            self.assertEqual(meets_gate(candidate), expected)
            self.assertFalse(meets_gate(replace(candidate, severity='medium')))
            self.assertFalse(meets_gate(replace(candidate, status='existing')))
            self.assertFalse(meets_gate(replace(candidate, status='suppressed')))
            self.assertFalse(meets_gate(candidate, 'none'))
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                js = root / 'app.js'
                js.write_text('eval(value)')
                self.assertEqual(main([str(js)]), 0)
                js.write_text('const cp=require("child_process"); cp.exec(value);')
                self.assertEqual(main([str(js)]), 1)
                py = root / 'test_app.py'
                py.write_text('eval(input())')
                self.assertEqual(main([str(py)]), 0)
                self.assertEqual(main([str(py), '--include-tests']), 1)
                py.write_text('def broken(')
                self.assertEqual(main([str(py), '--include-tests', '--fail-on', 'none']), 2)


if __name__ == '__main__':
    unittest.main()
