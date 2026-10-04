"""v0.1.2 regressions: language-neutral catalogs, scopes, exclusions, ranking, reporting.

Every sample is synthetic and is only read as text; nothing is executed. Each behavior
is checked in more than one language so the scanner is not tuned to a single ecosystem.
"""
import json
import tempfile
import unittest
from pathlib import Path

from appsec_assistant.cli import main
from benchmarks.score import load_target, score, table
from appsec_assistant.navigation import CATEGORIES, DOCUMENTED_GAPS, PATTERNS, static_php_path
from appsec_assistant.reports import render
from appsec_assistant.scanner import Options, generated_content_reason, scan, scan_stdin, vendored_path_reason


def check(source, name="app.py", **kwargs):
    return scan_stdin(source, name, Options(**kwargs))


def categories(result):
    return {m["category"] for m in result.code_map}


def write(root, files):
    for name, text in files.items():
        path = Path(root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


class CatalogTests(unittest.TestCase):
    def test_every_language_has_every_category_or_a_documented_gap(self):
        for language, entries in PATTERNS.items():
            present = {category for category, _ in entries}
            for category in CATEGORIES:
                with self.subTest(language=language, category=category):
                    self.assertTrue(category in present or (language, category) in DOCUMENTED_GAPS,
                                    f"{language} lacks {category} without a documented gap")

    def test_documented_gaps_are_real(self):
        for language, category in DOCUMENTED_GAPS:
            self.assertNotIn(category, {c for c, _ in PATTERNS[language]})

    def test_redirect_and_mitigation_present_in_each_language(self):
        samples = {
            "A.java": ("void f(HttpServletResponse r, String u) { r.sendRedirect(u); }", "void g(PreparedStatement s, String v) { s.setString(1, v); }"),
            "A.cs": ("void F(string u) { Response.Redirect(u); }", "void G(string v) { var n = HttpUtility.HtmlEncode(v); }"),
            "a.go": ("func f(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, u, 302) }", "func g(v string) { html.EscapeString(v) }"),
            "a.rb": ("def f\\n redirect_to params[:u]\\nend".replace("\\n", "\n"), "def g\n  sanitize(v)\nend"),
            "a.js": ("function f(res, u) { res.redirect(u); }", "function g(v) { encodeURIComponent(v); }"),
            "a.py": ("from flask import redirect\nredirect(u)", "import html\nhtml.escape(v)"),
            "a.php": ("<?php header('Location: ' . $u);", "<?php htmlspecialchars($v);"),
        }
        for name, (redirect, mitigation) in samples.items():
            with self.subTest(name=name):
                self.assertIn("redirect", categories(check(redirect, name)))
                found = check(mitigation, name)
                self.assertIn("mitigation", categories(found))
                self.assertTrue(all(m["kind"] == "note" for m in found.code_map if m["category"] == "mitigation"))

    def test_safe_sources_are_not_hotspots(self):
        self.assertFalse(check("os.path.basename(x)", "a.py").review_queue)
        self.assertFalse(check("<?php htmlspecialchars($v);", "a.php").review_queue)


class RequestVersusStateTests(unittest.TestCase):
    def test_state_never_creates_entry_points_in_any_language(self):
        samples = {
            "a.php": "<?php $a = $_SESSION['u']; $b = $GLOBALS['db']; $c = $_ENV['K']; $d = $_SERVER['DOCUMENT_ROOT'];",
            "a.js": "const k = process.env.KEY; const s = req.session;",
            "a.py": "import os\nk = os.environ['KEY']\nj = os.getenv('K')",
            "A.java": "class A { void f(HttpServletRequest r) { r.getSession(); System.getenv(\"K\"); } }",
            "a.go": "func f() { os.Getenv(\"K\") }",
            "a.rb": "def f\n  session[:u]\n  ENV['K']\nend",
            "A.cs": "class A { void F() { var s = HttpContext.Session; Environment.GetEnvironmentVariable(\"K\"); } }",
        }
        for name, source in samples.items():
            with self.subTest(name=name):
                result = check(source, name)
                self.assertIn("state", categories(result))
                self.assertNotIn("entry point", categories(result))
                self.assertNotIn("input", categories(result))
                self.assertFalse(result.review_queue)

    def test_request_input_creates_hints_when_no_routes_are_declared(self):
        samples = {
            "a.php": "<?php $x = $_GET['a'];",
            "a.js": "function h(req) { return req.query.a; }",
            "A.java": "class A { String f(HttpServletRequest r) { return r.getParameter(\"a\"); } }",
            "a.go": "func f(r *http.Request) { r.FormValue(\"a\") }",
            "a.rb": "def f\n  params[:a]\nend",
            "A.cs": "class A { void F() { var q = Request.Query; } }",
        }
        for name, source in samples.items():
            with self.subTest(name=name):
                result = check(source, name)
                self.assertIn("input", categories(result))
                self.assertIn("entry point", categories(result))

    def test_declared_routes_replace_hints(self):
        result = check("app.get('/a', (req, res) => { res.send(req.query.a); });", "a.js")
        names = [m["name"] for m in result.code_map if m["category"] == "entry point"]
        self.assertTrue(names)
        self.assertNotIn("Reads request input (entry-point hint)", names)

    def test_server_keys_split_by_control(self):
        self.assertIn("input", categories(check("<?php $h = $_SERVER['HTTP_HOST']; $q = $_SERVER['QUERY_STRING'];", "a.php")))
        only_state = check("<?php $r = $_SERVER['DOCUMENT_ROOT'];", "a.php")
        self.assertNotIn("input", categories(only_state))
        self.assertIn("state", categories(only_state))

    def test_browser_sources_are_inputs(self):
        self.assertIn("input", categories(check("const q = location.search; const r = document.referrer;", "a.js")))

    def test_go_url_query_is_input_not_database(self):
        result = check("func f(r *http.Request) { r.URL.Query() }", "a.go")
        self.assertIn("input", categories(result))
        self.assertNotIn("database query", categories(result))
        self.assertIn("database query", categories(check("func f() { db.Query(q) }", "a.go")))


class ScopeTests(unittest.TestCase):
    def test_php_functions_keep_their_own_scope(self):
        source = """<?php
function show() {
    $x = $_GET['a'];
    echo $x;
}
function save($db) {
    $db->query($sql);
    header('Location: ' . $target);
}
$y = $_POST['b'];
shell_exec($y);
"""
        result = check(source, "ctrl.php")
        scopes = {m["function"] for m in result.code_map if m["category"] != "function"}
        self.assertIn("show", scopes)
        self.assertIn("save", scopes)
        self.assertIn("<file: ctrl.php>", scopes)
        # header() and ->query() belong to the same function, not the file.
        in_save = {m["category"] for m in result.code_map if m["function"] == "save"}
        self.assertTrue({"database query", "redirect"} <= in_save)
        self.assertEqual(len(result.review_queue), 3)

    def test_each_language_uses_function_scope(self):
        samples = {
            "a.js": "function a(req) { eval(req.query.x); }\nfunction b() { }",
            "a.go": "func a(r *http.Request) { exec.Command(r.FormValue(\"x\")) }\nfunc b() {}",
            "A.java": "class A {\n    void a(HttpServletRequest r) {\n        Runtime.getRuntime().exec(r.getParameter(\"x\"));\n    }\n    void b() { }\n}",
        }
        for name, source in samples.items():
            with self.subTest(name=name):
                scopes = {m["function"] for m in check(source, name).code_map if m["category"] in {"command execution", "dynamic execution", "input"}}
                self.assertTrue(scopes)
                self.assertFalse(any(s.startswith("<file") for s in scopes), scopes)


class IncludeTests(unittest.TestCase):
    def test_constant_built_paths_are_static(self):
        for expr in ("'a.php'", "ROOT . 'lib/a.php'", "__DIR__ . '/a.php'", "dirname(__FILE__) . '/a.php'"):
            with self.subTest(expr=expr):
                self.assertTrue(static_php_path(expr))
        for expr in ("$file", "'dir/' . $file", '"a/$f.php"', "get_path() . 'a.php'", ""):
            with self.subTest(expr=expr):
                self.assertFalse(static_php_path(expr))

    def test_dynamic_include_is_still_navigation(self):
        self.assertNotIn("dynamic execution", categories(check("<?php require_once APP_ROOT . 'inc/a.php'; include __DIR__ . '/b.php';", "a.php")))
        self.assertIn("dynamic execution", categories(check("<?php include $page;", "a.php")))
        self.assertIn("dynamic execution", categories(check("<?php require_once APP_ROOT . $page;", "a.php")))


class ExclusionTests(unittest.TestCase):
    def test_path_reasons(self):
        for path in ("vendor/lib/a.js", "app/assets/vendor/x.js", "third_party/a.py", "bower_components/a/b.js",
                     "wwwroot/lib/jquery/a.js", "static/jquery.min.js", "dist-x/app.bundle.js"):
            with self.subTest(path=path):
                self.assertTrue(vendored_path_reason(path))
        for path in ("app.js", "src/vendors_list.js", "src/vendorize.py", "lib/a.js", "minify.js"):
            with self.subTest(path=path):
                self.assertIsNone(vendored_path_reason(path))

    def test_minified_and_generated_content(self):
        self.assertEqual(generated_content_reason("a.js", "a=" + "x+" * 3000), "minified or obfuscated file")
        self.assertIsNone(generated_content_reason("a.js", "function f() {}\n" * 300))
        self.assertEqual(generated_content_reason("a.go", "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage a\n"), "generated file")
        self.assertEqual(generated_content_reason("a.py", "# @generated\nx = 1\n"), "generated file")
        self.assertIsNone(generated_content_reason("a.py", "x = 1\n" * 10))
        # Lockfiles say "@generated" but are dependency data that the inventory reads.
        self.assertIsNone(generated_content_reason("composer.lock", '{"_readme": ["This file is @generated automatically"], "packages": []}'))
        self.assertIsNone(generated_content_reason("poetry.lock", "# This file is automatically @generated by Poetry\n"))
        # Minified detection applies to JS/TS only; long data lines in other types are not code.
        self.assertIsNone(generated_content_reason("data.json", '{"k": "' + "x" * 5000 + '"}'))

    def test_scan_excludes_and_counts_and_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, {
                "app.js": "function f(x) { eval(x); }\n",
                "vendor/lib.js": "function f(x) { eval(x); }\n",
                "static/jquery.min.js": "eval(x)",
                "static/bundle.js": "a=" + "eval(x);" * 500,
                "gen/api.go": "// Code generated by tool. DO NOT EDIT.\npackage a\n",
                "vendor/composer.json": '{"require": {"a/b": "1.0"}}',
            })
            result = scan(Path(tmp), Options())
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.vendored_files_excluded, 5)
            self.assertEqual({f.path for f in result.findings}, {"app.js"})
            self.assertFalse(result.inventory)
            self.assertTrue(any("vendored, generated or minified files excluded" in d["reason"] for d in result.diagnostics))
            self.assertTrue(result.complete)
            self.assertEqual(result.to_dict()["summary"]["vendored_files_excluded"], 5)
            self.assertIn("5 vendored/generated/minified files excluded", render(result, "html"))
            everything = scan(Path(tmp), Options(include_vendored=True))
            self.assertEqual(everything.vendored_files_excluded, 0)
            self.assertGreaterEqual(everything.files_scanned, 5)

    def test_only_vendored_files_is_not_an_empty_scan_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, {"vendor/a.js": "eval(x)"})
            self.assertTrue(scan(Path(tmp), Options()).complete)

    def test_cli_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, {"app.js": "var a = 1;\n", "vendor/a.js": "eval(x)"})
            out = Path(tmp) / "out" / "r.json"
            out.parent.mkdir()
            self.assertEqual(main([tmp, "-o", str(out), "--fail-on", "none"]), 0)
            self.assertEqual(json.loads(out.read_text())["findings"], [])
            self.assertEqual(main([tmp, "-o", str(out), "--include-vendored", "--fail-on", "none"]), 0)
            self.assertTrue(json.loads(out.read_text())["findings"])


class RankingTests(unittest.TestCase):
    def test_unmitigated_scope_outranks_mitigated_even_when_path_sorts_later(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, {
                "a_safe.php": "<?php\n$id = $_GET['id'];\n$id = intval($id);\nshell_exec('ping ' . $id);\n",
                "z_unsafe.php": "<?php\n$id = $_GET['id'];\nshell_exec('ping ' . $id);\n",
            })
            queue = scan(Path(tmp), Options()).review_queue
            self.assertEqual([q["path"] for q in queue], ["z_unsafe.php", "a_safe.php"])
            self.assertFalse(queue[0]["mitigated"])
            self.assertTrue(queue[1]["mitigated"])
            self.assertGreater(queue[0]["rank"], queue[1]["rank"])
            self.assertIn("no mitigation API was seen", queue[0]["reason"])
            self.assertIn("lowers priority but does not show safety", queue[1]["reason"])

    def test_mitigated_scope_is_still_listed(self):
        queue = check("<?php $a = $_GET['a']; $a = intval($a); shell_exec($a);", "a.php").review_queue
        self.assertEqual(len(queue), 1)

    def test_closer_input_ranks_first_and_operation_severity_breaks_ties(self):
        far = "<?php\n$a = $_GET['a'];\n" + "\n" * 30 + "mysqli_query($c, $a);\n"
        near = "<?php\n$a = $_GET['a'];\nmysqli_query($c, $a);\n"
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, {"a_far.php": far, "z_near.php": near})
            queue = scan(Path(tmp), Options()).review_queue
            self.assertEqual(queue[0]["path"], "z_near.php")
            self.assertEqual((queue[0]["evidence"], queue[1]["evidence"]), (3, 2))
        # A more severe operation outranks a less severe one with the same evidence.
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, {"a_read.php": "<?php\n$a = $_GET['a'];\nfile_get_contents($a);\n",
                        "z_exec.php": "<?php\n$a = $_GET['a'];\nshell_exec($a);\n"})
            self.assertEqual(scan(Path(tmp), Options()).review_queue[0]["path"], "z_exec.php")

    def test_ordering_is_not_alphabetical_for_non_ties(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = {f"m{i:02d}.js": "function f(a) { return a; }\napp.get('/x', (req, res) => { res.send(1); });\n" for i in range(25)}
            files["zzz.js"] = "function g(req) { eval(req.query.q); }\n"
            write(tmp, files)
            result = scan(Path(tmp), Options())
            self.assertEqual(result.review_queue[0]["path"], "zzz.js")
            self.assertEqual(result.to_dict()["review_queue_omitted"], 6)

    def test_python_function_scopes_use_the_same_ranking(self):
        source = ("from flask import request\nimport os\n"
                  "def safe():\n    v = int(request.args['n'])\n    os.system('ls')\n"
                  "def risky():\n    v = request.args['n']\n    os.system(v)\n")
        queue = [q for q in check(source).review_queue if q["function"] in {"safe", "risky"}]
        self.assertEqual(queue[0]["function"], "risky")

    def test_queue_entries_are_explainable_in_every_format(self):
        result = check("<?php $a = $_GET['a']; shell_exec($a);", "a.php")
        item = result.review_queue[0]
        self.assertEqual((item["evidence"], item["mitigated"]), (3, False))
        self.assertIn("command execution", item["reason"])
        self.assertIn("share this scope", render(result, "text"))
        self.assertIn("share this scope", render(result, "html"))
        self.assertIn("share this scope", json.dumps(result.to_dict()))


class ReportTests(unittest.TestCase):
    def test_headline_stats_do_not_conflate_confidence(self):
        source = "function a(x) { a.innerHTML = x; }\nfunction b(x) { eval(x); }"
        result = check(source, "a.js")
        summary = result.to_dict()["summary"]
        self.assertEqual(summary["likely_vulnerabilities"], 0)
        self.assertEqual(summary["low_confidence_hotspots"], len(result.finding_groups))
        self.assertEqual(summary["review_findings_medium_plus"], 0)
        html = render(result, "html")
        for label in ("Likely vulnerabilities", "Review hotspots (medium+ confidence)", "Low-confidence hotspots"):
            self.assertIn(label, html)
        self.assertNotIn("High / critical", html)
        self.assertIn("A clean report is not evidence", html)
        text = render(result, "text")
        self.assertIn("Low-confidence hotspots", text)

    def test_state_rows_are_collapsed_with_inputs(self):
        html = render(check("import os\nk = os.environ['K']\n"), "html")
        self.assertIn("Input and state locations (1)", html)
        self.assertIn('<details id="map-inputs">', html)


class BenchmarkScoringTests(unittest.TestCase):
    TARGET = {"name": "t", "role": "held-out", "cases": [
        {"path": "a.py", "function": "bad", "line": 3, "cwe": "CWE-78", "expected_vulnerable": True, "navigation_category": "command execution"},
        {"path": "a.py", "function": "good", "line": 9, "cwe": "CWE-78", "expected_vulnerable": False, "navigation_category": "command execution"},
        {"path": "b.js", "line": 5, "cwe": "CWE-78", "expected_vulnerable": False, "navigation_category": "command execution",
         "queue_comparable": False}]}

    def report(self, queue, findings=(), code_map=()):
        return {"review_queue": queue, "findings": list(findings), "code_map": list(code_map)}

    def test_target_files_are_valid_and_language_agnostic(self):
        for name in ("dvwa", "nodegoat", "vulnerable-flask-app"):
            target = load_target(name)
            self.assertIn(target["role"], {"dev", "held-out"})
            self.assertEqual(len(target["commit"]), 40)
            for case in target["cases"]:
                self.assertTrue({"path", "cwe", "expected_vulnerable", "navigation_category", "sha256"} <= set(case), case)
        roles = {load_target(n)["role"] for n in ("dvwa", "nodegoat", "vulnerable-flask-app")}
        self.assertEqual(roles, {"dev", "held-out"})
        self.assertGreaterEqual(len({tuple(load_target(n)["languages"]) for n in ("dvwa", "nodegoat", "vulnerable-flask-app")}), 3)

    def test_no_findings_means_precision_and_recall_are_unavailable(self):
        result = score(self.report([{"path": "a.py", "function": "bad"}]), self.TARGET)
        self.assertFalse(result["findings"]["reported"])
        self.assertNotIn("false_positive_rate", result["findings"])
        self.assertIn("not reported", result["findings"]["reason"])
        self.assertIn("no findings emitted", table([("r", result)]))

    def test_metrics_reported_once_findings_exist(self):
        finding = {"path": "a.py", "function": "bad", "cwe": "CWE-78", "classification": "likely-vulnerability", "rule_id": "PY001"}
        result = score(self.report([], [finding]), self.TARGET)
        self.assertEqual((result["findings"]["recall"], result["findings"]["precision"], result["findings"]["false_positive_rate"]), (1.0, 1.0, 0.0))
        wrong = dict(finding, function="good")
        result = score(self.report([], [finding, wrong]), self.TARGET)
        self.assertEqual((result["findings"]["precision"], result["findings"]["false_positive_rate"]), (0.5, 0.5))

    def test_queue_labels_use_function_and_ordering_is_pairwise(self):
        queue = [{"path": "a.py", "function": "bad"}, {"path": "a.py", "function": "other"}, {"path": "a.py", "function": "good"}]
        q = score(self.report(queue), self.TARGET)["queue"]
        self.assertEqual((q["positives_in_top_k"], q["recall_at_k"]), (1, 1.0))
        self.assertEqual((q["labeled_positive_entries_in_top_k"], q["labeled_negative_entries_in_top_k"], q["unlabeled_entries_in_top_k"]), (1, 1, 1))
        self.assertEqual(q["labeled_precision_at_k"], 0.5)
        self.assertEqual((q["pairwise_ordering"]["pairs"], q["pairwise_ordering"]["positive_first"]), (1, 1))
        reversed_queue = [queue[2], queue[0]]
        self.assertEqual(score(self.report(reversed_queue), self.TARGET)["queue"]["pairwise_ordering"]["positive_first"], 0)

    def test_non_comparable_cases_do_not_affect_ordering_and_depth_is_respected(self):
        queue = [{"path": "b.js", "function": "<file: b.js>"}, {"path": "a.py", "function": "bad"}]
        q = score(self.report(queue), self.TARGET)["queue"]
        self.assertEqual(q["labeled_negative_entries_in_top_k"], 0)
        self.assertEqual(score(self.report(queue), self.TARGET, k=1)["queue"]["positives_in_top_k"], 0)

    def test_localized_navigation_requires_category_near_expected_line(self):
        item = lambda line, cat="command execution": {"path": "a.py", "function": "bad", "line": line, "category": cat}  # noqa: E731
        self.assertEqual(score(self.report([], code_map=[item(5)]), self.TARGET)["counts"]["navigation_localized"], 1)
        self.assertEqual(score(self.report([], code_map=[item(40)]), self.TARGET)["counts"]["navigation_localized"], 0)
        self.assertEqual(score(self.report([], code_map=[item(3, "input")]), self.TARGET)["counts"]["navigation_localized"], 0)
        self.assertEqual(score(self.report([]), self.TARGET)["counts"]["navigation_matches"], 0)

    def test_old_reports_without_a_queue_are_handled(self):
        result = score({"findings": [], "code_map": []}, self.TARGET)
        self.assertFalse(result["queue"]["available"])


if __name__ == "__main__":
    unittest.main()
