# Validation — v0.1.2

## Completed locally

- **88 unittest tests passed** (54 existing, 34 new) on Python 3.12. Tests use inert synthetic source and do not execute scanned applications. Two existing tests changed because the behavior they asserted was deliberately replaced: state superglobals no longer create entry points, and the collapsed code-map section is labeled "Input and state".
- **Ruff:** all selected correctness checks passed. The scanner still has no runtime dependencies.
- **Report filter script:** `node tests/report_filters.js` passed against the actual embedded script after the code-map filter change.
- **Cross-language checks:** every language has every navigation category or a documented gap; redirect and mitigation entries in seven languages; request-versus-state separation in seven languages; entry-point hints only when no routes are declared; function scopes in PHP, JavaScript, Go and Java; Java and C# methods without access modifiers; constant-built PHP include paths; vendored directory, minified, bundled and generated-file exclusion, lockfiles retained, the `--include-vendored` flag and exclusion counts; mitigation-aware, proximity-aware and severity-aware queue ordering without an alphabetical tie-break; headline statistics.
- **Benchmark scorer:** tests for target-file validity, unavailable precision/recall when no findings exist, per-function labeling, pairwise ordering, non-comparable cases, queue depth, line localization and reports without a queue.
- **Before/after on four unrelated projects** (v0.1.1 commit versus this tree; no tuning to any of them): DVWA (PHP), NodeGoat (JavaScript), Vulnerable-Flask-App and pygoat (Python). Python findings were unchanged on pygoat (28 groups, 6 likely) and Vulnerable-Flask-App (3 likely). Every finding that disappeared came from a file now excluded as vendored, minified or generated; none came from application code. One initial regression was found and fixed during this check: `composer.lock` was being excluded as "generated" and is now retained, with a test.
- **Benchmarks:** DVWA (dev), Vulnerable-Flask-App and NodeGoat (held-out) run from pinned, clean checkouts with hash checks. See [benchmarks/README.md](benchmarks/README.md).
- **Demo artifacts** regenerated for 0.1.2 with portable paths.

## Limits and checks still requiring another environment

- **GitHub Actions** defines Python 3.11–3.14 checks. Only Python 3.12 was executed here; a configured workflow is not evidence of a hosted run.
- **SARIF schema validation was not repeated** for this release. The SARIF structure changed only by the existing `rank` and `properties` fields; re-validate against the OASIS 2.1.0 schema before relying on it.
- DOM-stub tests verify filter logic, not browser layout, accessibility or compatibility. No browser automation was used.
- Benchmark matrices are small (16, 5 and 4 cases). PHP vulnerability recall is still 0/12: this release improves where reviewers look first, not detection. NodeGoat exposes JavaScript gaps (no redirect rule; `$where` NoSQL injection not modeled).
- DVWA is a development target; its numbers are not evidence of generalization.
- No production-scale precision/recall, Windows behavior, parser fuzzing, live advisory lookup or broad framework validation is claimed. The new lexical function patterns for Java and C# were tested on small samples, not large codebases.

## Reproduce

```sh
python3 -m unittest discover -s tests -v
python3 -m pip install -r requirements-dev.txt
python3 -m ruff check .
node tests/report_filters.js  # optional Node development runtime
python3 benchmarks/run.py dvwa /path/to/pinned/clean/DVWA
python3 benchmarks/run.py vulnerable-flask-app /path/to/pinned/clean/Vulnerable-Flask-App
python3 benchmarks/run.py nodegoat /path/to/pinned/clean/NodeGoat
```
