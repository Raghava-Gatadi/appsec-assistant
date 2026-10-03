# Validation — v0.1.1

## Completed locally

- **54 unittest tests**, including all 32 existing finding rules and new cleanup regressions, passed on Python 3.13. Tests use inert synthetic source and do not execute scanned applications.
- **Ruff 0.16.10:** all selected correctness checks passed (`E4`, `E7`, `E9`, `F`). The scanner still has no runtime dependencies.
- **Cross-language cleanup:** conventional test exclusion/override, suffix handling, direct literal credential assignments across Python/JS/TS/PHP/Java/C#/Go/Ruby/configuration, scope grouping, all occurrence fingerprints, mixed baseline/suppression states, rank precedence and CI confidence gating.
- **Navigation:** PHP file scopes, superglobal reads versus direct writes, fixed versus dynamic includes, output/redirect/crypto/upload APIs and mitigation-only notes. Python/JS mitigation notes also covered. Same-named declarations at different lines remain separate scopes.
- **Reports:** grouped locations, queue overflow, likely-vulnerability statistic, collapsed input rows, shared guidance, escaping and credential redaction. Actual embedded filter JavaScript passed DOM-stub tests using macOS JavaScriptCore through the CLI. `tests/report_filters.js` runs the same checks under Node in CI.
- **SARIF:** demo, DVWA before/after, and grouped trace results validated against the official OASIS SARIF 2.1.0 JSON schema, using jsonschema 4.26.0. The schema was downloaded for validation only; report generation remains offline.
- **CLI:** exit codes 0/1/2, test override, complete versus incomplete scans, confidence gate, baseline output retaining every grouped occurrence, and source/output protection.
- **DVWA:** reproduced the published v0.1.0 baseline and compared the same clean pinned checkout to v0.1.1. Findings changed from 17 locations to 10 locations in six groups; the five SQL-string SEC001 false positives disappeared and the direct assignment in `sqli/test.php` remains. See [benchmarks/README.md](benchmarks/README.md).
- **Static demo:** all nine example files scanned, with 11 finding groups; HTML, JSON and SARIF refreshed for 0.1.1.

## Limits and checks still requiring another environment

- GitHub Actions defines Python 3.11–3.14 checks. Only Python 3.13 was executed locally; a configured workflow is not evidence of a successful hosted run.
- DOM-stub tests verify filtering logic, not browser layout, accessibility or browser compatibility. No desktop/browser automation was used for this release.
- The DVWA matrix covers only 16 selected file/CWE cases. PHP vulnerability recall remains 0/12 positives; navigation covers 9/12. Source-to-sink PHP analysis remains deferred. No exploitability was tested.
- No production-scale precision/recall, Windows behavior, parser fuzzing, live advisory lookup or broad framework validation is claimed.

## Reproduce

```sh
python3 -m unittest discover -s tests -v
python3 -m pip install -r requirements-dev.txt
python3 -m ruff check .
node tests/report_filters.js  # optional Node development runtime
python3 benchmarks/run.py /path/to/pinned/clean/DVWA
```

SARIF schema source: [OASIS SARIF 2.1.0 schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json).
