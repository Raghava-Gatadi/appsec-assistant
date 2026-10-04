# Changelog

## 0.1.2 — 2026-10-03

Behavior is now consistent across languages instead of PHP-specific.

- **Language-neutral catalog.** Every code language uses the same navigation categories, including `redirect`, `mitigation` and the new `state`. Java, C#, Go and Ruby gain redirect and mitigation entries; JavaScript, Python, Java, C#, Go and Ruby gain request-input and state entries. A test fails if a language lacks a category without a documented gap (today: Go dynamic execution).
- **Request input versus server state.** `$_SESSION`, `$GLOBALS`, `$_ENV`, most `$_SERVER` keys, `process.env`, `os.environ`, `getSession()`, `ENV[]` and similar are `state` notes. Only request-controlled input creates entry-point hints and raises ranking. `$_SERVER['HTTP_*']`, `QUERY_STRING` and similar remain input.
- **One scope model.** PHP no longer forces file scope. Function and method scopes are used in every language; `<file>` applies only outside functions. Java and C# methods without an access modifier now get function scopes. Every lexical item, including PHP redirects, includes and password hashes, carries its function scope.
- **Entry-point hints generalized.** A file that declares no routes gets a hint per scope that reads request input, in any lexical language.
- **Vendored, minified and generated code excluded by default** (`vendor/`, `third_party/`, `bower_components/`, `wwwroot/lib/`, `*.min.js`, bundles, minified or obfuscated JavaScript/TypeScript, and source files marked generated). Lockfiles are never skipped as generated. Add `--include-vendored` to analyze them; diagnostics and the report show the exclusion count and reasons.
- **Explainable, mitigation-aware "Where to start".** Evidence levels combine request input, an operation, proximity (within 10 lines) and the absence of a mitigation in the same scope. A mitigation lowers rank without removing the entry. Ties break by operation severity and input distance; there is no alphabetical tie-break. Each entry says why it ranks where it does. Queue JSON gains `evidence`, `distance`, `mitigated` and `operation_weight`.
- **PHP include paths built from literals and constants** (`__DIR__ . '/a.php'`, `ROOT . 'lib/a.php'`) are no longer listed as dynamic execution.
- **Honest headline statistics.** The report separates likely vulnerabilities, review hotspots with medium or higher confidence, and low-confidence hotspots, and drops the combined "High / critical" tile. JSON summary adds `review_findings_medium_plus`, `low_confidence_hotspots` and `vendored_files_excluded`. Input and state rows are collapsed together in the code map.
- **Target-agnostic benchmarks.** Matrices move to `benchmarks/targets/` with `dev` and `held-out` roles. The runner and scorer contain no application names. Queue metrics (top-k, pairwise ordering, localized sinks, labeled precision) replace the lenient file-level navigation check, and precision/recall are reported only when findings exist. Targets: DVWA (dev), Vulnerable-Flask-App and NodeGoat (held-out).
- Demo artifacts regenerated; 88 tests (34 new).

Deferred: PHP and Java parsing, same-scope source-to-sink hints for lexical languages, JavaScript redirect and NoSQL rules, interprocedural taint.

## 0.1.1 — 2026-10-03

- Exclude conventional tests by default; add `--include-tests` and exclusion counts. Keep bare `test.php` included.
- Share ranking across findings, review scopes and SARIF. Expose scopes beyond the first 20.
- Group repeated findings by rule/scope, retaining all locations, fingerprints and review states. JSON report schema becomes 2; baseline schema remains 1.
- Show likely-vulnerability counts separately from high/critical severity counts.
- Require direct literal credential assignments across supported source/configuration checks; stop matching SQL text inside strings.
- Analyze template-suffixed source/manifests and inventory Composer manifests/lockfiles.
- Use PHP file scopes, superglobal-read entry-point hints, a broader navigation catalog and mitigation notes. No PHP data-flow rules added.
- Collapse input map rows and fold repeated symbols into location lists; show guidance once per category.
- Gate CI on severity threshold plus likely-vulnerability label or medium/high confidence. Low-confidence hotspots stay visible without failing builds.
- Preserve the v0.1.0 DVWA baseline; add a pinned, limited file/CWE matrix and reproducible report scoring.
- Add cleanup regression tests, lint configuration and GitHub Actions for Python 3.11–3.14.

## 0.1.0

Initial offline Python/JavaScript security triage, multi-language navigation, configuration/secret rules, report formats, baselines and suppressions.
