# Changelog

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
