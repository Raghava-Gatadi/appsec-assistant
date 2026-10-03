# AppSec Assistant

A local, offline Python tool for the **first pass of a source security review**. Give it a folder; it discovers supported files, maps entry points and sensitive APIs, and produces a prioritized reading list with rule findings and remediation guidance.

It helps answer: **Which functions should I inspect first, what looks suspicious, and what evidence still needs checking?** It assists an analyst; it does not certify an application or establish exploitability.

## Quick start

Requires **Python 3.11+**. The scanner has **no runtime dependencies**. No API key, server, package installation, or network connection is needed.

From this project's folder:

```sh
python3 scan.py /path/to/source
python3 scan.py /path/to/source -o report.html
```

Open `report.html` in a browser. It is a self-contained, searchable report with:

- **Where to start:** up to 20 scopes prioritized using findings, input sources and sensitive operations.
- **Findings:** file, line, function, severity, confidence, evidence, CWE link, remediation and verification questions.
- **Code map:** entry points, inputs, sensitive operations and function declarations, including APIs used safely.
- **File inventory:** each supported file and the analysis performed on it.
- **Dependency inventory:** declared packages, with advisory status explicitly marked **not checked**.
- Diagnostics, scan policy, coverage limits and a manual review agenda.

The source is parsed or read as text. The scanner never imports or executes the target, installs its dependencies, sends its source to a model, or contacts its services.

### Try the included static fixtures

```sh
python3 scan.py examples -o demo-report.html --fail-on none
```

The example files are **inert inspection fixtures**, not an application to run or deploy. Their credential-like values are synthetic. A generated `demo-report.html` is included.

## What the labels mean

| Label | Meaning | Analyst action |
|---|---|---|
| **Likely vulnerability** | A finding has stronger evidence, such as request input reaching a sensitive operation or an explicit verification bypass. | Check callable identity, reachability, input trust and existing controls. |
| **Review hotspot** | A potentially unsafe pattern, sensitive API, input source or entry point needs inspection. Safe use is possible. | Trace the surrounding code and validate assumptions. |
| **Note** | A function declaration included for navigation. | Use it to orient your review. |

**None of these labels means confirmed exploitability.** Severity estimates potential impact; confidence describes the strength of the match. They are separate from the label. Priority ordering is a reading aid, not a CVSS score. No findings does not mean a file is safe.

A safely parameterized SQL call remains in the code map but does not receive the dynamic SQL finding. A function parameter has **unknown trust**; recognized request input provides stronger evidence. Outbound URL and filesystem path flows remain review hotspots because the scanner cannot establish the effectiveness of all surrounding controls.

## Language coverage

| Files | Analysis |
|---|---|
| Python `.py`, `.pyw` | AST checks, import/call aliases, selected HTTP client instances, bounded local input propagation through assignments and branch joins; function and decorator-based route map. |
| JavaScript / TypeScript, including JSX, TSX, MJS, CJS, MTS, CTS | Lexical checks for dynamic execution, explicit child-process imports, raw HTML, TLS bypasses and simple SQL construction; approximate function and route map. |
| PHP, Java, C#, Go, Ruby | Lexical navigation map of sensitive APIs, selected input sources, routes and declarations; generic secret checks. **No semantic vulnerability analysis for these languages.** |
| JSON, YAML, TOML, INI, environment files, Dockerfiles and selected other text/code formats | Limited secret and configuration checks. A file's presence in inventory does not imply complete security coverage. |

There are **32 finding rules**: 17 Python, 6 JavaScript/TypeScript, 6 configuration and 3 secret rules. The navigation catalog is separate from these rules.

```sh
python3 scan.py --list-rules
```

Finding families include dynamic SQL, shell commands, dynamic evaluation, unsafe object/YAML loading, template source injection, HTML escaping bypasses, input-dependent URLs and paths, redirects, JWT verification bypasses, TLS settings, weak hashes, temporary files, security-related randomness, debug mode, cookies, CORS and literal credentials.

## Commands

```sh
# Folder is the positional argument; nested folders are scanned automatically.
python3 scan.py /path/to/source

# Formats are inferred from the output suffix, or selected explicitly.
python3 scan.py /path/to/source -o report.html
python3 scan.py /path/to/source -o findings.json
python3 scan.py /path/to/source -o findings.sarif
python3 scan.py /path/to/source --format json

# Keep higher-confidence findings; the navigation map remains available.
python3 scan.py /path/to/source --min-confidence medium --min-severity medium

# Exclude root-relative paths. Quote globs so the shell does not expand them.
python3 scan.py /path/to/source --exclude 'vendor/**' --exclude '**/*.min.js'

# Inspect one file, or accept source from standard input.
python3 scan.py /path/to/source/app.py
cat /path/to/source/handler.ts | python3 scan.py - --stdin-name handler.ts

# CI: fail only on new findings at/above this severity.
python3 scan.py /path/to/source --fail-on high -o findings.sarif

# Return success regardless of finding severity, while still failing on scan errors.
python3 scan.py /path/to/source --fail-on none -o review.html
```

`python3 -m appsec_assistant` is an equivalent entry point from this directory. An optional console command can be installed with `python3 -m pip install .`; this can require downloading the build tool. Direct execution of `scan.py` needs no installation.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No **new, unsuppressed, reported** finding meets `--fail-on`, or `--fail-on none` was used. |
| `1` | A new reported finding meets the severity threshold; the scan/report still completed. |
| `2` | Invalid input/policy, read or parse failure, resource limit, no supported files, or output failure. Check diagnostics. |

The default threshold is `high`. Navigation hotspots by themselves do not fail CI. Severity/confidence filters apply before threshold evaluation, and the report counts filtered findings. An incomplete scan always returns `2`, even with `--fail-on none`.

## Baselines and reviewed suppressions

Create a baseline **after reviewing the existing results**:

```sh
python3 scan.py /path/to/source --write-baseline baseline.json --fail-on none
python3 scan.py /path/to/source --baseline baseline.json -o next-review.html
```

Baseline matches stay visible with status `existing` and do not fail CI. Fingerprints include the root-relative path, rule, normalized source line and duplicate occurrence. Adding unrelated lines usually preserves identity; changing a line or renaming a file creates a new identity. Baselines are for one repository and scan root. A baseline contains only findings retained under the selected filters. An incomplete scan never writes one.

Use an explicit JSON policy for exclusions or reviewed exceptions:

```json
{
  "excludes": ["generated/**"],
  "suppressions": [
    {
      "rule_id": "PY007",
      "path": "tools/checksum.py",
      "reason": "Reviewed: this checksum is not used for a security decision.",
      "expires": "2099-01-01"
    }
  ]
}
```

```sh
python3 scan.py /path/to/source --config policy.json -o report.html
```

The date above demonstrates the format; choose an appropriate review date for your project. A suppression needs a reason and either an exact fingerprint or a rule/path pair. Expired or malformed suppressions cause an error. Suppressed findings stay visible; navigation entries remain available. The tool does not automatically trust a policy, `.gitignore`, or inline suppression comments found in the target repository. See `policy.example.json`.

## Scope, privacy and operational limits

- Analysis is **intraprocedural**. It does not trace calls across functions/files, compute a complete call graph, resolve every alias or dynamic framework feature, or establish reachability.
- Python branch joins are conservative, and loops are approximated with one body pass plus the zero-iteration possibility. Reflection, complex object state, pattern bindings, closures, comprehensions and exceptions are not fully modeled. Framework request sources are name-based heuristics.
- Sanitizers and custom validation are not proven correct. Wrapper calls can retain input taint and generate false positives. Unknown flows, positional options and framework variants can be missed.
- Non-Python checks are lexical. Strings/comments are masked for many code checks, but templates, regex literals, unusual syntax and multiline constructs can cause missed or extra locations. Non-Python function scope is approximate; anonymous callbacks may be unresolved. Ruby/PHP lexical support is particularly limited.
- Authentication, authorization, business logic, tenant isolation and deployment policy require human review. The report includes a checklist for those areas.
- Dependency inventory supports `requirements*.txt`, PEP 621 dependency arrays in `pyproject.toml`, and `package.json`. It does not resolve lockfiles, transitive dependencies, includes, installed versions, or CVEs. URL-style dependency specifiers are withheld.
- Secret detection is heuristic: named string literals (8+ characters), selected provider shapes and private key headers. Encoded/split secrets and other token formats may be missed; fixtures can be flagged. Detected literal values and raw source snippets are omitted from reports. Paths, identifiers, dependency metadata, flow labels and user-provided suppression reasons remain visible, so treat reports as project information.
- Binary content, invalid encoding and malformed Python are reported explicitly. Python respects source encoding declarations; other text uses UTF-8. Python syntax support follows the interpreter running the scanner.
- Defaults: 2 MB/file, 100 MB total, 10,000 filesystem entries, 100,000 Python AST nodes and 64 directory levels. Size/parser limit hits make the scan incomplete. Limits can be adjusted with `--max-file-bytes`, `--max-total-bytes`, `--max-files` and `--max-python-nodes`.
- Default directory exclusions: `.git`, `.hg`, `.svn`, `.venv`, `venv`, `env`, `node_modules`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.next`, `dist`, `build`, `coverage`, `.tox`. Tests are **not** automatically excluded. Excluded directories appear in diagnostics; skipped-file counts do not count their unseen contents. Scan an excluded directory directly if you need to inspect it.
- Symlinks and special files are not followed. Scan a stable checkout, not a directory being actively mutated. Resource limits are safeguards, not a hardened sandbox against malicious parser inputs; use an OS sandbox for hostile repositories.
- HTML is self-contained with escaped metadata and a restrictive content security policy. New report files use private temporary-file permissions where supported. An explicitly named output file is replaced atomically; choose a report path, not an existing project asset. Source-file targets and policy inputs are protected from overwrite.
- This initial implementation is tested against synthetic cases. It has not been benchmarked for production precision/recall and is not a replacement for maintained language-specific analyzers or a professional review.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests cover every finding rule, safer alternatives, aliases, scope and branch behavior, trace retention, Unicode positions, multi-language maps, redaction, report escaping, baselines, suppressions, CLI exit codes, resource limits and non-execution of target code.

## Extending the tool

- `appsec_assistant/rules.py`: rule definitions, CWE references and review/remediation text.
- `appsec_assistant/python_analyzer.py`: AST and local data-flow checks.
- `appsec_assistant/text_analyzer.py`: lexical JavaScript/configuration/secret checks.
- `appsec_assistant/navigation.py`: entry-point and sensitive-API navigation catalogs.
- `appsec_assistant/scanner.py`: traversal, coverage, inventory and scan policy.
- `appsec_assistant/reports.py`: text, JSON, HTML and SARIF output.

Add both a suspicious example and a safe alternative when adding a rule. Keep navigation-only matches separate from findings with stronger evidence.

## References

The design follows the distinction between automated findings and contextual manual review described in the [OWASP Secure Code Review Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html). SQL remediation follows the [Python sqlite3 documentation](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries). The interchange report targets [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
