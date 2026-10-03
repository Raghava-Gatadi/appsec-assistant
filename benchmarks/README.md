# DVWA cleanup comparison

Target: [DVWA](https://github.com/digininja/DVWA), clean commit `d45ba3c4e7efa7f023f25f58ab4af9912c887057`. Only source files were read. The target was never started, imported or exercised.

## Preserved baseline

`v0.1.0` points at the originally published scanner commit `ab2233611b6fdb1d4c3c2188dc862a8e055bf900`. `baseline-v0.1.0/` holds the user's supplied HTML plus HTML/JSON/SARIF reproduced with that scanner. Local absolute target paths were replaced by `DVWA`; SARIF source-root bindings were removed. Provenance records target/scanner revisions and artifact hashes. The supplied original file's hash is also recorded; the portable copy necessarily has a different hash.

## Measured results

| Measure | 0.1.0 | 0.1.1 |
|---|---:|---:|
| Analyzed files | 194 | 195 |
| Finding locations | 17 | 10 |
| Displayed findings / groups | 17 | 6 |
| Likely vulnerabilities | 0 | 0 |
| SQL-string false positives from SEC001 | 5 | 0 |
| Direct password assignment in `sqli/test.php` retained | Yes | Yes |
| Test files excluded by policy | 0 | 2 |
| Entry-point hints | 0 | 90 |
| HTML bytes, portable regenerated report | 241,449 | 193,977 |

The new file count includes `config/config.inc.php.dist` and `composer.lock`, and excludes the Python test source. The test count also includes a previously unsupported file in the test directory. HTML is about 20% smaller despite the expanded navigation catalog and complete review queue. Repeats retain all line locations.

Entry points are navigation hints. Superglobal reads include session/environment/global state and do not prove external control or web reachability. Mitigation notes do not prove an operation safe.

## Ground truth and scoring

`dvwa-expected.json` is a small, manually reviewed matrix: four families × four levels = 16 file/CWE cases. It includes 12 expected positives (`low`, `medium`, `high`) and four expected negatives (`impossible`). Negative expectations are **CWE-specific**, not whole-file safety claims. The matrix also checks the six original SEC001 locations. The scanner contains no DVWA names or scoring exceptions.

Both versions find **0/12** expected PHP vulnerabilities and **0/4** false positives for the matrix's negative CWEs. Both provide relevant sensitive-operation navigation in **9/12** positive cases. Reflected XSS assembles an HTML variable rather than using a recognized output API, so those three navigation cases are missed. These measurements deliberately expose the PHP semantic-analysis gap; they do not represent production precision or recall.

```sh
python3 benchmarks/run.py /path/to/DVWA
python3 benchmarks/score.py benchmarks/baseline-v0.1.0/report.json
python3 benchmarks/score.py benchmarks/results-v0.1.1/report.json
```

The runner checks the pinned commit, clean checkout and hashes before scanning. It emits portable reports, provenance and scores under `results-v0.1.1/`. Timing values and hashes may differ across runs. `baseline-score.json` scores the frozen report without altering the frozen baseline directory.
