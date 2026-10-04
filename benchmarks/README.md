# Benchmarks

The benchmark measures a **triage** tool: does "Where to start" put the scopes a reviewer should read first near the top, and does it order a vulnerable scope above a safe one? Finding precision and recall are reported only when the scanner emitted findings for the listed CWEs. Otherwise they are marked unavailable, because "0 false positives" means nothing when nothing could be flagged.

## Targets

One JSON matrix per application in [`targets/`](targets). Each pins a repository commit, records source hashes, and is marked:

| Role | Rule |
|---|---|
| `dev` | Scanner rules may be tuned against it. |
| `held-out` | Measure only. Never tune rules against it. |

| Target | Role | Language | Cases |
|---|---|---|---|
| `dvwa` | dev | PHP | 16 (12 positive, 4 negative) |
| `vulnerable-flask-app` | held-out | Python | 5 (3 positive, 2 negative), function level |
| `nodegoat` | held-out | JavaScript | 4 (3 positive, 1 negative) |

Expected sink lines were located by reading the pinned source, independently of scanner output. The scripts contain no application names; the scanner never reads a matrix and does not special-case application paths. Matrices are small and manually reviewed. They are not audits.

```sh
python3 benchmarks/run.py --list
python3 benchmarks/run.py <target> /path/to/clean/pinned/checkout     # writes benchmarks/results/<target>-v<version>/
python3 benchmarks/score.py <report.json> [...] --target <target> --table
python3 benchmarks/score.py <report.json> --target <target> -k 50      # deeper queue
```

The runner checks the pinned commit, a clean checkout and the recorded hashes before scanning. The target is only read, never started or imported. Reports are portable (no local paths) and each run records provenance.

## Metrics

- **Positives in top-k:** known-vulnerable scopes present in the first k queue entries (default 20).
- **Pairwise ordering:** among positive/negative pairs with the same CWE, how often the positive ranks first. Ranks outside the top k count as ties. Cases marked `queue_comparable: false` are skipped, with the reason recorded in the matrix.
- **Localized sinks:** a sink of the expected category within 10 lines of the expected line.
- **Labeled precision@k:** positive entries divided by labeled entries in the top k. Entries are labeled per function when a case names one, otherwise per file. Unlabeled entries are unknown, not false.
- **Findings P/R:** reported only when findings exist for the listed CWEs.

## Results

### DVWA (dev, PHP)

| Report | Positives in top 20 | Pairwise ordering | Localized sinks | Labeled precision@20 | Findings P/R |
|---|---:|---:|---:|---:|---|
| v0.1.0 (frozen baseline) | 0/12 | 0/18 (all ties) | 9/12 | n/a | none emitted |
| v0.1.1 | 3/12 | 1/18 (ties 15) | 9/12 | 0.75 | none emitted |
| v0.1.2 | 6/12 | 9/18 (ties 9) | 9/12 | 0.857 | none emitted |

At depth 50 the v0.1.0 report is unavailable (it stored only 20 queue entries); v0.1.1 and v0.1.2 both place 8/12 positives, and ordering improves from 6/18 to 11/18 pairs (ties 3 in both).

Findings are still not emitted for PHP: **PHP vulnerability recall remains 0/12.** The gain is in where the reviewer looks first, not in detection. Known limits visible in the matrix:

- Reflected XSS (3 positives) assembles an `$html` variable instead of calling an output API, so its sink is not in the catalog. These rank around 165 of 168.
- `sqli/high.php` reads its id from `$_SESSION` (set by an earlier request). The request/state split classifies it as state, so it ranks lower. This is a real trade-off of the split: second-order flows through session state are only visible as a state note.
- `sqli/medium.php` calls `mysqli_real_escape_string`, a mitigation that lowers rank without proving safety; it is also known to be insufficient in numeric contexts. A mitigation API is a hint, not a verdict.

### Held-out targets

| Target | Version | Positives in top 20 | Pairwise ordering | Localized sinks | Labeled precision@20 | Findings P/R |
|---|---|---:|---:|---:|---:|---|
| Vulnerable-Flask-App (Python) | v0.1.1 | 3/3 | 2/2 | 3/3 | 0.6 | 1.0 / 1.0 |
| Vulnerable-Flask-App (Python) | v0.1.2 | 3/3 | 2/2 | 3/3 | 0.6 | 1.0 / 1.0 |
| NodeGoat (JavaScript) | v0.1.1 | 1/3 | n/a | 2/3 | 1.0 | 1.0 / 0.333 |
| NodeGoat (JavaScript) | v0.1.2 | 2/3 | n/a | 2/3 | 1.0 | 1.0 / 0.333 |

Python results come from the AST engine that this release did not change; they show no regression. NodeGoat shows the lexical JavaScript gap:

- `res.redirect(req.query.url)` produces no finding (there is no JavaScript redirect rule) and ranks 17th.
- The `$where` injection is a collection `.find()` call that the JavaScript database catalog does not model. It is a known miss, and it is not in the queue.
- The only finding that matches the matrix is the `eval` on request data (JS001), at low confidence as a review hotspot, not labeled likely.

These are v0.2 candidates. They were not fixed in this release because the targets are held out.

## Limitations

- Case counts are small (16, 5 and 4), runs are single and deterministic, and no confidence intervals are computed. Treat the numbers as illustrative, not statistically meaningful.
- Intentionally vulnerable applications are not representative of production code. They contain flaws in obvious places, and their "fixed" variants are teaching examples.
- DVWA output informed this release's design (include-path handling, validation-function mitigations, request/state split). The changes are implemented generally and covered by synthetic multi-language tests, but DVWA is a development target, so its numbers are not evidence of generalization. The held-out comparison above is the better signal and is still a small sample.
- Navigation and queue placement are triage aids, not vulnerability recall. Negative cases apply only to the listed CWE.

## History

- [`baseline-v0.1.0/`](baseline-v0.1.0): the originally published DVWA report, preserved unchanged.
- [`results-v0.1.1/`](results-v0.1.1): the v0.1.1 DVWA reports.
- [`results/`](results): v0.1.2 reports, scores and provenance for every target.
