"""Reproduce a static benchmark for any target described in benchmarks/targets/.

    python3 benchmarks/run.py dvwa /path/to/DVWA
    python3 benchmarks/run.py --list

The target is only read, never started or imported. The runner checks the pinned commit,
a clean checkout and recorded source hashes before scanning, and writes portable reports.
Targets are marked `dev` (rules may be tuned against them) or `held-out` (measure only).
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from appsec_assistant import __version__  # noqa: E402
from appsec_assistant.reports import render  # noqa: E402
from appsec_assistant.scanner import Options, scan  # noqa: E402
from score import TARGETS, load_target, score  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target', nargs='?', help='Target name from benchmarks/targets')
    parser.add_argument('checkout', nargs='?', type=Path, help='Path to a clean checkout at the pinned commit')
    parser.add_argument('--output', type=Path, help='Output directory (default benchmarks/results/<target>-v<version>)')
    parser.add_argument('-k', type=int, default=20)
    parser.add_argument('--list', action='store_true', help='List available targets and exit')
    args = parser.parse_args()
    if args.list:
        for path in sorted(TARGETS.glob('*.json')):
            t = json.loads(path.read_text())
            print(f"{t['name']:24} {t['role']:9} {','.join(t['languages']):24} {t['repository']}")
        return
    if not args.target or not args.checkout:
        parser.error('target and checkout are required (or use --list)')
    expected = load_target(args.target)
    root = args.checkout.resolve()
    commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True)
    if commit != expected['commit'] or dirty:
        parser.error(f"Benchmark requires the pinned, clean checkout {expected['commit']} listed in targets/{expected['name']}.json")
    for case in expected['cases']:
        if hashlib.sha256((root / case['path']).read_bytes()).hexdigest() != case['sha256']:
            parser.error('A benchmark source file does not match its recorded hash')
    result = scan(root, Options())
    if not result.complete:
        parser.error('Scan incomplete; inspect the target and scanner limits before benchmarking')
    output = args.output or Path(__file__).parent / 'results' / f"{expected['name']}-v{__version__}"
    output.mkdir(parents=True, exist_ok=True)
    label = expected['display_name']
    for format, name in [('html', 'report.html'), ('json', 'report.json'), ('sarif', 'report.sarif')]:
        content = render(result, format).replace(str(root), label)
        if format == 'sarif':
            obj = json.loads(content)
            for run in obj['runs']:
                run.pop('originalUriBaseIds', None)
                for finding in run['results']:
                    for location in finding['locations']:
                        location['physicalLocation']['artifactLocation'].pop('uriBaseId', None)
            content = json.dumps(obj, indent=2) + '\n'
        (output / name).write_text(content)
    report = json.loads((output / 'report.json').read_text())
    scored = score(report, expected, args.k)
    (output / 'score.json').write_text(json.dumps(scored, indent=2) + '\n')
    repo = Path(__file__).resolve().parents[1]
    provenance = {'scanner_version': __version__, 'target': expected['name'], 'target_role': expected['role'],
                  'target_commit': commit, 'clean_checkout': True, 'scan_policy': result.policy,
                  'python_version': sys.version.split()[0],
                  'scanner_files_sha256': {p.relative_to(repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(repo.glob('appsec_assistant/*.py'))},
                  'files_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.name != 'provenance.json'}}
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(json.dumps({'target': expected['name'], 'role': expected['role'], 'summary': report['summary'],
                      'files_scanned': result.files_scanned, 'queue': scored['queue'], 'findings': scored['findings'],
                      'counts': scored['counts']}, indent=2))


if __name__ == '__main__':
    main()
