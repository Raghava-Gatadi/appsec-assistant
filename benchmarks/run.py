"""Reproduce the static DVWA comparison without executing target code."""
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
from score import score  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', type=Path)
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / f'results-v{__version__}')
    args = parser.parse_args()
    target = args.target.resolve()
    expected = json.loads(Path(__file__).with_name('dvwa-expected.json').read_text())
    commit = subprocess.check_output(['git', '-C', str(target), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(target), 'status', '--porcelain'], text=True)
    if commit != expected['commit'] or dirty:
        parser.error('Benchmark requires the pinned, clean DVWA checkout listed in dvwa-expected.json')
    for case in expected['cases']:
        if hashlib.sha256((target / case['path']).read_bytes()).hexdigest() != case['sha256']:
            parser.error('A benchmark source file does not match its recorded hash')
    result = scan(target, Options())
    if not result.complete:
        parser.error('Scan incomplete; inspect the target and scanner limits before benchmarking')
    args.output.mkdir(parents=True, exist_ok=True)
    for format, name in [('html', 'report.html'), ('json', 'report.json'), ('sarif', 'report.sarif')]:
        content = render(result, format).replace(str(target), 'DVWA')
        if format == 'sarif':
            obj = json.loads(content)
            for run in obj['runs']:
                run.pop('originalUriBaseIds', None)
                for finding in run['results']:
                    for location in finding['locations']:
                        location['physicalLocation']['artifactLocation'].pop('uriBaseId', None)
            content = json.dumps(obj, indent=2) + '\n'
        (args.output / name).write_text(content)
    report = json.loads((args.output / 'report.json').read_text())
    (args.output / 'score.json').write_text(json.dumps(score(report, expected), indent=2) + '\n')
    provenance = {'scanner_version': __version__, 'dvwa_commit': commit, 'clean_checkout': True,
                  'scan_policy': result.policy, 'python_version': sys.version.split()[0],
                  'scanner_files_sha256': {p.relative_to(Path(__file__).resolve().parents[1]).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).resolve().parents[1].glob('appsec_assistant/*.py'))},
                  'files_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.output.iterdir() if p.name != 'provenance.json'}}
    (args.output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(json.dumps({'summary': report['summary'], 'files_scanned': result.files_scanned,
                      'test_files_excluded': result.test_files_excluded,
                      'html_bytes': (args.output / 'report.html').stat().st_size,
                      'score': score(report, expected)['counts']}, indent=2))


if __name__ == '__main__':
    main()
