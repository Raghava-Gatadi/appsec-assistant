"""Score a saved report against the pinned, limited DVWA review matrix.

This reads reports only. It never runs the target or changes scanner behavior.
"""
import argparse
import json
from pathlib import Path


def score(report, expected):
    findings = report.get('findings', [])
    code_map = report.get('code_map', [])
    counts = {'positive_cases': 0, 'finding_matches': 0, 'likely_matches': 0,
              'navigation_matches': 0, 'negative_cases': 0, 'false_positives': 0}
    cases = []
    for case in expected['cases']:
        matches = [f for f in findings if f['path'] == case['path'] and f['cwe'] == case['cwe']]
        navigation = any(m['path'] == case['path'] and m['category'] == case['navigation_category'] for m in code_map)
        likely = any(f['classification'] == 'likely-vulnerability' for f in matches)
        positive = case['expected_vulnerable']
        counts['positive_cases' if positive else 'negative_cases'] += 1
        if positive:
            counts['finding_matches'] += bool(matches)
            counts['likely_matches'] += likely
            counts['navigation_matches'] += navigation
        else:
            counts['false_positives'] += bool(matches)
        cases.append({'path': case['path'], 'cwe': case['cwe'], 'expected_vulnerable': positive,
                      'finding_match': bool(matches), 'likely_match': likely, 'navigation_present': navigation})
    checks = []
    for case in expected.get('credential_checks', []):
        matched = any(f['path'] == case['path'] and f['rule_id'] == 'SEC001' for f in findings)
        checks.append({'path': case['path'], 'expected': case['expected'], 'matched': matched,
                       'pass': matched == case['expected']})
    return {'counts': counts, 'cases': cases, 'credential_checks': checks,
            'interpretation': 'Navigation coverage is not vulnerability recall. Clean impossible cases apply only to the listed CWE, not all possible defects.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--expected', type=Path, default=Path(__file__).with_name('dvwa-expected.json'))
    args = parser.parse_args()
    print(json.dumps(score(json.loads(args.report.read_text()), json.loads(args.expected.read_text())), indent=2))


if __name__ == '__main__':
    main()
