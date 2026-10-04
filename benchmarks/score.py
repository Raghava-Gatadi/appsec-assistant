"""Score a saved report against a pinned, manually reviewed target matrix.

This reads reports only. It never runs the target or changes scanner behavior. The
scorer is language-agnostic: every target is described by a JSON file in `targets/`.

A triage tool is judged on how well it orders a reviewer's work, so the headline
numbers are queue metrics. Finding precision/recall are reported only when the
scanner emitted findings for the listed CWEs; otherwise they are marked unavailable
instead of being shown as a vacuous zero.
"""
import argparse
import json
from pathlib import Path

TARGETS = Path(__file__).with_name('targets')
INF = float('inf')


def load_target(name_or_path):
    path = Path(name_or_path)
    if not path.suffix:
        path = TARGETS / f'{name_or_path}.json'
    return json.loads(path.read_text())


def _entry_rank(queue, case):
    """1-based position of the best queue entry for a case, or None."""
    for position, entry in enumerate(queue, 1):
        if entry['path'] == case['path'] and (not case.get('function') or entry.get('function') == case['function']):
            return position
    return None


def _matches(item, case):
    return item['path'] == case['path'] and (not case.get('function') or item.get('function') == case['function'])


def score(report, target, k=20, near=10):
    findings = report.get('findings', [])
    code_map = report.get('code_map', [])
    queue = report.get('review_queue')
    cases_out = []
    counts = {'positive_cases': 0, 'finding_matches': 0, 'likely_matches': 0, 'navigation_matches': 0,
              'navigation_localized': 0, 'negative_cases': 0, 'false_positives': 0}
    ranks = {}
    for index, case in enumerate(target['cases']):
        matched = [f for f in findings if _matches(f, case) and f['cwe'] == case['cwe']]
        category = [m for m in code_map if _matches(m, case) and m['category'] == case['navigation_category']]
        # Localized: a sink of the expected category within `near` lines of the expected line.
        localized = bool(case.get('line')) and any(abs(m['line'] - case['line']) <= near for m in category)
        likely = any(f['classification'] == 'likely-vulnerability' for f in matched)
        rank = _entry_rank(queue, case) if queue is not None else None
        ranks[index] = rank
        positive = case['expected_vulnerable']
        counts['positive_cases' if positive else 'negative_cases'] += 1
        if positive:
            counts['finding_matches'] += bool(matched)
            counts['likely_matches'] += likely
            counts['navigation_matches'] += bool(category)
            counts['navigation_localized'] += localized
        else:
            counts['false_positives'] += bool(matched)
        cases_out.append({'path': case['path'], 'function': case.get('function'), 'cwe': case['cwe'],
                          'expected_vulnerable': positive, 'finding_match': bool(matched), 'likely_match': likely,
                          'navigation_present': bool(category), 'navigation_localized': localized, 'queue_rank': rank})

    positives = [i for i, c in enumerate(target['cases']) if c['expected_vulnerable']]
    queue_metrics = {'k': k, 'available': queue is not None}
    if queue is not None:
        in_top = {i for i, r in ranks.items() if r is not None and r <= k}
        comparable = [c for c in target['cases'] if c.get('queue_comparable', True)]
        top = queue[:k]

        def label(entry):
            hits = [c for c in comparable if _matches(entry, c)]
            if any(c['expected_vulnerable'] for c in hits):
                return 'positive'
            return 'negative' if hits else 'unlabeled'
        labels = [label(e) for e in top]
        positive_entries, negative_entries = labels.count('positive'), labels.count('negative')
        pairs = ordered = ties = 0
        for pi in positives:
            for ni, neg in enumerate(target['cases']):
                if neg['expected_vulnerable'] or neg['cwe'] != target['cases'][pi]['cwe'] or not neg.get('queue_comparable', True):
                    continue
                pr = ranks[pi] if ranks[pi] is not None and ranks[pi] <= k else INF
                nr = ranks[ni] if ranks[ni] is not None and ranks[ni] <= k else INF
                pairs += 1
                ordered += pr < nr
                ties += pr == nr
        queue_metrics.update({
            'positives': len(positives),
            'positives_in_top_k': len(in_top & set(positives)),
            'recall_at_k': round(len(in_top & set(positives)) / len(positives), 3) if positives else None,
            'labeled_positive_entries_in_top_k': positive_entries,
            'labeled_negative_entries_in_top_k': negative_entries,
            'labeled_precision_at_k': round(positive_entries / (positive_entries + negative_entries), 3) if positive_entries + negative_entries else None,
            'unlabeled_entries_in_top_k': labels.count('unlabeled'),
            'pairwise_ordering': {'pairs': pairs, 'positive_first': ordered, 'ties': ties,
                                  'score': round((ordered + ties / 2) / pairs, 3) if pairs else None,
                                  'note': 'A positive ranked above a same-CWE negative; ranks outside the top k count as tied. Cases marked queue_comparable=false are skipped.'},
            'note': 'Entries are labeled per (path, function) when a case names a function, otherwise per file. Precision counts labeled entries only; unlabeled entries are unknown, not false.'})

    emitted = [f for f in findings if any(_matches(f, c) and f['cwe'] == c['cwe'] for c in target['cases'])]
    if emitted:
        tp, fp = counts['finding_matches'], counts['false_positives']
        finding_metrics = {'reported': True,
                           'recall': round(tp / counts['positive_cases'], 3) if counts['positive_cases'] else None,
                           'precision': round(tp / (tp + fp), 3) if tp + fp else None,
                           'false_positive_rate': round(fp / counts['negative_cases'], 3) if counts['negative_cases'] else None}
    else:
        finding_metrics = {'reported': False,
                           'reason': 'The scanner emitted no findings for the listed CWEs, so finding precision and recall are not reported. '
                                     'A clean negative case says nothing when nothing could be flagged.'}
    checks = []
    for case in target.get('credential_checks', []):
        matched = any(f['path'] == case['path'] and f['rule_id'] == 'SEC001' for f in findings)
        checks.append({'path': case['path'], 'expected': case['expected'], 'matched': matched, 'pass': matched == case['expected']})
    return {'target': target.get('name'), 'role': target.get('role', 'dev'), 'counts': counts, 'queue': queue_metrics,
            'findings': finding_metrics, 'cases': cases_out, 'credential_checks': checks,
            'interpretation': 'Navigation and queue placement are triage aids, not vulnerability recall. Negative cases apply only to the listed CWE, not all possible defects.'}


def table(rows):
    header = '| Report | Positives in top-k | Pairwise ordering | Localized sinks | Labeled precision@k | Findings P/R |\n|---|---:|---:|---:|---:|---|\n'
    lines = []
    for label, result in rows:
        q, c, f = result['queue'], result['counts'], result['findings']
        recall = f"{q['positives_in_top_k']}/{q['positives']}" if q.get('available') else 'n/a'
        pair = q.get('pairwise_ordering', {})
        order = f"{pair['positive_first']}/{pair['pairs']} (ties {pair['ties']})" if pair.get('pairs') else 'n/a'
        prec = q.get('labeled_precision_at_k')
        fm = f"P {f['precision']} / R {f['recall']}" if f['reported'] else 'no findings emitted'
        lines.append(f"| {label} | {recall} | {order} | {c['navigation_localized']}/{c['positive_cases']} | {prec if prec is not None else 'n/a'} | {fm} |")
    return header + '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path, nargs='+')
    parser.add_argument('--target', default='dvwa', help='Target name in benchmarks/targets or a path to a target JSON file')
    parser.add_argument('-k', type=int, default=20, help='Review-queue depth to score (default 20)')
    parser.add_argument('--table', action='store_true', help='Print a Markdown comparison table instead of JSON')
    args = parser.parse_args()
    target = load_target(args.target)
    results = [(p.parent.name or p.name, score(json.loads(p.read_text()), target, args.k)) for p in args.report]
    print(table(results) if args.table else json.dumps(results[0][1] if len(results) == 1 else dict(results), indent=2))


if __name__ == '__main__':
    main()
