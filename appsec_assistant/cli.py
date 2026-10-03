from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import date
from pathlib import Path

from . import __version__
from .models import CONFIDENCES, SEVERITIES
from .reports import plain, render
from .rules import RULES
from .scanner import FINGERPRINT, Options, scan, scan_stdin


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def read_json(path):
    with Path(path).open("rb") as handle:
        data = handle.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError("Policy/baseline file exceeds 2 MB")
    return json.loads(data)


def load_baseline(path):
    data = read_json(path)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Baseline must have schema_version 1")
    items = data.get("fingerprints")
    if not isinstance(items, list) or any(not isinstance(v, str) or not FINGERPRINT.fullmatch(v) for v in items):
        raise ValueError("Baseline fingerprints must be an array of 64-character lowercase SHA-256 hashes")
    return set(items)


def load_config(path):
    data = read_json(path)
    if not isinstance(data, dict) or set(data) - {"excludes", "suppressions"}:
        raise ValueError("Config supports only excludes and suppressions")
    excludes = data.get("excludes", [])
    if not isinstance(excludes, list) or any(not isinstance(s, str) or not s for s in excludes):
        raise ValueError("Config excludes must be an array of non-empty glob strings")
    suppressions = data.get("suppressions", [])
    if not isinstance(suppressions, list):
        raise ValueError("Config suppressions must be an array")
    for s in suppressions:
        if not isinstance(s, dict) or set(s) - {"fingerprint", "rule_id", "path", "reason", "expires"}:
            raise ValueError("Invalid suppression fields")
        if any(not isinstance(v, str) or not v.strip() for v in s.values()):
            raise ValueError("Suppression values must be non-empty strings")
        if not s.get("reason"):
            raise ValueError("Every suppression needs a reason")
        if not s.get("fingerprint") and not (s.get("rule_id") and s.get("path")):
            raise ValueError("A suppression needs a fingerprint or both rule_id and path")
        if s.get("rule_id") and s["rule_id"] not in RULES:
            raise ValueError("Suppression references an unknown rule_id")
        if s.get("fingerprint") and not FINGERPRINT.fullmatch(s["fingerprint"]):
            raise ValueError("Suppression fingerprint must be a SHA-256 hash")
        if s.get("expires") and date.fromisoformat(s["expires"]) < date.today():
            raise ValueError("A suppression has expired; review and update it explicitly")
    return excludes, suppressions


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing to write through an output symlink")
    fd, temporary = tempfile.mkstemp(prefix=".appsec-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parser():
    p = argparse.ArgumentParser(
        prog="appsec-assistant",
        description="Scan a local source folder and map security review starting points. Never executes target code or uses the network.",
        epilog="Exit codes: 0 = no new finding at fail threshold; 1 = threshold reached; 2 = incomplete scan or error. Navigation hotspots alone do not fail CI.",
    )
    p.add_argument("target", nargs="?", help="Source folder or file; use - to read source from standard input")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--list-rules", action="store_true", help="List finding rules and exit")
    p.add_argument("--format", "-f", choices=["text", "json", "html", "sarif"], help="Report format; inferred from output suffix, otherwise text")
    p.add_argument("--output", "-o", type=Path, help="Write report to this file (otherwise stdout)")
    p.add_argument("--stdin-name", default="input.py", help="Virtual filename for stdin language detection (default: input.py)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Exclude a root-relative path glob; repeatable")
    p.add_argument("--config", type=Path, help="Explicit JSON policy with exclusions and reasoned suppressions")
    p.add_argument("--baseline", type=Path, help="Mark matching fingerprints as existing; existing findings do not fail CI")
    p.add_argument("--write-baseline", type=Path, help="Save reported finding fingerprints for a future scan; requires a complete scan")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low")
    p.add_argument("--min-confidence", choices=CONFIDENCES, default="low")
    p.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="high", help="Fail on new findings at this severity or higher (default: high)")
    p.add_argument("--max-file-bytes", type=positive, default=2_000_000)
    p.add_argument("--max-total-bytes", type=positive, default=100_000_000)
    p.add_argument("--max-files", type=positive, default=10_000, help="Maximum filesystem entries considered (default: 10000)")
    p.add_argument("--max-python-nodes", type=positive, default=100_000)
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.list_rules:
        for rule in RULES.values():
            print(f"{rule.id:7} {rule.severity:7} CWE-{rule.cwe:<5} {rule.title}")
        return 0
    if not args.target:
        p.error("a source folder/file is required (or use --list-rules)")
    try:
        excludes, suppressions = load_config(args.config) if args.config else ([], [])
        baseline = load_baseline(args.baseline) if args.baseline else set()
        outputs = [v.absolute() for v in [args.output, args.write_baseline] if v]
        if len(outputs) != len(set(outputs)):
            raise ValueError("Report and baseline output paths must be different")
        protected = {v.resolve() for v in [args.config, args.baseline] if v}
        if args.target != "-" and Path(args.target).is_file():
            protected.add(Path(args.target).resolve())
        if any(v.resolve() in protected for v in outputs):
            raise ValueError("Output would overwrite an input, config or baseline file")
        # Report outputs cannot overwrite executable source files by accident.
        for out in outputs:
            if out.suffix.lower() not in {".txt", ".json", ".html", ".htm", ".sarif"}:
                raise ValueError("Output filenames must end in .txt, .json, .html, .htm or .sarif")
        options = Options(
            excludes=excludes + args.exclude, suppressions=suppressions, baseline=baseline,
            max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes,
            max_files=args.max_files, max_nodes=args.max_python_nodes,
            min_severity=args.min_severity, min_confidence=args.min_confidence,
            omitted_paths=set(outputs) | {v.absolute() for v in [args.config, args.baseline] if v},
        )
        if args.target == "-":
            if Path(args.stdin_name).is_absolute() or ".." in Path(args.stdin_name).parts:
                raise ValueError("stdin-name must be a relative filename without parent traversal")
            limit = min(options.max_file_bytes, options.max_total_bytes)
            raw = sys.stdin.buffer.read(limit + 1)
            result = scan_stdin(raw.decode("utf-8"), args.stdin_name, options)
        else:
            result = scan(Path(args.target), options)
        format = args.format or ({".json": "json", ".sarif": "sarif", ".html": "html", ".htm": "html"}.get(args.output.suffix.lower(), "text") if args.output else "text")
        report = render(result, format)
        if args.output:
            atomic_write(args.output, report)
            print(plain(f"Report: {args.output.absolute()}\n{len(result.active)} new findings; {len(result.code_map)} navigation entries; {result.files_scanned} files analyzed."), file=sys.stderr)
        else:
            sys.stdout.write(report)
        if not result.complete:
            print("Scan incomplete. Review report diagnostics; no baseline was written.", file=sys.stderr)
            return 2
        if args.write_baseline:
            atomic_write(args.write_baseline, json.dumps({"schema_version": 1, "fingerprints": sorted({f.fingerprint for f in result.findings})}, indent=2) + "\n")
        if args.fail_on != "none" and any(SEVERITIES[f.severity] >= SEVERITIES[args.fail_on] for f in result.active):
            return 1
        return 0
    except BrokenPipeError:
        return 2
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        # Error messages from decoders can quote source content; do not echo them.
        if isinstance(exc, (json.JSONDecodeError, UnicodeError)):
            message = "Input or policy could not be decoded"
        elif isinstance(exc, OSError):
            message = "A required file could not be read or written"
        elif isinstance(exc, RecursionError):
            message = "Input structure exceeded a processing limit"
        else:
            message = str(exc)
        print("Error: " + plain(message), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
