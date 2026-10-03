from __future__ import annotations

import fnmatch
import io
import json
import os
import re
import stat
import time
import tokenize
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import Collector, ScanResult
from .priorities import CONFIDENCES, SEVERITIES, finding_key
from . import navigation, python_analyzer, text_analyzer

DEFAULT_EXCLUDES = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", ".next", "dist", "build", "coverage", ".tox"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
TEXT_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".txt", ".sh", ".bash", ".zsh", ".java", ".cs", ".go", ".rb", ".php", ".rs", ".c", ".h", ".cpp", ".html", ".vue", ".svelte", ".pem", ".key", ".properties", ".xml"}
TEST_DIRS = {"tests", "test", "__tests__", "spec"}
TEMPLATE_SUFFIXES = {".dist", ".example", ".sample", ".template"}
FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Options:
    include_tests: bool = False
    excludes: list[str] = field(default_factory=list)
    max_file_bytes: int = 2_000_000
    max_total_bytes: int = 100_000_000
    max_files: int = 10_000
    max_nodes: int = 100_000
    min_severity: str = "low"
    min_confidence: str = "low"
    baseline: set[str] = field(default_factory=set)
    suppressions: list[dict] = field(default_factory=list)
    omitted_paths: set[Path] = field(default_factory=set)


def matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern) or (pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]))


def underlying_path(path: str) -> Path:
    p = Path(path)
    while p.suffix.lower() in TEMPLATE_SUFFIXES:
        p = p.with_suffix("")
    return p


def is_test_file(path: str) -> bool:
    p = underlying_path(path)
    return (bool(set(p.parts[:-1]) & TEST_DIRS)
            or p.name == "conftest.py"
            or any(fnmatch.fnmatchcase(p.name, pattern) for pattern in
                   ("test_*.py", "*_test.py", "*_test.go", "*.test.js", "*.test.ts",
                    "*.spec.js", "*.spec.ts", "*.test.jsx", "*.test.tsx", "*.spec.jsx", "*.spec.tsx")))


def language(path: str) -> str | None:
    p = underlying_path(path)
    if p.name.lower() == "composer.lock":
        return "configuration/secrets"
    if p.suffix.lower() in {".py", ".pyw"}:
        return "python"
    if p.suffix.lower() in JS_EXTENSIONS:
        return "javascript/typescript"
    if p.suffix.lower() in navigation.LANGUAGES:
        return navigation.LANGUAGES[p.suffix.lower()]
    if p.name.lower().startswith((".env", "dockerfile")) or p.suffix.lower() in TEXT_EXTENSIONS:
        return "configuration/secrets"
    return None


def _version(value):
    # Avoid echoing authenticated URLs or arbitrary manifest strings.
    return value if isinstance(value, str) and re.fullmatch(r"[v^~<>=!*|\s]*\d[0-9A-Za-z.^~<>=!*|,+ _-]{0,120}", value) else "[specifier withheld]"


def dependency_inventory(source: str, path: str) -> list[dict]:
    name = underlying_path(path).name
    found = []
    def add(ecosystem, package, spec, group="runtime"):
        if isinstance(package, str) and re.fullmatch(r"[@A-Za-z0-9][A-Za-z0-9_./-]{0,180}", package):
            found.append({"ecosystem": ecosystem, "name": package, "specifier": _version(spec), "group": group, "path": path, "advisory_status": "not checked"})
    if name == "package.json":
        obj = json.loads(source)
        if not isinstance(obj, dict):
            raise ValueError("Manifest must be an object")
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            items = obj.get(key, {})
            if not isinstance(items, dict):
                raise ValueError("Dependency group must be an object")
            for package, spec in items.items():
                add("npm", package, spec, key)
    elif name == "composer.json":
        obj = json.loads(source)
        if not isinstance(obj, dict):
            raise ValueError("Manifest must be an object")
        for group in ("require", "require-dev"):
            items = obj.get(group, {})
            if not isinstance(items, dict):
                raise ValueError("Dependency group must be an object")
            for package, spec in items.items():
                add("Composer", package, spec, group)
    elif name == "composer.lock":
        obj = json.loads(source)
        if not isinstance(obj, dict):
            raise ValueError("Lockfile must be an object")
        for group in ("packages", "packages-dev"):
            items = obj.get(group, [])
            if not isinstance(items, list):
                raise ValueError("Lockfile packages must be an array")
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("version"), str):
                    raise ValueError("Invalid locked package")
                add("Composer", item["name"], item["version"], group)
    elif name == "pyproject.toml":
        obj = tomllib.loads(source)
        project = obj.get("project", {})
        if not isinstance(project, dict):
            raise ValueError("Project table must be an object")
        groups = {"runtime": project.get("dependencies", [])}
        optional = project.get("optional-dependencies", {})
        if not isinstance(optional, dict):
            raise ValueError("Optional dependencies must be a table")
        groups.update(optional)
        for group, entries in groups.items():
            if not isinstance(entries, list):
                raise ValueError("Dependencies must be an array")
            for entry in entries:
                if isinstance(entry, str):
                    m = re.match(r"([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*(.*?)(?:;.*)?$", entry)
                    if m:
                        add("PyPI", m[1], m[2] or "*", group)
    elif re.fullmatch(r"requirements(?:[._-][\w.-]+)?\.txt", name):
        for line in source.splitlines():
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*(.*?)(?:\s*#.*)?$", line)
            if m:
                add("PyPI", m[1], m[2].split(";")[0] or "*")
    return found


def analyze_text(source: str, path: str, result: ScanResult, options: Options):
    out = Collector(path, source)
    lang = language(path)
    if lang is None:
        result.files_skipped += 1
        result.diagnostic(path, "Unsupported extension; file was not analyzed")
        return
    result.files_scanned += 1
    result.coverage[lang] = result.coverage.get(lang, 0) + 1
    items = []
    mode = "AST + local data flow" if lang == "python" else "lexical rules + navigation" if lang == "javascript/typescript" else "navigation + secrets" if lang in navigation.PATTERNS else "configuration/secrets"
    result.file_inventory.append({"path": path, "language": lang, "analysis": mode})
    try:
        text_analyzer.secrets(source, out, python=lang == "python")
        if lang == "python":
            tree = python_analyzer.analyze(source, out, options.max_nodes)
            items = navigation.python_map(tree, path)
        elif lang == "javascript/typescript":
            text_analyzer.javascript(source, out)
            items = navigation.lexical_map(source, path, lang)
        elif lang in navigation.PATTERNS:
            items = navigation.lexical_map(source, path, lang)
        else:
            text_analyzer.config(source, path, out)
        try:
            result.inventory.extend(dependency_inventory(source, path))
        except (ValueError, TypeError, KeyError, tomllib.TOMLDecodeError):
            result.diagnostic(path, "Dependency manifest could not be parsed; inventory is incomplete", True)
    except SyntaxError as exc:
        result.diagnostic(path, f"Python syntax could not be parsed near line {exc.lineno or 1}; AST checks were incomplete", True)
    except (RecursionError, ValueError, MemoryError):
        result.diagnostic(path, "Analysis exceeded a parser/resource limit; checks were incomplete", True)
    functions = sorted([m for m in items if m["category"] == "function"], key=lambda m: m["line"], reverse=True)
    for finding in out.findings:
        # ast column offsets are UTF-8 byte offsets, while report columns are
        # Unicode code points (including in SARIF).
        if finding.engine == "python-ast":
            line_text = out.lines[finding.line - 1]
            finding.column = len(line_text.encode("utf-8")[:finding.column - 1].decode("utf-8", errors="ignore")) + 1
        scope = next((m for m in functions if m["line"] <= finding.line <= m["end_line"]), None)
        finding.function = scope["name"] if scope and lang != "php" else f"<file: {path}>"
        finding.scope_start = scope["line"] if scope and lang != "php" else 0
    result.code_map.extend(items)
    result.findings.extend(out.findings)


def finish(result: ScanResult, options: Options):
    retained = []
    for finding in result.findings:
        if (SEVERITIES[finding.severity] < SEVERITIES[options.min_severity]
                or CONFIDENCES[finding.confidence] < CONFIDENCES[options.min_confidence]):
            result.filtered_findings += 1
            continue
        if finding.fingerprint in options.baseline:
            finding.status = "existing"
        for suppression in options.suppressions:
            if ((not suppression.get("fingerprint") or suppression["fingerprint"] == finding.fingerprint)
                    and (not suppression.get("rule_id") or suppression["rule_id"] == finding.rule_id)
                    and matches(finding.path, suppression.get("path", "**"))):
                finding.status = "suppressed"
                finding.suppression_reason = suppression["reason"]
                break
        retained.append(finding)
    result.findings = sorted(retained, key=finding_key)
    if result.test_files_excluded:
        result.diagnostic(".", f"{result.test_files_excluded} test files excluded; use --include-tests to analyze them")
    result.policy = {
        "include_tests": options.include_tests, "test_directories": sorted(TEST_DIRS),
        "ci_gate": "new; severity at fail-on threshold; likely-vulnerability or confidence >= medium",
        "min_severity": options.min_severity, "min_confidence": options.min_confidence,
        "excludes": sorted(DEFAULT_EXCLUDES) + options.excludes,
        "baseline_fingerprints": len(options.baseline), "suppression_rules": len(options.suppressions),
        "max_file_bytes": options.max_file_bytes, "max_total_bytes": options.max_total_bytes,
        "max_files": options.max_files, "max_python_nodes": options.max_nodes,
    }
    return result


def scan_stdin(source: str, name: str, options: Options):
    started = time.monotonic()
    result = ScanResult("standard input")
    if not options.include_tests and is_test_file(name):
        result.test_files_excluded += 1
        result.files_skipped += 1
    elif len(source.encode("utf-8")) > min(options.max_file_bytes, options.max_total_bytes):
        result.diagnostic(name, "Input exceeds the byte limit", True)
    else:
        analyze_text(source, name, result, options)
    if not result.files_scanned and not result.test_files_excluded:
        result.diagnostic(name, "No supported files were analyzed", True)
    result.elapsed_seconds = round(time.monotonic() - started, 3)
    return finish(result, options)


def scan(target: Path, options: Options):
    started = time.monotonic()
    target = target.absolute()
    result = ScanResult(str(target))
    try:
        mode = target.lstat().st_mode
    except OSError:
        result.diagnostic(str(target), "Target is missing or cannot be accessed", True)
        return finish(result, options)
    if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        result.diagnostic(str(target), "Target must be a regular file or directory, not a symlink or special file", True)
        return finish(result, options)
    root = target if stat.S_ISDIR(mode) else target.parent
    total_bytes = 0
    examined = 0
    stopped = False

    def consider(path):
        nonlocal total_bytes, examined, stopped
        rel = path.relative_to(root).as_posix()
        examined += 1
        if examined > options.max_files:
            result.diagnostic(".", "File traversal limit reached; remaining entries were not scanned", True)
            stopped = True
            return
        if not options.include_tests and (is_test_file(rel) or root.name in TEST_DIRS):
            result.files_skipped += 1
            result.test_files_excluded += 1
            return
        if path.absolute() in options.omitted_paths:
            result.files_skipped += 1
            return
        if any(matches(rel, p) for p in options.excludes):
            result.files_skipped += 1
            result.diagnostic(rel, "Excluded by scan policy")
            return
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                result.files_skipped += 1
                result.diagnostic(rel, "Symlink or special file was not followed")
                return
            if language(rel) is None:
                result.files_skipped += 1
                result.diagnostic(rel, "Unsupported extension; file was not analyzed")
                return
            if info.st_size > options.max_file_bytes:
                result.files_skipped += 1
                result.diagnostic(rel, "File exceeds the per-file byte limit", True)
                return
            if total_bytes + info.st_size > options.max_total_bytes:
                result.diagnostic(rel, "Total byte limit reached; remaining files were not scanned", True)
                stopped = True
                return
            # O_NOFOLLOW prevents a leaf symlink swap; fstat also rejects devices.
            # Scanning a directory being actively changed remains unsupported.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise OSError("not a regular file")
                raw = handle.read(options.max_file_bytes + 1)
            if len(raw) > options.max_file_bytes or total_bytes + len(raw) > options.max_total_bytes:
                result.files_skipped += 1
                result.diagnostic(rel, "File grew beyond the byte limit during the scan", True)
                return
            total_bytes += len(raw)
            if b"\x00" in raw:
                result.files_skipped += 1
                result.diagnostic(rel, "Binary content in a supported file; analysis skipped", True)
                return
            if language(rel) == "python":
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                source = raw.decode(encoding)
            else:
                source = raw.decode("utf-8-sig")
            analyze_text(source, rel, result, options)
        except (OSError, UnicodeError, SyntaxError, LookupError):
            result.files_skipped += 1
            result.diagnostic(rel, "File could not be read or decoded; analysis skipped", True)

    if stat.S_ISREG(mode):
        consider(target)
    else:
        def walk_error(error):
            result.diagnostic(".", "A directory could not be enumerated", True)
        for directory, dirs, files in os.walk(target, followlinks=False, onerror=walk_error):
            current = Path(directory)
            depth = len(current.relative_to(root).parts)
            kept = []
            for name in sorted(dirs):
                examined += 1
                if examined > options.max_files:
                    result.diagnostic(".", "Directory traversal limit reached; remaining entries were not scanned", True)
                    stopped = True
                    break
                path = current / name
                rel = path.relative_to(root).as_posix()
                if depth >= 64:
                    result.diagnostic(rel, "Directory depth limit reached", True)
                elif path.is_symlink() or name in DEFAULT_EXCLUDES or any(matches(rel, p) or matches(rel + "/", p) for p in options.excludes):
                    result.diagnostic(rel, "Directory excluded or symlink not followed")
                else:
                    kept.append(name)
            dirs[:] = kept
            if stopped:
                break
            for name in sorted(files):
                consider(current / name)
                if stopped:
                    break
            if stopped:
                break
    if not result.files_scanned and not result.test_files_excluded:
        result.diagnostic(".", "No supported files were analyzed", True)
    result.elapsed_seconds = round(time.monotonic() - started, 3)
    return finish(result, options)
