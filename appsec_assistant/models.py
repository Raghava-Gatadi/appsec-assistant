from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any

SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCES = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: int
    remediation: str
    review: str

    @property
    def reference(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.cwe}.html"


@dataclass(frozen=True)
class Trace:
    line: int
    label: str
    kind: str = "flow"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    path: str
    line: int
    column: int
    message: str
    remediation: str
    review: str
    reference: str
    fingerprint: str
    engine: str
    trace: list[Trace] = field(default_factory=list)
    status: str = "new"
    suppression_reason: str | None = None
    classification: str = "review-hotspot"
    function: str = "<module or unresolved>"


class Collector:
    def __init__(self, path: str, source: str):
        self.path = path
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int, int]] = set()
        self._occurrences: dict[tuple[str, str], int] = {}

    def add(self, rule: Rule, line: int, column: int, message: str,
            confidence: str = "medium", trace: tuple[Trace, ...] = (),
            engine: str = "python-ast", severity: str | None = None) -> None:
        key = (rule.id, line, column)
        if key in self._seen:
            return
        self._seen.add(key)
        # No code or literal values leave the analyzer. Hashes remain stable when
        # unrelated lines are inserted; repeated identical lines get distinct IDs.
        normalized = " ".join(self.lines[line - 1].split()) if 0 < line <= len(self.lines) else ""
        identity = (rule.id, normalized)
        ordinal = self._occurrences.get(identity, 0)
        self._occurrences[identity] = ordinal + 1
        fingerprint = sha256(f"{self.path}\0{rule.id}\0{normalized}\0{ordinal}".encode()).hexdigest()
        self.findings.append(Finding(
            rule.id, rule.title, severity or rule.severity, confidence,
            f"CWE-{rule.cwe}", self.path, max(1, line), max(1, column),
            message, rule.remediation, rule.review, rule.reference,
            fingerprint, engine, list(trace),
        ))
        if confidence == "high" and rule.id in {
            "PY001", "PY002", "PY003", "PY004", "PY005", "PY006", "PY010", "PY011", "PY016"
        }:
            self.findings[-1].classification = "likely-vulnerability"


REVIEW_CHECKLIST = [
    "Authorization: verify object ownership, tenant isolation and role checks on every sensitive operation.",
    "Authentication: review account recovery, MFA, session rotation, token expiry and revocation.",
    "Business logic: review payment amounts, state transitions, concurrency and abuse limits.",
    "Web controls: review CSRF, CORS, cookie settings, security headers and output encoding by context.",
    "Files and network: verify upload limits, destination allowlists, path containment and egress policy.",
    "Dependencies: use a maintained advisory scanner against resolved lockfiles; inventory here is not a CVE audit.",
    "Deployment: review production configuration, IAM permissions, secret rotation and audit logging.",
]

LIMITATIONS = [
    "Findings are review candidates, not proof of exploitability. No findings does not mean the application is secure.",
    "Python analysis is bounded and intraprocedural. It does not resolve calls across functions or files, or prove sanitizers correct.",
    "JavaScript/TypeScript and configuration checks use lexical heuristics, not a full parser or data-flow engine.",
    "PHP, Java, C#, Go and Ruby receive navigation hotspots only. Callable identity, reachability and function scope may be unresolved.",
    "Unsupported languages receive limited secret checks only. Generated and dependency directories are excluded by default.",
    "No live CVE lookup, dependency resolution, runtime testing, authorization verification or automatic exploitation is performed.",
]


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    inventory: list[dict[str, Any]] = field(default_factory=list)
    code_map: list[dict[str, Any]] = field(default_factory=list)
    file_inventory: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, int] = field(default_factory=dict)
    files_scanned: int = 0
    files_skipped: int = 0
    complete: bool = True
    elapsed_seconds: float = 0
    filtered_findings: int = 0
    policy: dict[str, Any] = field(default_factory=dict)

    def diagnostic(self, path: str, reason: str, incomplete: bool = False) -> None:
        self.diagnostics.append({"path": path, "reason": reason, "incomplete": incomplete})
        if incomplete:
            self.complete = False

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "new"]

    @property
    def review_queue(self) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for item in self.code_map:
            if item["category"] == "function":
                continue
            key = (item["path"], item["function"])
            group = groups.setdefault(key, {"path": key[0], "function": key[1], "line": item["line"], "categories": set(), "findings": [], "priority": 0})
            group["categories"].add(item["category"])
            group["line"] = min(group["line"], item["line"])
        for f in self.active:
            key = (f.path, f.function)
            group = groups.setdefault(key, {"path": key[0], "function": key[1], "line": f.line, "categories": set(), "findings": [], "priority": 0})
            group["findings"].append(f.rule_id)
            group["priority"] = max(group["priority"], SEVERITIES[f.severity] * 10 + CONFIDENCES[f.confidence])
        for group in groups.values():
            categories = group["categories"]
            has_input = bool(categories & {"input", "entry point"})
            has_operation = bool(categories - {"input", "entry point"})
            if group["findings"]:
                group["reason"] = "Review rule findings: " + ", ".join(sorted(set(group["findings"])))
            elif has_input and has_operation:
                group["reason"] = "Input/entry point and sensitive operations share this scope; a data-flow connection is not established."
            elif has_operation:
                group["reason"] = "Security-sensitive operations require a trust-boundary review."
            else:
                group["reason"] = "Review input validation, authentication and authorization at this boundary."
            group["priority"] += (5 if has_input else 0) + (2 if has_operation else 0)
            group["categories"] = sorted(categories)
        return sorted(groups.values(), key=lambda g: (-g["priority"], g["path"], g["line"]))[:20]

    def to_dict(self) -> dict[str, Any]:
        from . import __version__
        data = asdict(self)
        data.update({
            "schema_version": 1,
            "tool": {"name": "AppSec Assistant", "version": __version__},
            "summary": {
                "new": len(self.active),
                "existing": sum(f.status == "existing" for f in self.findings),
                "suppressed": sum(f.status == "suppressed" for f in self.findings),
                "by_severity": {s: sum(f.severity == s for f in self.active) for s in reversed(SEVERITIES)},
                "likely_vulnerabilities": sum(f.classification == "likely-vulnerability" for f in self.active),
                "review_findings": sum(f.classification == "review-hotspot" for f in self.active),
                "navigation_hotspots": sum(m["kind"] == "review-hotspot" for m in self.code_map),
                "functions": sum(m["category"] == "function" for m in self.code_map),
                "entry_points": sum(m["category"] == "entry point" for m in self.code_map),
            },
            "limitations": LIMITATIONS,
            "manual_review": REVIEW_CHECKLIST,
            "review_queue": self.review_queue,
        })
        return data
