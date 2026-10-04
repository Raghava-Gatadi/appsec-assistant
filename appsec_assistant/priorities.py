"""One deterministic triage order for findings, scopes and SARIF rank."""

SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCES = {"low": 1, "medium": 2, "high": 3}
LABELS = {"note": 0, "review-hotspot": 1, "likely-vulnerability": 2}
CATEGORY_WEIGHTS = {
    "command execution": 9, "dynamic execution": 9, "deserialization": 8,
    "database query": 7, "template/HTML output": 6, "authentication/crypto": 6,
    "credentials": 6, "filesystem access": 5, "outbound request": 4,
    "redirect": 3, "configuration": 2, "entry point": 1,
    "input": 0, "state": 0, "function": 0, "mitigation": 0,
}
# Categories that describe how data arrives, not an operation to review.
# Lines within which request input and an operation count as close together.
NEAR_LINES = 10
SOURCE_CATEGORIES = {"input", "entry point"}
NON_OPERATION_CATEGORIES = SOURCE_CATEGORIES | {"state", "function", "mitigation"}
RULE_CATEGORIES = {
    "PY001": "database query", "JS005": "database query",
    "PY002": "command execution", "JS002": "command execution",
    "PY003": "dynamic execution", "JS001": "dynamic execution",
    "PY004": "deserialization", "PY005": "deserialization",
    "PY007": "authentication/crypto", "PY008": "authentication/crypto",
    "PY016": "authentication/crypto", "PY009": "filesystem access",
    "PY014": "filesystem access", "PY015": "filesystem access",
    "PY011": "template/HTML output", "PY012": "template/HTML output",
    "JS003": "template/HTML output", "JS006": "template/HTML output",
    "PY013": "outbound request", "PY017": "redirect",
}


def category_for(rule_id):
    return "credentials" if rule_id.startswith("SEC") else RULE_CATEGORIES.get(rule_id, "configuration")


def evidence_strength(finding):
    if any(t.kind == "external" for t in finding.trace):
        return 3
    if finding.trace or finding.engine in {"python-ast", "config-pattern", "secret-pattern"}:
        return 2
    return 1


def score(label, severity, confidence, evidence, category):
    """Mixed-radix encoding preserves the specified lexicographic precedence.

    Label > severity*confidence > evidence > category. Path/line resolve ties.
    1559 is the maximum encoded value, so SARIF rank is in [0, 100].
    This is a triage order, not a probability or CVSS score.
    """
    impact = SEVERITIES[severity] * CONFIDENCES[confidence]
    encoded = ((LABELS[label] * 13 + impact) * 4 + evidence) * 10 + CATEGORY_WEIGHTS[category]
    return round(encoded * 100 / 1559, 6)


def finding_rank(finding):
    return score(finding.classification, finding.severity, finding.confidence,
                 evidence_strength(finding), category_for(finding.rule_id))


def finding_key(finding):
    return (-finding_rank(finding), finding.path, finding.line, finding.column, finding.rule_id)


def scope_evidence(has_input, has_operation, mitigated, distance, near=10):
    """Evidence level for a navigation scope (0-3).

    0 no request input and operation together; 1 together but a mitigation API is
    present in the same scope; 2 together with no mitigation seen; 3 as 2 and the
    input is within `near` lines of an operation. A mitigation lowers rank but never
    removes the scope: it is not proof of safety.
    """
    if not (has_input and has_operation):
        return 0
    if mitigated:
        return 1
    return 3 if distance is not None and distance <= near else 2


def navigation_rank(category, evidence=0):
    weight = CATEGORY_WEIGHTS.get(category, 0)
    severity = "high" if weight >= 4 else "medium" if weight else "low"
    return score("review-hotspot", severity, "low", int(evidence), category)


def meets_gate(finding, threshold="high"):
    return (threshold != "none" and finding.status == "new"
            and SEVERITIES[finding.severity] >= SEVERITIES[threshold]
            and (finding.classification == "likely-vulnerability"
                 or CONFIDENCES[finding.confidence] >= CONFIDENCES["medium"]))
