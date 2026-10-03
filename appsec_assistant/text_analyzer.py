"""Lightweight lexical checks. These deliberately report lower confidence."""
from __future__ import annotations

import re
from pathlib import PurePath

from .models import Collector
from .python_analyzer import credential_literal
from .rules import RULES

# Preserve offsets and newlines so report locations still point into the source.
JS_TOKENS = re.compile(r'''//[^\n]*|/\*[\s\S]*?\*/|'(?:\\[\s\S]|[^'\\])*'|"(?:\\[\s\S]|[^"\\])*"|`(?:\\[\s\S]|[^`\\])*`''')
ASSIGNMENT = re.compile(r'''(?i)(?<![\w.-])["']?([a-z_][a-z0-9_.-]{0,120})["']?\s*[:=]\s*(["'])([^\r\n"']{8,500})\2''')
UNQUOTED = re.compile(r"(?im)^[ \t]*(?:export[ \t]+)?([A-Z_][A-Z0-9_]{0,120})[ \t]*=[ \t]*([^\s#\"']{8,500})[ \t]*(?:#.*)?$")
TOKEN_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{20,200}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,200}\b"),
]


def blank(text):
    return "".join("\n" if c == "\n" else " " for c in text)


def lexical_views(source):
    def comments(m):
        return blank(m[0]) if m[0].startswith(("//", "/*")) else m[0]
    clean = JS_TOKENS.sub(comments, source)
    code = JS_TOKENS.sub(lambda m: blank(m[0]), clean)
    return clean, code


def location(source, offset):
    return source.count("\n", 0, offset) + 1, offset - source.rfind("\n", 0, offset)


def add(out, id, source, offset, message, confidence="low", engine="text-pattern"):
    line, column = location(source, offset)
    out.add(RULES[id], line, column, message, confidence, engine=engine)


def secrets(source: str, out: Collector, python=False):
    # Provider patterns and key headers are also checked in comments: a commented
    # credential still needs review. Never emit the matching token itself.
    for m in re.finditer(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", source):
        add(out, "SEC002", source, m.start(), "A private key header is present; key material is withheld.", "high", "secret-pattern")
    for pattern in TOKEN_PATTERNS:
        for m in pattern.finditer(source):
            add(out, "SEC003", source, m.start(), "A string resembles a provider credential; its value is withheld.", "medium", "secret-pattern")
    if not python:
        for pattern in (ASSIGNMENT, UNQUOTED):
            for m in pattern.finditer(source):
                value = m[3] if pattern is ASSIGNMENT else m[2]
                if credential_literal(m[1], value):
                    add(out, "SEC001", source, m.start(), "A credential-like setting contains a literal; its value is withheld.", "medium", "secret-pattern")


def first_argument(source, start):
    # A bounded lexical window, not a JS grammar. Covers ordinary quoted and
    # template arguments without mistaking a second parameter for SQL source.
    window = source[start:start + 2000]
    tokens = {m.start(): m for m in JS_TOKENS.finditer(window)}
    depth = 0
    i = 0
    while i < len(window):
        if i in tokens:
            i = tokens[i].end()
            continue
        char = window[i]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return window[:i]
            depth -= 1
        elif char == "," and depth == 0:
            return window[:i]
        i += 1
    return window


def javascript(source: str, out: Collector):
    clean, code = lexical_views(source)
    for m in re.finditer(r"(?<![\w.$])(?:eval\s*\(|(?:new\s+)?Function\s*\()", code):
        add(out, "JS001", source, m.start(), "Code-like text is passed to a dynamic execution API.")
    for m in re.finditer(r"\.\s*(?:innerHTML|outerHTML)\s*=(?!=)|\.\s*insertAdjacentHTML\s*\(", code):
        add(out, "JS003", source, m.start(), "A DOM API inserts raw HTML; trace and review the assigned value.")
    for m in re.finditer(r"\bdangerouslySetInnerHTML\s*[:=]", code):
        add(out, "JS006", source, m.start(), "React's raw HTML rendering escape hatch is used.")
    for m in re.finditer(r"\brejectUnauthorized\s*:\s*false\b", code):
        add(out, "JS004", source, m.start(), "A TLS-like option disables certificate verification.", "medium")
    for m in re.finditer(r'''\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]''', clean):
        add(out, "JS004", source, m.start(), "Node TLS verification is disabled through the environment.", "medium")
    for m in re.finditer(r"\.\s*(?:query|execute|raw)\s*\(", code):
        arg = first_argument(clean, m.end())
        _, arg_code = lexical_views(arg)
        if ("${" in arg and "`" in arg) or ("+" in arg_code and re.search(r"['\"]", arg)):
            add(out, "JS005", source, m.start(), "A database-like call appears to build SQL using interpolation or concatenation.")
    # Identify explicit Node child_process imports; avoid flagging RegExp.exec.
    names = set()
    namespaces = set()
    for m in re.finditer(r'''(?:import\s*\{([^}]+)\}\s*from\s*|(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*)['"](?:node:)?child_process['"]''', clean):
        if code[m.start()].isspace():
            continue
        for item in (m[1] or m[2]).split(","):
            parts = re.split(r"\s+as\s+|\s*:\s*", item.strip())
            if parts[0] in {"exec", "execSync"}:
                names.add(parts[-1])
    for m in re.finditer(r'''(?:import\s+(?:\*\s+as\s+)?(\w+)\s+from\s*|(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*)['"](?:node:)?child_process['"]''', clean):
        if code[m.start()].isspace():
            continue
        namespaces.add(m[1] or m[2])
    for name in names:
        for m in re.finditer(r"(?<![\w.$])" + re.escape(name) + r"\s*\(", code):
            add(out, "JS002", source, m.start(), "A child_process shell execution function is called.", "medium")
    for name in namespaces:
        for m in re.finditer(r"\b" + re.escape(name) + r"\.\s*exec(?:Sync)?\s*\(", code):
            add(out, "JS002", source, m.start(), "A child_process shell execution function is called.", "medium")


def config(source: str, path: str, out: Collector):
    flags = [
        ("CFG001", r"(?:DEBUG|FLASK_DEBUG)", r"(?:true|1)"),
        ("CFG002", r"(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)", r"(?:false|0)"),
        ("CFG003", r"SESSION_COOKIE_HTTPONLY", r"(?:false|0)"),
        ("CFG005", r"(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)", r"(?:true|1)"),
    ]
    for id, name, value in flags:
        pattern = rf'''(?im)^[ \t]*["']?{name}["']?[ \t]*[:=][ \t]*["']?{value}["']?[ \t]*(?:[,#;}}]|$)'''
        for m in re.finditer(pattern, source):
            add(out, id, source, m.start(), "A configuration flag selects an insecure production default.", "medium", "config-pattern")
    if PurePath(path).name.lower().startswith("dockerfile"):
        # Only the final stage's final USER is effective in the image itself.
        final = re.split(r"(?im)^\s*FROM\s+", source)[-1]
        users = list(re.finditer(r"(?im)^\s*USER\s+(\S+)", final))
        if users and users[-1][1].split(":")[0] in {"root", "0"}:
            offset = len(source) - len(final) + users[-1].start()
            add(out, "CFG006", source, offset, "The final container stage explicitly selects the root user.", "high", "config-pattern")
