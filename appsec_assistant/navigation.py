"""Code navigation for manual review; matches are not vulnerability verdicts."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .text_analyzer import lexical_views, location

LANGUAGES = {".php": "php", ".java": "java", ".cs": "csharp", ".go": "go", ".rb": "ruby"}
GUIDANCE = {
    "command execution": "Check who controls the program, command text and arguments; prefer fixed programs with structured arguments.",
    "dynamic execution": "Determine whether external input can become executable code or an expression.",
    "database query": "Verify parameter binding and trace any constructed query fragments or identifiers.",
    "deserialization": "Establish the origin and integrity of serialized data and prefer data-only formats.",
    "template/HTML output": "Distinguish template source from data and check contextual output escaping.",
    "filesystem access": "Check allowed base directories, canonicalization, symlinks and object-level authorization.",
    "outbound request": "Check destination trust, redirects, resolved addresses and network egress policy.",
    "redirect": "Check allowed destinations and URL normalization.",
    "authentication/crypto": "Review algorithm selection, key management, claim validation and session lifecycle.",
    "input": "Identify the trust boundary and trace validation before sensitive operations.",
    "entry point": "Review authentication, authorization, validation and state-changing behavior reachable from this entry point.",
    "function": "Navigation note: this declaration is not itself evidence of a security issue.",
}

# These patterns enumerate review locations, including legitimate safe use.
PATTERNS = {
    "python": [
        ("command execution", r"(?:^|\.)(?:system|popen|Popen|run|call|check_call|check_output|getoutput|getstatusoutput)$"),
        ("dynamic execution", r"(?:^|\.)(?:eval|exec|compile)$"),
        ("database query", r"\.(?:execute|executemany|executescript|raw)$"),
        ("deserialization", r"^(?:pickle|_pickle|marshal|dill|joblib|yaml)\.(?:load|loads|load_all|unsafe_load|full_load)$"),
        ("template/HTML output", r"(?:^|\.)(?:render_template_string|mark_safe|Markup|Template)$"),
        ("filesystem access", r"(?:^|\.)(?:open|send_file|send_from_directory|read_text|read_bytes|write_text|write_bytes|unlink|remove|extractall|extract)$"),
        ("outbound request", r"^(?:requests|httpx|urllib\.request)\.(?:get|post|put|patch|delete|request|urlopen|Request)$"),
        ("redirect", r"(?:^|\.)(?:redirect|RedirectResponse)$"),
        ("authentication/crypto", r"^(?:jwt|jose\.jwt|hashlib|hmac|cryptography|random|secrets)\."),
    ],
    "javascript/typescript": [
        ("command execution", r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\("),
        ("dynamic execution", r"\b(?:eval|Function|runInNewContext|runInThisContext)\s*\("),
        ("database query", r"\.\s*(?:query|execute|raw|aggregate|findOne)\s*\("),
        ("deserialization", r"\.\s*(?:unserialize|deserialize|load)\s*\("),
        ("template/HTML output", r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\s*[:=]|\.\s*(?:insertAdjacentHTML|render)\s*\("),
        ("filesystem access", r"\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|download|unlink)\s*\("),
        ("outbound request", r"\b(?:fetch|axios)\s*\(|\b(?:axios|https?|request)\.\s*(?:get|post|request)\s*\("),
        ("redirect", r"\.\s*redirect\s*\("),
        ("authentication/crypto", r"\b(?:jwt|crypto|bcrypt|argon2)\.\s*\w+\s*\("),
        ("input", r"\b(?:req|request)\.(?:body|query|params|headers|cookies|files)\b"),
    ],
    "php": [
        ("command execution", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
        ("dynamic execution", r"\b(?:eval|assert|include|include_once|require|require_once)\s*(?:\(|\$)"),
        ("database query", r"\b(?:mysqli_query|pg_query|mysql_query)\s*\(|->\s*(?:query|exec|prepare)\s*\("),
        ("deserialization", r"\bunserialize\s*\("),
        ("filesystem access", r"\b(?:fopen|file_get_contents|file_put_contents|readfile|unlink|move_uploaded_file)\s*\("),
        ("outbound request", r"\b(?:curl_exec|curl_setopt)\s*\("),
        ("input", r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"),
    ],
    "java": [
        ("command execution", r"\.\s*exec\s*\(|\bProcessBuilder\s*\("),
        ("database query", r"\.\s*(?:executeQuery|executeUpdate|execute|createNativeQuery|prepareStatement)\s*\("),
        ("deserialization", r"\b(?:ObjectInputStream|XMLDecoder|Yaml|XStream)\s*\(|\.readObject\s*\("),
        ("filesystem access", r"\b(?:FileInputStream|FileOutputStream|File|Path)\s*\(|\bFiles\.\w+\s*\("),
        ("outbound request", r"\bURL\s*\(|\.(?:openConnection|sendAsync|send)\s*\("),
        ("template/HTML output", r"\bTemplate\s*\(|\.getWriter\s*\("),
        ("input", r"\.(?:getParameter|getHeader|getInputStream|getCookies)\s*\("),
    ],
    "csharp": [
        ("command execution", r"\bProcess\.(?:Start|StartInfo)\b"),
        ("database query", r"\b(?:SqlCommand|NpgsqlCommand)\s*\(|\.(?:ExecuteSqlRaw|FromSqlRaw|Query|Execute)\s*\("),
        ("deserialization", r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter)\b|\.Deserialize\s*\("),
        ("filesystem access", r"\b(?:File|Directory|Path)\.\w+\s*\("),
        ("outbound request", r"\.(?:GetAsync|PostAsync|SendAsync|DownloadString)\s*\("),
        ("template/HTML output", r"\bHtml\.Raw\s*\("),
        ("input", r"\bRequest\.(?:Query|Form|Body|Headers|Cookies)\b"),
    ],
    "go": [
        ("command execution", r"\bexec\.(?:Command|CommandContext)\s*\("),
        ("database query", r"\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\("),
        ("template/HTML output", r"\btemplate\.(?:HTML|JS|URL|CSS)\s*\("),
        ("filesystem access", r"\b(?:os|ioutil)\.(?:Open|OpenFile|ReadFile|WriteFile|Remove|Create)\s*\("),
        ("outbound request", r"\bhttp\.(?:Get|Post|NewRequest)\s*\(|\.Do\s*\("),
        ("input", r"\.(?:FormValue|PostFormValue|Query)\s*\("),
    ],
    "ruby": [
        ("command execution", r"\b(?:system|exec|spawn)\s*(?:\(|\w)|\bOpen3\.\w+"),
        ("dynamic execution", r"\b(?:eval|instance_eval|class_eval)\b"),
        ("database query", r"\.(?:where|find_by_sql|execute)\b"),
        ("deserialization", r"\b(?:Marshal|YAML)\.(?:load|restore|unsafe_load)\b"),
        ("filesystem access", r"\bFile\.(?:read|open|write|delete)\b|\bsend_file\b"),
        ("outbound request", r"\b(?:Net::HTTP|URI)\.\w+"),
        ("input", r"\b(?:params|request|cookies)\b"),
    ],
}


class MapBuilder:
    def __init__(self, path, language):
        self.path, self.language = path, language
        self.items = []
        self.seen = set()

    def add(self, line, name, category, function="<module>", end_line=None):
        key = (line, name, category)
        if key in self.seen:
            return
        self.seen.add(key)
        self.items.append({"path": self.path, "line": line, "end_line": end_line or line,
                           "name": name, "category": category, "function": function,
                           "kind": "note" if category == "function" else "review-hotspot",
                           "language": self.language, "review": GUIDANCE[category],
                           "engine": "python-ast" if self.language == "python" else "lexical"})


def python_map(tree, path):
    builder = MapBuilder(path, "python")
    aliases = {}
    # A navigation map is intentionally inclusive; alias resolution is best effort.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return name(node.value) + "." + node.attr
        return ""
    def visit(node, scope="<module>"):
        if isinstance(node, ast.ClassDef):
            scope = node.name if scope == "<module>" else scope + "." + node.name
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = node.name if scope == "<module>" else scope + "." + node.name
            builder.add(node.lineno, scope, "function", scope, node.end_lineno)
            for deco in node.decorator_list:
                n = name(deco.func if isinstance(deco, ast.Call) else deco)
                if n.rsplit(".", 1)[-1] in {"route", "get", "post", "put", "patch", "delete", "api_view", "websocket", "action"}:
                    builder.add(deco.lineno, n, "entry point", scope)
        if isinstance(node, ast.Call):
            n = name(node.func)
            for category, pattern in PATTERNS["python"]:
                if re.search(pattern, n):
                    builder.add(node.lineno, n, category, scope)
            if n in {"input", "flask.request.get_json", "request.get_json"}:
                builder.add(node.lineno, n, "input", scope)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            n = name(node)
            if re.match(r"^(?:flask\.)?(?:request|req)\.(?:args|form|values|json|data|GET|POST|body|headers|cookies|query_params|path_params)$", n):
                builder.add(node.lineno, n, "input", scope)
        for child in ast.iter_child_nodes(node):
            visit(child, scope)
    visit(tree)
    return builder.items


FUNCTION_PATTERNS = {
    "javascript/typescript": [r"\bfunction\s+([\w$]+)\s*\(", r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w$]+)\s*(?::[^=;]+)?=>"],
    "php": [r"\bfunction\s+&?\s*(\w+)\s*\("],
    "java": [r"(?m)^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)+[\w<>\[\].?, ]+\s+(\w+)\s*\("],
    "csharp": [r"(?m)^\s*(?:(?:public|private|protected|internal|static|async|virtual|override)\s+)+[\w<>\[\].?, ]+\s+(\w+)\s*\("],
    "go": [r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\("],
    "ruby": [r"(?m)^\s*def\s+([\w.?!]+)"],
}


def lexical_map(source, path, language):
    builder = MapBuilder(path, language)
    _, code = lexical_views(source)
    if language == "ruby":
        code = re.sub(r"(?m)#[^\n]*", lambda m: " " * len(m[0]), code)
    functions = []
    stack, closing = [], {}
    for pos, char in enumerate(code):
        if char == "{":
            stack.append(pos)
        elif char == "}" and stack:
            closing[stack.pop()] = pos + 1
    for pattern in FUNCTION_PATTERNS.get(language, []):
        for m in re.finditer(pattern, code):
            line, _ = location(source, m.start(1))
            end = line
            # Scope approximation only; Ruby blocks and arrow expression bodies
            # deliberately retain a single-line scope rather than claiming precision.
            brace = code.find("{", m.end(), m.end() + 300)
            if language != "ruby" and 0 <= brace - m.end() < 300:
                pos = closing.get(brace, brace)
                end = location(source, pos)[0]
            functions.append((line, end, m[1]))
            builder.add(line, m[1], "function", m[1], end)
    for category, pattern in PATTERNS.get(language, []):
        for m in re.finditer(pattern, code):
            line, _ = location(source, m.start())
            scope = next((n for a, b, n in sorted(functions, reverse=True) if a <= line <= b), "<module or unresolved>")
            # Only API syntax from the string-masked source appears in the map.
            name = re.sub(r"\s+", " ", m[0]).strip().rstrip("(").strip()
            builder.add(line, name, category, scope)
    routes = {
        "javascript/typescript": r"\b(?:app|router|server)\.\s*(?:get|post|put|patch|delete|use|all)\s*\(",
        "java": r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b",
        "csharp": r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route)\b|\.(?:MapGet|MapPost|MapPut|MapDelete)\s*\(",
        "go": r"\b(?:http\.)?HandleFunc\s*\(|\.(?:GET|POST|PUT|DELETE|HandleFunc)\s*\(",
        "php": r"\bRoute::(?:get|post|put|delete|any)\s*\(",
        "ruby": r"(?m)^\s*(?:get|post|put|patch|delete)\b",
    }
    for m in re.finditer(routes.get(language, r"(?!)"), code):
        line, _ = location(source, m.start())
        builder.add(line, re.sub(r"\s+", " ", m[0]).strip().rstrip("("), "entry point")
    return sorted(builder.items, key=lambda x: (x["line"], x["category"]))
