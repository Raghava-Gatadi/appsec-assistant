"""Code navigation for manual review; matches are not vulnerability verdicts."""
from __future__ import annotations

import ast
import re

from .priorities import NEAR_LINES  # noqa: F401  (shared proximity threshold)
from .text_analyzer import JS_TOKENS, blank, first_argument, lexical_views, location

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
    "state": "Server-side or process state (session, environment, framework globals). Not request-controlled by itself; check where it is populated.",
    "entry point": "Review authentication, authorization, validation and state-changing behavior reachable from this entry point.",
    "mitigation": "A potentially protective API or check is present. Verify its arguments, context and connection to the sensitive operation; this is not a safe verdict.",
    "function": "Navigation note: this declaration is not itself evidence of a security issue.",
}

# Every language exposes the same category vocabulary. A missing category is an
# explicit, documented gap (see DOCUMENTED_GAPS), never a silent omission.
# "input" means request-controlled data; "state" means server-side/process state
# that is not attacker-controlled by itself. Both are navigation, not verdicts.
CATEGORIES = (
    "command execution", "dynamic execution", "database query", "deserialization",
    "template/HTML output", "filesystem access", "outbound request", "redirect",
    "authentication/crypto", "input", "state", "mitigation",
)
DOCUMENTED_GAPS = {
    ("go", "dynamic execution"): "Go has no built-in eval; plugin and reflection loading are not modeled.",
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
        ("redirect", r"(?:^|\.)(?:redirect|RedirectResponse|HttpResponseRedirect)$"),
        ("mitigation", r"^(?:int|float|html\.escape|shlex\.quote|os\.path\.basename|os\.path\.normpath|os\.path\.realpath|secure_filename|werkzeug\.utils\.secure_filename|markupsafe\.escape|flask\.escape|urllib\.parse\.quote|bleach\.clean|django\.utils\.html\.escape)$"),
        ("authentication/crypto", r"^(?:jwt|jose\.jwt|hashlib|hmac|cryptography|random|secrets)\."),
        ("input", r"^(?:input|(?:flask\.)?request\.get_json)$"),
        ("state", r"^(?:os\.environ|os\.getenv)$"),
    ],
    "javascript/typescript": [
        ("command execution", r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\("),
        ("dynamic execution", r"\b(?:eval|Function|runInNewContext|runInThisContext)\s*\("),
        ("database query", r"\.\s*(?:query|execute|raw|aggregate|findOne)\s*\("),
        ("deserialization", r"\.\s*(?:unserialize|deserialize|load)\s*\("),
        ("template/HTML output", r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\s*[:=]|\.\s*(?:insertAdjacentHTML|render)\s*\("),
        ("filesystem access", r"\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|download|unlink)\s*\("),
        ("outbound request", r"\b(?:fetch|axios)\s*\(|\b(?:axios|https?|request)\.\s*(?:get|post|request)\s*\("),
        ("redirect", r"\.\s*redirect\s*\(|\b(?:location\.(?:href|assign|replace))\b\s*(?:=(?!=)|\()"),
        ("authentication/crypto", r"\b(?:jwt|crypto|bcrypt|argon2)\.\s*\w+\s*\("),
        ("mitigation", r"\b(?:parseInt|Number|encodeURIComponent|encodeURI|escapeHtml)\s*\(|\bDOMPurify\.sanitize\s*\(|\bpath\.(?:basename|normalize)\s*\(|\bvalidator\.\w+\s*\("),
        ("input", r"\b(?:req|request)\.(?:body|query|params|headers|cookies|files|signedCookies)\b|\blocation\.(?:search|hash)\b|\bdocument\.(?:URL|referrer)\b"),
        ("state", r"\bprocess\.env\b|\b(?:req|request)\.session\b"),
    ],
    "php": [
        ("command execution", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
        ("dynamic execution", r"\b(?:eval|assert)\s*(?:\(|\$)"),
        ("database query", r"\b(?:mysqli_query|pg_query|mysql_query|mysqli_prepare|pg_prepare)\s*\(|->\s*(?:query|exec|prepare)\s*\("),
        ("deserialization", r"\bunserialize\s*\("),
        # header("Location: ...") needs argument inspection and is handled separately.
        ("redirect", r"\b(?:wp_redirect|redirect)\s*\(|\bRedirect::(?:to|away)\s*\("),
        ("filesystem access", r"\b(?:fopen|file_get_contents|file_put_contents|readfile|unlink|move_uploaded_file)\s*\("),
        ("outbound request", r"\b(?:curl_exec|curl_setopt)\s*\("),
        ("template/HTML output", r"\b(?:echo|print)\b|\bprintf\s*\(|<\?="),
        ("authentication/crypto", r"\b(?:rand|mt_rand)\s*\("),
        ("mitigation", r"\b(?:intval|escapeshellarg|escapeshellcmd|htmlspecialchars|htmlentities|basename|realpath|in_array|is_numeric|filter_var|filter_input|ctype_\w+|mysqli_real_escape_string|mysqli_prepare|mysqli_stmt_bind_param|pg_prepare)\s*\(|\(\s*int\s*\)|->\s*(?:prepare|bindParam|bindValue|bind_param)\s*\("),
        # Request superglobals only. $_SERVER keys are classified separately below.
        ("input", r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"),
        ("state", r"\$(?:_(?:SESSION|ENV|SERVER)|GLOBALS)\b"),
    ],
    "java": [
        ("command execution", r"\.\s*exec\s*\(|\bProcessBuilder\s*\("),
        ("dynamic execution", r"\bClass\.forName\s*\(|\bGroovyShell\b|\.\s*parseExpression\s*\(|\bScriptEngine\b"),
        ("database query", r"\.\s*(?:executeQuery|executeUpdate|execute|createNativeQuery|prepareStatement)\s*\("),
        ("deserialization", r"\b(?:ObjectInputStream|XMLDecoder|Yaml|XStream)\s*\(|\.readObject\s*\("),
        ("filesystem access", r"\b(?:FileInputStream|FileOutputStream|File|Path)\s*\(|\bFiles\.\w+\s*\("),
        ("outbound request", r"\bURL\s*\(|\.(?:openConnection|sendAsync|send)\s*\("),
        ("template/HTML output", r"\bTemplate\s*\(|\.getWriter\s*\("),
        ("redirect", r"\.\s*sendRedirect\s*\(|\bnew\s+RedirectView\s*\("),
        ("authentication/crypto", r"\b(?:MessageDigest|Cipher|KeyGenerator)\.getInstance\s*\(|\bnew\s+Random\s*\(|\bMath\.random\s*\("),
        ("mitigation", r"\.\s*set(?:String|Int|Long|Date|Object)\s*\(|\b(?:Integer|Long)\.parseInt\s*\(|\bHtmlUtils\.htmlEscape\s*\(|\bStringEscapeUtils\.escape\w+\s*\(|\bEncode\.for\w+\s*\(|\.\s*normalize\s*\(\s*\)|\.getCanonicalPath\s*\("),
        ("input", r"\.(?:getParameter|getParameterMap|getHeader|getInputStream|getCookies|getQueryString|getRequestURI)\s*\(|@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)\b"),
        ("state", r"\.getSession\s*\(|\bSystem\.(?:getenv|getProperty)\s*\("),
    ],
    "csharp": [
        ("command execution", r"\bProcess\.(?:Start|StartInfo)\b"),
        ("dynamic execution", r"\b(?:CSharpScript\.(?:Evaluate|Run)\w*|Assembly\.Load\w*|Activator\.CreateInstance)\b|\bType\.GetType\s*\("),
        ("database query", r"\b(?:SqlCommand|NpgsqlCommand)\s*\(|\.(?:ExecuteSqlRaw|FromSqlRaw|Query|Execute)\s*\("),
        ("deserialization", r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter)\b|\.Deserialize\s*\("),
        ("filesystem access", r"\b(?:File|Directory|Path)\.\w+\s*\("),
        ("outbound request", r"\.(?:GetAsync|PostAsync|SendAsync|DownloadString)\s*\("),
        ("template/HTML output", r"\bHtml\.Raw\s*\(|\bHtmlString\s*\(|\bResponse\.Write\s*\("),
        ("redirect", r"\b(?:Response\.Redirect|Redirect|RedirectPermanent|RedirectToAction|RedirectToRoute)\s*\("),
        ("authentication/crypto", r"\b(?:MD5|SHA1|DES|TripleDES|RC2)\.Create\s*\(|\bnew\s+(?:MD5|SHA1)CryptoServiceProvider\b|\bnew\s+Random\s*\(|\bJwtSecurityTokenHandler\b"),
        ("mitigation", r"\bLocalRedirect\s*\(|\bUrl\.IsLocalUrl\s*\(|\b(?:HttpUtility|WebUtility)\.HtmlEncode\s*\(|\bHtmlEncoder\.\w+|\.Parameters\.(?:Add|AddWithValue)\s*\(|\b(?:int|long)\.(?:Parse|TryParse)\s*\(|\bPath\.GetFileName\s*\("),
        ("input", r"\bRequest\.(?:Query|Form|Body|Headers|Cookies|QueryString|Params)\b|\[From(?:Query|Body|Form|Header)\]"),
        ("state", r"\bHttpContext\.Session\b|\bSession\s*\[|\bEnvironment\.GetEnvironmentVariable\s*\("),
    ],
    "go": [
        ("command execution", r"\bexec\.(?:Command|CommandContext)\s*\("),
        ("database query", r"(?<!URL)\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\("),
        ("deserialization", r"\bgob\.NewDecoder\s*\("),
        ("template/HTML output", r"\btemplate\.(?:HTML|JS|URL|CSS)\s*\("),
        ("filesystem access", r"\b(?:os|ioutil)\.(?:Open|OpenFile|ReadFile|WriteFile|Remove|Create)\s*\("),
        ("outbound request", r"\bhttp\.(?:Get|Post|NewRequest)\s*\(|\.Do\s*\("),
        ("redirect", r"\bhttp\.Redirect\s*\("),
        ("authentication/crypto", r"\b(?:md5|sha1|des|rc4)\.(?:New|Sum)\w*\s*\(|\brand\.(?:Int|Intn|Int31|Int63|Seed|Read)\s*\(|\bjwt\.\w+\s*\("),
        ("mitigation", r"\b(?:html\.EscapeString|template\.(?:HTML|JS)EscapeString|url\.QueryEscape|filepath\.(?:Clean|Base)|path\.(?:Clean|Base)|strconv\.(?:Atoi|ParseInt))\s*\("),
        ("input", r"\.(?:FormValue|PostFormValue|PathValue)\s*\(|\bURL\.Query\s*\(|\.Header\.Get\s*\(|\.Cookie\s*\("),
        ("state", r"\bos\.(?:Getenv|LookupEnv)\s*\("),
    ],
    "ruby": [
        ("command execution", r"\b(?:system|exec|spawn)\s*(?:\(|\w)|\bOpen3\.\w+"),
        ("dynamic execution", r"\b(?:eval|instance_eval|class_eval)\b"),
        ("database query", r"\.(?:where|find_by_sql|execute)\b"),
        ("deserialization", r"\b(?:Marshal|YAML)\.(?:load|restore|unsafe_load)\b"),
        ("template/HTML output", r"\.html_safe\b|\braw\s*[(\s]"),
        ("filesystem access", r"\bFile\.(?:read|open|write|delete)\b|\bsend_file\b"),
        ("outbound request", r"\b(?:Net::HTTP|URI)\.\w+"),
        ("redirect", r"\bredirect_(?:to|back)\b"),
        ("authentication/crypto", r"\bDigest::(?:MD5|SHA1)\b|\bOpenSSL::\w+|\bBCrypt\b|\b(?:rand|srand)\s*\(|\bJWT\.\w+"),
        ("mitigation", r"\bERB::Util\.(?:h|html_escape)\b|\bsanitize\s*\(|\bShellwords\.(?:escape|shellescape)\b|\.shellescape\b|\.to_i\b|\bFile\.basename\b|\bsanitize_sql\w*\b"),
        ("input", r"\b(?:params|request|cookies)\b"),
        ("state", r"\bsession\s*\[|\bENV\s*\["),
    ],
}

# Only these $_SERVER keys are request-controlled; other keys are server state.
PHP_SERVER_REQUEST_KEY = re.compile(r"""\s*\[\s*['"](?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO|PATH_TRANSLATED|PHP_AUTH_\w+)['"]\s*\]""")
NOTE_CATEGORIES = {"function", "mitigation", "state"}


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
                           "kind": "note" if category in NOTE_CATEGORIES else "review-hotspot",
                           "language": self.language, "review": GUIDANCE[category],
                           "engine": "python-ast" if self.language == "python" else "lexical"})

    def finish(self):
        declarations = [m for m in self.items if m["category"] == "function"]
        for item in self.items:
            if item["function"] in {"<module>", "<module or unresolved>"}:
                item["function"] = f"<file: {self.path}>"
                item["scope_start"] = 0
            else:
                scopes = [m for m in declarations if m["name"] == item["function"]]
                scope = min(scopes, key=lambda m: abs(item["line"] - m["line"]), default=None)
                # Prefer containment for repeated declaration names.
                scope = next((m for m in reversed(scopes) if m["line"] <= item["line"] <= m["end_line"]), scope)
                item["scope_start"] = scope["line"] if scope else 0
        return sorted(self.items, key=lambda x: (x["line"], x["category"]))


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
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            n = name(node)
            if re.match(r"^(?:flask\.)?(?:request|req)\.(?:args|form|values|json|data|GET|POST|body|headers|cookies|query_params|path_params)$", n) or n == "sys.argv":
                builder.add(node.lineno, n, "input", scope)
            elif n == "os.environ":
                builder.add(node.lineno, n, "state", scope)
        for child in ast.iter_child_nodes(node):
            visit(child, scope)
    visit(tree)
    return builder.finish()


FUNCTION_PATTERNS = {
    "javascript/typescript": [r"\bfunction\s+([\w$]+)\s*\(", r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w$]+)\s*(?::[^=;]+)?=>"],
    "php": [r"\bfunction\s+&?\s*(\w+)\s*\("],
    "java": [r"(?m)^[ \t]*(?:(?:public|private|protected|static|final|synchronized|abstract|native)\s+)*(?!(?:return|else|new|throw|case)\b)[\w<>\[\].?,]+(?:<[^>\n]*>)?[ \t]+(?!(?:if|for|while|switch|catch|synchronized)\b)(\w+)\s*\((?=[^;{}]*\)\s*(?:throws\s[^{;]*)?\{)"],
    "csharp": [r"(?m)^[ \t]*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|abstract)\s+)*(?!(?:return|else|new|throw|case|await)\b)[\w<>\[\].?,]+(?:<[^>\n]*>)?[ \t]+(?!(?:if|for|foreach|while|switch|catch|lock|using)\b)(\w+)\s*\((?=[^;{}]*\)\s*(?:where\s[^{;]*)?\{)"],
    "go": [r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\("],
    "ruby": [r"(?m)^\s*def\s+([\w.?!]+)"],
}



def static_php_path(expr):
    """True when an include/require argument is built only from literals and constants.

    `ROOT . 'lib/a.php'`, `__DIR__ . '/a.php'` and `dirname(__FILE__) . '/a.php'` are
    fixed paths. A variable, interpolation or function result makes the path dynamic.
    """
    if not expr.strip():
        return False
    for literal in re.finditer(r'"(?:\\.|[^"\\])*"', expr):
        if "$" in literal[0] or "{" in literal[0]:
            return False
    rest = JS_TOKENS.sub(" ", expr)
    rest = re.sub(r"\b(?:dirname|realpath)\s*\(", "(", rest)
    rest = re.sub(r"\b(?:__DIR__|__FILE__)\b", " ", rest)
    rest = re.sub(r"\b[A-Z][A-Z0-9_]*\b", " ", rest)
    return re.sub(r"[().\s]", "", rest) == ""


def lexical_map(source, path, language):
    builder = MapBuilder(path, language)
    clean, code = lexical_views(source)
    if language in {"ruby", "php"}:
        code = re.sub(r"(?m)#[^\n]*", lambda m: blank(m[0]), code)
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
    ordered = sorted(functions, reverse=True)

    def scope_of(line):
        return next((n for a, b, n in ordered if a <= line <= b), "<module or unresolved>")

    def php_write(end):
        # A direct write to a superglobal is not a read boundary.
        tail = code[end:end + 2000].lstrip()
        while tail.startswith("["):
            depth, close = 0, None
            for i, char in enumerate(tail):
                depth += (char == "[") - (char == "]")
                if depth == 0:
                    close = i + 1
                    break
            if close is None:
                break
            tail = tail[close:].lstrip()
        return bool(re.match(r"=(?!=|>)", tail))

    for category, pattern in PATTERNS.get(language, []):
        flags = re.I if language == "php" and category not in {"input", "state"} else 0
        for m in re.finditer(pattern, code, flags):
            line, _ = location(source, m.start())
            name, kind = re.sub(r"\s+", " ", m[0]).strip().rstrip("(").strip(), category
            if language == "php" and category in {"input", "state"}:
                if php_write(m.end()):
                    continue
                if name == "$_SERVER" and PHP_SERVER_REQUEST_KEY.match(source, m.end()):
                    kind = "input"
            # Only API syntax from the string-masked source appears in the map.
            builder.add(line, name, kind, scope_of(line))
    routes = {
        "javascript/typescript": r"\b(?:app|router|server)\.\s*(?:get|post|put|patch|delete|use|all)\s*\(",
        "java": r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b",
        "csharp": r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route)\b|\.(?:MapGet|MapPost|MapPut|MapDelete)\s*\(",
        "go": r"\b(?:http\.)?HandleFunc\s*\(|\.(?:GET|POST|PUT|DELETE|HandleFunc)\s*\(",
        "php": r"\bRoute::(?:get|post|put|delete|any)\s*\(",
        "ruby": r"(?m)^\s*(?:get|post|put|patch|delete)\b",
    }
    declared_routes = 0
    for m in re.finditer(routes.get(language, r"(?!)"), code):
        line, _ = location(source, m.start())
        builder.add(line, re.sub(r"\s+", " ", m[0]).strip().rstrip("("), "entry point", scope_of(line))
        declared_routes += 1
    if language == "php":
        for m in re.finditer(r"\b(?:include_once|require_once|include|require)\b", code, re.I):
            tail = clean[m.end():].lstrip()
            expr = first_argument(tail[1:] if tail.startswith("(") else tail, 0)
            _, expr_code = lexical_views(expr)
            end = expr_code.find(";")
            expr = (expr[:end] if end >= 0 else expr).strip()
            if not static_php_path(expr):
                line = location(source, m.start())[0]
                builder.add(line, m[0], "dynamic execution", scope_of(line))
        for m in re.finditer(r"\bheader\s*\(", code, re.I):
            arg = first_argument(clean, m.end()).lstrip()
            if re.match(r"[\"']\s*Location\s*:", arg, re.I):
                line = location(source, m.start())[0]
                builder.add(line, "header(Location)", "redirect", scope_of(line))
        for m in re.finditer(r"\b(?:md5|sha1)\s*\(", code, re.I):
            arg = first_argument(clean, m.end())
            prefix = clean[clean.rfind("\n", 0, m.start()) + 1:m.start()]
            if re.search(r"pass(?:word|wd)?|secret", arg + prefix, re.I):
                line = location(source, m.start())[0]
                builder.add(line, m[0].rstrip("( "), "authentication/crypto", scope_of(line))
    # Script-style code (PHP pages, Rails controllers, plain handlers) has no
    # route declaration. When a file declares none, each scope that reads
    # request-controlled input is a candidate entry point. Server-side state
    # never creates a hint.
    if not declared_routes:
        by_scope = {}
        for item in builder.items:
            if item["category"] == "input":
                by_scope.setdefault(item["function"], []).append(item["line"])
        for scope, lines in by_scope.items():
            builder.add(min(lines), "Reads request input (entry-point hint)", "entry point", scope)
    return builder.finish()
