"""Bounded, intraprocedural AST analysis. Source is parsed, never imported."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .models import Collector, Trace
from .rules import RULES


@dataclass(frozen=True)
class Value:
    dynamic: bool = True
    literal: object = None
    known: bool = False
    trace: tuple[Trace, ...] = ()

    @property
    def external(self):
        return any(t.kind == "external" for t in self.trace)

    @property
    def influenced(self):
        return any(t.kind in {"external", "parameter"} for t in self.trace)


def merge(*values: Value) -> Value:
    if not values:
        return Value()
    trace = tuple(dict.fromkeys(t for v in values for t in v.trace))
    # Keep source evidence even after long assignment chains.
    trace = tuple(t for t in trace if t.kind in {"external", "parameter"})[:4] + tuple(
        t for t in trace if t.kind not in {"external", "parameter"})[-8:]
    same = all(v.known and v.literal == values[0].literal for v in values)
    return Value(any(v.dynamic for v in values), values[0].literal if same else None, same, trace)


SENSITIVE_NAME = re.compile(r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)", re.I)
PLACEHOLDER = re.compile(r"^(?:example|sample|dummy|test|fake|placeholder|changeme|change_me|your[_ -]|replace[_ -]|xxx|<|\$\{|\{\{)", re.I)


def credential_literal(name: str, value: object) -> bool:
    return (bool(SENSITIVE_NAME.search(name)) and isinstance(value, str)
            and len(value) >= 8 and not PLACEHOLDER.search(value)
            and value.lower() not in {"undefined", "redacted"})


def target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return str(node.slice.value)
    return ""


class Analyzer(ast.NodeVisitor):
    def __init__(self, collector: Collector):
        self.out = collector
        self.env: dict[str, Value] = {}
        self.aliases: dict[str, str] = {}
        self.scopes: list[str] = []

    def name(self, node: ast.AST | None) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            prefix = self.name(node.value)
            return f"{prefix}.{node.attr}" if prefix else ""
        return ""

    def source(self, node: ast.AST) -> str | None:
        name = self.name(node)
        if re.match(r"^(?:flask\.)?(?:request|req)\.(?:args|form|values|json|data|cookies|headers|files|GET|POST|body|query_params|path_params)(?:\.|$)", name):
            return "HTTP request input"
        if name.startswith("sys.argv"):
            return "Command-line input"
        if isinstance(node, ast.Call):
            called = self.name(node.func)
            if called in {"input", "builtins.input"}:
                return "Interactive input"
            if re.match(r"^(?:flask\.)?(?:request|req)\.(?:get_json|json|body|form)$", called):
                return "HTTP request input"
            return self.source(node.func)
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            return self.source(node.value)
        return None

    def value(self, node: ast.AST | None) -> Value:
        if node is None:
            return Value(False, None, True)
        source = self.source(node)
        if source:
            return Value(trace=(Trace(node.lineno, source, "external"),))
        if isinstance(node, ast.Constant):
            return Value(False, node.value, True)
        if isinstance(node, ast.Name):
            return self.env.get(node.id, Value())
        if isinstance(node, ast.NamedExpr):
            return self.value(node.value)
        if isinstance(node, ast.Call):
            # Numeric conversion removes string syntax but does not establish
            # authorization or a safe URL/path. Drop taint only for SQL/shell use
            # by retaining the flow; conservative review is preferable here.
            values = [self.value(a) for a in node.args] + [self.value(k.value) for k in node.keywords]
            if isinstance(node.func, ast.Attribute):
                values.insert(0, self.value(node.func.value))
            merged = merge(*values)
            return Value(True, trace=merged.trace)
        if isinstance(node, ast.Attribute):
            return Value(True, trace=self.value(node.value).trace)
        if isinstance(node, ast.Subscript):
            return merge(self.value(node.value), self.value(node.slice))
        if isinstance(node, ast.JoinedStr):
            vals = [self.value(n.value) if isinstance(n, ast.FormattedValue) else self.value(n) for n in node.values]
            return Value(any(v.dynamic for v in vals), trace=merge(*vals).trace)
        if isinstance(node, ast.BinOp):
            left, right = self.value(node.left), self.value(node.right)
            if (isinstance(node.op, ast.Add) and left.known and right.known
                    and isinstance(left.literal, str) and isinstance(right.literal, str)
                    and len(left.literal) + len(right.literal) < 65536):
                return Value(False, left.literal + right.literal, True)
            return merge(left, right)
        if isinstance(node, ast.IfExp):
            return merge(self.value(node.body), self.value(node.orelse))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            v = self.value(node.operand)
            return Value(False, not v.literal, True) if v.known else v
        return merge(*(self.value(n) for n in ast.iter_child_nodes(node) if isinstance(n, ast.expr)))

    def emit(self, id: str, node: ast.AST, message: str, value: Value | None = None,
             confidence: str | None = None, severity: str | None = None):
        v = value or Value()
        confidence = confidence or ("high" if v.external else "medium" if v.influenced else "low")
        trace = v.trace + ((Trace(node.lineno, "Security-sensitive operation", "sink"),) if v.trace else ())
        self.out.add(RULES[id], node.lineno, node.col_offset + 1, message, confidence, trace, severity=severity)

    def bind(self, target: ast.AST, value: Value, origin: ast.AST | None = None):
        if isinstance(target, ast.Name):
            flow = value.trace + (Trace(target.lineno, f"Assigned to {target.id}"),) if value.trace else ()
            bounded = merge(Value(trace=flow)).trace
            self.env[target.id] = Value(value.dynamic, value.literal, value.known, bounded)
            canonical = self.name(origin) if isinstance(origin, (ast.Name, ast.Attribute)) else ""
            if isinstance(origin, ast.Call) and self.name(origin.func) in {"requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient"}:
                canonical = self.name(origin.func)
            # Resolve explicit callable/module aliases; shadowed builtins must
            # not be mistaken for the original builtin.
            self.aliases[target.id] = canonical or ""
        elif isinstance(target, (ast.Tuple, ast.List)):
            for part in target.elts:
                self.bind(part, value)
        name = target_name(target)
        if isinstance(origin, ast.Constant) and value.known and credential_literal(name, value.literal):
            self.emit("SEC001", target, "A credential-like field contains a string literal; its value is withheld.", confidence="medium")
        if value.known:
            flags = {"DEBUG": (True, "CFG001"), "SESSION_COOKIE_SECURE": (False, "CFG002"),
                     "CSRF_COOKIE_SECURE": (False, "CFG002"), "SESSION_COOKIE_HTTPONLY": (False, "CFG003"),
                     "CORS_ALLOW_ALL_ORIGINS": (True, "CFG005"), "CORS_ORIGIN_ALLOW_ALL": (True, "CFG005")}
            if name in flags and value.literal is flags[name][0]:
                self.emit(flags[name][1], target, f"{name} is set to an insecure production default.", confidence="high")
        if name == "ALLOWED_HOSTS" and isinstance(origin, (ast.List, ast.Tuple)):
            if any(isinstance(n, ast.Constant) and n.value == "*" for n in origin.elts):
                self.emit("CFG004", target, "The host allowlist contains a wildcard.", confidence="high")
        if SENSITIVE_NAME.search(name) and origin:
            for n in ast.walk(origin):
                if isinstance(n, ast.Call) and self.name(n.func).startswith("random."):
                    self.emit("PY008", n, "A security-named value is generated using the random module.", confidence="medium")

    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]

    def visit_ImportFrom(self, node):
        for a in node.names:
            if a.name != "*":
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def visit_Assign(self, node):
        self.visit(node.value)
        val = self.value(node.value)
        for target in node.targets:
            self.bind(target, val, node.value)

    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
            self.bind(node.target, self.value(node.value), node.value)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self.bind(node.target, merge(self.value(node.target), self.value(node.value)))

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.bind(node.target, self.value(node.value), node.value)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                val = self.value(value)
                if isinstance(value, ast.Constant) and val.known and credential_literal(key.value, val.literal):
                    self.emit("SEC001", value, "A credential-like dictionary field contains a literal; its value is withheld.", confidence="medium")
        self.generic_visit(node)

    def _function(self, node):
        for expr in node.decorator_list + node.args.defaults + [n for n in node.args.kw_defaults if n]:
            self.visit(expr)
        self.aliases[node.name] = ""
        saved_env, saved_aliases = self.env, self.aliases
        self.env, self.aliases = self.env.copy(), self.aliases.copy()
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        args += [a for a in [node.args.vararg, node.args.kwarg] if a]
        for arg in args:
            self.env[arg.arg] = Value(trace=(Trace(arg.lineno, f"Parameter {arg.arg} (trust unknown)", "parameter"),))
            # Preserve recognition of common framework request parameter names.
            self.aliases[arg.arg] = arg.arg if arg.arg in {"request", "req"} else ""
        self.scopes.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.scopes.pop()
        self.env, self.aliases = saved_env, saved_aliases

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_Lambda(self, node):
        saved_env, saved_aliases = self.env, self.aliases
        self.env, self.aliases = self.env.copy(), self.aliases.copy()
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.env[arg.arg] = Value(trace=(Trace(arg.lineno, f"Parameter {arg.arg} (trust unknown)", "parameter"),))
            self.aliases[arg.arg] = arg.arg if arg.arg in {"request", "req"} else ""
        self.visit(node.body)
        self.env, self.aliases = saved_env, saved_aliases

    def visit_ClassDef(self, node):
        self.aliases[node.name] = ""
        saved_env, saved_aliases = self.env, self.aliases
        self.env, self.aliases = self.env.copy(), self.aliases.copy()
        self.generic_visit(node)
        self.env, self.aliases = saved_env, saved_aliases

    def branches(self, bodies):
        initial_env, initial_aliases = self.env.copy(), self.aliases.copy()
        states = []
        for body in bodies:
            self.env, self.aliases = initial_env.copy(), initial_aliases.copy()
            for stmt in body:
                self.visit(stmt)
            states.append((self.env, self.aliases))
        names = set().union(*(s[0] for s in states))
        self.env = {n: merge(*(s[0].get(n, Value()) for s in states)) for n in names}
        names = set().union(*(s[1] for s in states))
        self.aliases = {}
        for n in names:
            vals = {s[1].get(n, n) for s in states}
            self.aliases[n] = vals.pop() if len(vals) == 1 else ""

    def visit_If(self, node):
        self.visit(node.test)
        self.branches([node.body, node.orelse])

    def visit_Match(self, node):
        self.visit(node.subject)
        for case in node.cases:
            if case.guard:
                self.visit(case.guard)
        self.branches([[]] + [case.body for case in node.cases])

    def visit_For(self, node):
        self.visit(node.iter)
        initial_env, initial_aliases = self.env.copy(), self.aliases.copy()
        self.bind(node.target, self.value(node.iter))
        for stmt in node.body:
            self.visit(stmt)
        self.env = {n: merge(initial_env.get(n, Value()), self.env.get(n, Value())) for n in initial_env.keys() | self.env.keys()}
        self.aliases = {n: a for n, a in initial_aliases.items() if self.aliases.get(n) == a}
        for stmt in node.orelse:
            self.visit(stmt)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        self.branches([[], node.body])
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Try(self, node):
        # Include state at each possible interruption point of the try body.
        initial = self.env.copy()
        snapshots = [initial]
        for stmt in node.body:
            self.visit(stmt)
            snapshots.append(self.env.copy())
        keys = set().union(*snapshots)
        self.env = {k: merge(*(s.get(k, Value()) for s in snapshots)) for k in keys}
        self.branches([node.orelse] + [handler.body for handler in node.handlers])
        for stmt in node.finalbody:
            self.visit(stmt)

    visit_TryStar = visit_Try

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self.bind(item.optional_vars, self.value(item.context_expr))
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With

    def visit_Call(self, node):
        self.generic_visit(node)
        name = self.name(node.func)
        tail = node.func.attr if isinstance(node.func, ast.Attribute) else name.rsplit(".", 1)[-1]
        kwargs = {k.arg: k.value for k in node.keywords if k.arg}
        def argument(index=0, *keys):
            return node.args[index] if len(node.args) > index else next((kwargs[k] for k in keys if k in kwargs), None)
        arg = argument(0, "query", "sql", "command", "args", "source", "object", "data", "stream", "url", "file", "filename", "path", "template")
        val = self.value(arg)
        def is_value(key, expected):
            v = self.value(kwargs[key]) if key in kwargs else Value()
            return v.known and v.literal is expected
        def emit(id, message, confidence=None, severity=None):
            self.emit(id, node, message, val, confidence, severity)

        if tail in {"execute", "executemany", "executescript", "raw"} and arg is not None and val.dynamic:
            emit("PY001", "A database-like API receives a dynamically built statement; parameter binding needs review.")
        shell_api = name in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
        if shell_api or (name.startswith("subprocess.") and is_value("shell", True)):
            emit("PY002", "A command is passed through a shell." + (" Input flow reaches this operation." if val.influenced else " Review command construction."),
                 severity="high" if val.dynamic else "medium")
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            emit("PY003", "Text is executed as Python code.")
        if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads", "marshal.load", "marshal.loads", "dill.load", "dill.loads", "joblib.load"}:
            emit("PY004", "A loader accepts serialized Python objects; input trust must be established.")
        if name in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all", "yaml.full_load", "yaml.full_load_all"}:
            loader = kwargs.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            if self.name(loader) not in {"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader"}:
                emit("PY005", "YAML is loaded without an explicitly safe loader.")
        if ((name.startswith(("requests.", "httpx.")) or tail in {"get", "post", "put", "patch", "delete", "request", "Client", "AsyncClient"}) and is_value("verify", False)):
            known_client = name.startswith(("requests.", "httpx."))
            emit("PY006", "Certificate verification is explicitly disabled." if known_client else "A client-like API receives verify=False; confirm this controls TLS verification.", "high" if known_client else "low")
        if name == "ssl._create_unverified_context":
            emit("PY006", "An unverified TLS context is constructed.", "high")
        if name in {"hashlib.md5", "hashlib.sha1"} and not is_value("usedforsecurity", False):
            emit("PY007", "A legacy hash is used without an explicit non-security annotation.", "medium")
        if name == "hashlib.new" and val.known and str(val.literal).lower() in {"md5", "sha1"} and not is_value("usedforsecurity", False):
            emit("PY007", "A legacy hash algorithm is selected.", "medium")
        if name == "tempfile.mktemp":
            emit("PY009", "A temporary name is generated without atomically opening the file.", "high")
        if tail in {"run", "run_simple"} and (is_value("debug", True) or is_value("use_debugger", True)):
            emit("PY010", "A server-like entry point enables its debugger.", "medium")
        if name in {"flask.render_template_string", "jinja2.Template", "jinja2.environment.Template"} and val.dynamic:
            emit("PY011", "Dynamically supplied text is compiled as template source.")
        if name in {"django.utils.safestring.mark_safe", "markupsafe.Markup", "flask.Markup"} and val.dynamic:
            emit("PY012", "A dynamic value is marked as trusted HTML.")
        url_arg = argument(1, "url") if name.startswith(("requests.", "httpx.")) and tail == "request" else argument(0, "url")
        url_val = self.value(url_arg)
        if name.startswith(("requests.", "httpx.", "urllib.request.")) and tail in {"get", "post", "put", "patch", "delete", "head", "request", "urlopen", "Request"} and url_val.influenced:
            self.emit("PY013", node, "Input contributes to an outbound request URL.", url_val)
        if name in {"open", "builtins.open", "io.open", "os.remove", "os.unlink", "shutil.rmtree", "pathlib.Path", "flask.send_file"} and val.influenced:
            emit("PY014", "Input contributes to a filesystem path; containment requires review.")
        if tail in {"extractall", "extract"} and not (isinstance(kwargs.get("filter"), ast.Constant) and kwargs["filter"].value == "data"):
            emit("PY015", "Archive-like extraction does not select the data filter explicitly.", "low")
        if name in {"jwt.decode", "jose.jwt.decode"}:
            opts = kwargs.get("options")
            disabled = False
            if isinstance(opts, ast.Dict):
                disabled = any(isinstance(k, ast.Constant) and k.value == "verify_signature" and self.value(v).known and self.value(v).literal is False for k, v in zip(opts.keys, opts.values))
            if disabled or is_value("verify", False):
                emit("PY016", "Token decoding disables signature verification.", "high")
        if name in {"flask.redirect", "django.shortcuts.redirect", "starlette.responses.RedirectResponse"} and val.influenced:
            emit("PY017", "Input contributes to a redirect destination.")


def analyze(source: str, collector: Collector, max_nodes: int = 100_000):
    tree = ast.parse(source)
    for count, _ in enumerate(ast.walk(tree), 1):
        if count > max_nodes:
            raise ValueError("Python syntax tree exceeds the configured node limit")
    Analyzer(collector).visit(tree)
    return tree
