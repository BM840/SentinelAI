"""
SentinelAI - Agent C: Basic Data Flow Analyzer
Tracks user-controlled input to sensitive sink operations (DB queries, eval, etc.)
"""
import ast
from typing import List, Set, Dict
from core.models import Finding, Severity
from core.ingestion import FileAnalysis


# Sources of user-controlled data
USER_INPUT_SOURCES = {
    "request.form.get", "request.args.get", "request.json",
    "request.data", "request.values.get", "request.get_json",
    "request.headers.get", "request.cookies.get",
    "Body", "Query", "Form",  # FastAPI
}

# Sensitive sinks (operations that should not receive unsanitized input)
SENSITIVE_SINKS = {
    "execute", "cursor.execute", "eval", "exec",
    "os.system", "subprocess.call", "subprocess.run",
    "open", "pickle.loads",
}


class DataFlowAnalyzer:
    """Agent C: Tracks taint from user inputs to dangerous sinks."""

    AGENT_NAME = "Agent C - Data Flow Analyzer"

    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        findings = []
        for analysis in analyses:
            for func in analysis.functions:
                findings.extend(self._analyze_function(func, analysis))
        return findings

    def _analyze_function(self, func, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        try:
            func_tree = ast.parse(func.source)
        except SyntaxError:
            return findings

        tainted_vars: Set[str] = set()

        # Walk AST to find tainted assignments and track to sinks
        for node in ast.walk(func_tree):
            # Find assignments from user input
            if isinstance(node, ast.Assign):
                if self._is_tainted_source(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars.add(target.id)

            # Find calls to sensitive sinks
            if isinstance(node, ast.Call):
                sink_name = self._get_call_name(node)
                if sink_name and any(s in sink_name for s in SENSITIVE_SINKS):
                    # Check if any argument is tainted
                    tainted_args = self._get_tainted_args(node, tainted_vars)
                    if tainted_args:
                        lineno = func.lineno + (node.lineno - 1)
                        findings.append(Finding(
                            agent=self.AGENT_NAME,
                            title=f"Unsanitized User Input Reaches {sink_name}()",
                            description=(
                                f"In function '{func.name}', user-controlled variable(s) "
                                f"{tainted_args} flow directly into '{sink_name}()' "
                                f"without apparent sanitization."
                            ),
                            severity=Severity.HIGH if sink_name != "open" else Severity.MEDIUM,
                            filepath=analysis.filepath,
                            lineno=lineno,
                            code_snippet=ast.unparse(node) if hasattr(ast, 'unparse') else None,
                            recommendation=(
                                "Sanitize and validate all user-supplied data before passing to database "
                                "queries, OS commands, or eval-like functions. Use parameterized queries for SQL."
                            ),
                            cwe_id="CWE-20"
                        ))

        return findings

    def _is_tainted_source(self, node: ast.AST) -> bool:
        """Check if an expression is a user-input source."""
        if isinstance(node, ast.Call):
            name = self._get_call_name(node)
            if name and any(src in name for src in USER_INPUT_SOURCES):
                return True
        # Check for request.json direct attribute access
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                return True
        return False

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function call name as a string."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            return ".".join(reversed(parts))
        return ""

    def _get_tainted_args(self, call_node: ast.Call, tainted_vars: Set[str]) -> List[str]:
        """Return list of tainted variable names used in a call's arguments."""
        tainted = []
        for arg in call_node.args:
            if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                tainted.append(arg.id)
            # Check f-strings and BinOps for tainted vars
            elif isinstance(arg, ast.JoinedStr):
                for value in ast.walk(arg):
                    if isinstance(value, ast.Name) and value.id in tainted_vars:
                        tainted.append(value.id)
            elif isinstance(arg, ast.BinOp):
                for value in ast.walk(arg):
                    if isinstance(value, ast.Name) and value.id in tainted_vars:
                        tainted.append(value.id)
        return list(set(tainted))
