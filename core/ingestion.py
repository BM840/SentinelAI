"""
SentinelAI - Code Ingestion Layer
Parses Python files, extracts AST nodes, and identifies key modules.
"""
import ast
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class FunctionInfo:
    name: str
    lineno: int
    source: str
    args: List[str]
    is_auth_related: bool = False
    is_db_related: bool = False
    is_route: bool = False


@dataclass
class FileAnalysis:
    filepath: str
    source_code: str
    functions: List[FunctionInfo] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    global_vars: Dict[str, str] = field(default_factory=dict)
    ast_tree: Optional[ast.AST] = None


AUTH_KEYWORDS = {"login", "auth", "authenticate", "password", "token", "session",
                 "jwt", "oauth", "verify", "credential", "permission", "role", "privilege"}

DB_KEYWORDS = {"query", "execute", "cursor", "select", "insert", "update", "delete",
               "database", "db", "sql", "fetch", "commit"}


class CodeIngestionLayer:
    """Parses Python files and extracts structured information for downstream agents."""

    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.analyses: List[FileAnalysis] = []

    def ingest(self) -> List[FileAnalysis]:
        """Entry point: ingest all Python files from the target path."""
        if self.target_path.is_file():
            py_files = [self.target_path] if self.target_path.suffix == ".py" else []
        else:
            py_files = list(self.target_path.rglob("*.py"))

        for filepath in py_files:
            analysis = self._analyze_file(filepath)
            if analysis:
                self.analyses.append(analysis)

        print(f"[Ingestion] Analyzed {len(self.analyses)} Python file(s).")
        return self.analyses

    def _analyze_file(self, filepath: Path) -> Optional[FileAnalysis]:
        try:
            source = filepath.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[Ingestion] Could not read {filepath}: {e}")
            return None

        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            print(f"[Ingestion] Syntax error in {filepath}: {e}")
            return None

        analysis = FileAnalysis(
            filepath=str(filepath),
            source_code=source,
            ast_tree=tree
        )

        self._extract_imports(tree, analysis)
        self._extract_global_vars(tree, analysis, source)
        self._extract_functions(tree, analysis, source)

        return analysis

    def _extract_imports(self, tree: ast.AST, analysis: FileAnalysis):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    analysis.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    analysis.imports.append(f"{module}.{alias.name}")

    def _extract_global_vars(self, tree: ast.AST, analysis: FileAnalysis, source: str):
        lines = source.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Only top-level assignments
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        try:
                            value_src = ast.unparse(node.value)
                        except Exception:
                            value_src = "<unknown>"
                        analysis.global_vars[target.id] = value_src

    def _extract_functions(self, tree: ast.AST, analysis: FileAnalysis, source: str):
        lines = source.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_lines = lines[node.lineno - 1: node.end_lineno]
                func_source = "\n".join(func_lines)

                args = [arg.arg for arg in node.args.args]
                name_lower = node.name.lower()

                is_auth = any(kw in name_lower for kw in AUTH_KEYWORDS)
                is_db = any(kw in name_lower for kw in DB_KEYWORDS)

                # Also check body for auth/db keyword context
                if not is_auth:
                    is_auth = any(kw in func_source.lower() for kw in AUTH_KEYWORDS)
                if not is_db:
                    is_db = any(kw in func_source.lower() for kw in DB_KEYWORDS)

                # Check for Flask/FastAPI route decorators
                is_route = any(
                    isinstance(d, ast.Call) and
                    isinstance(d.func, ast.Attribute) and
                    d.func.attr in ("route", "get", "post", "put", "delete", "patch")
                    for d in node.decorator_list
                )

                func_info = FunctionInfo(
                    name=node.name,
                    lineno=node.lineno,
                    source=func_source,
                    args=args,
                    is_auth_related=is_auth,
                    is_db_related=is_db,
                    is_route=is_route
                )
                analysis.functions.append(func_info)
