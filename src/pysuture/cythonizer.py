from __future__ import annotations

import ast
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .analyzer import AnalysisReport, ModuleRecord
from .errors import BuildError


INIT_SYMBOL_RE = re.compile(r"\b(?:PyMODINIT_FUNC|__Pyx_PyMODINIT_FUNC)\s+(PyInit_[A-Za-z0-9_]+)\s*\(void\)")
MAIN_FLAG_RE = re.compile(r"\bint\s+(__pyx_module_is_main_[A-Za-z0-9_]+)\s*=\s*0\s*;")


@dataclass(frozen=True)
class CythonUnit:
    module: ModuleRecord
    prepared_source: Path
    c_source: Path
    original_init_symbol: str
    init_symbol: str
    original_main_flag: str | None
    main_flag: str | None
    compile_definitions: tuple[str, ...]


def installed_cython_version() -> str:
    try:
        import Cython
    except ImportError as exc:
        raise BuildError("Cython is not installed; install PySuture with the 'build' extra") from exc
    return str(Cython.__version__)


def require_cython_version(expected: str) -> None:
    actual = installed_cython_version()
    if actual != expected:
        raise BuildError(
            f"pysuture.lock requires Cython {expected}, but {actual} is installed; "
            f"run '{sys.executable} -m pip install Cython=={expected}'"
        )


def _is_main_guard(test: ast.expr) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return False
    if len(test.comparators) != 1:
        return False
    left, right = test.left, test.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    ) or (
        isinstance(right, ast.Name)
        and right.id == "__name__"
        and isinstance(left, ast.Constant)
        and left.value == "__main__"
    )


def _insertion_index(body: list[ast.stmt]) -> int:
    index = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        index = 1
    while index < len(body) and isinstance(body[index], ast.ImportFrom) and body[index].module == "__future__":
        index += 1
    return index


def _no_argument_call(statement: ast.stmt) -> ast.Call | None:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return None
    call = statement.value
    if call.args or call.keywords:
        return None
    return call


def _strict_freeze_support_prelude() -> list[ast.stmt]:
    return ast.parse(
        """
import sys as __pysuture_multiprocessing_sys
from multiprocessing import freeze_support as __pysuture_freeze_support

def __pysuture_decimal_argument(argument, prefix):
    if not argument.startswith(prefix):
        return False
    value = argument[len(prefix):]
    if not value or not value.isascii() or not value.isdecimal():
        return False
    value = value.lstrip("0") or "0"
    return len(value) < 20 or (len(value) == 20 and value <= "18446744073709551615")

if (
    len(__pysuture_multiprocessing_sys.argv) == 4
    and __pysuture_multiprocessing_sys.argv[1] == "--multiprocessing-fork"
    and __pysuture_decimal_argument(__pysuture_multiprocessing_sys.argv[2], "parent_pid=")
    and __pysuture_decimal_argument(__pysuture_multiprocessing_sys.argv[3], "pipe_handle=")
):
    __pysuture_freeze_support()
"""
    ).body


def _has_freeze_support_prelude(body: list[ast.stmt]) -> bool:
    strict = _strict_freeze_support_prelude()
    if len(body) >= len(strict) and all(
        ast.dump(actual, include_attributes=False) == ast.dump(expected, include_attributes=False)
        for actual, expected in zip(body, strict)
    ):
        return True
    if len(body) < 2:
        return False
    first = body[0]
    call = _no_argument_call(body[1])
    if call is None:
        return False
    if isinstance(call.func, ast.Name) and isinstance(first, ast.ImportFrom):
        return (
            first.level == 0
            and first.module == "multiprocessing"
            and any(
                alias.name == "freeze_support" and (alias.asname or alias.name) == call.func.id
                for alias in first.names
            )
        )
    if isinstance(call.func, ast.Attribute) and isinstance(first, ast.Import):
        return (
            call.func.attr == "freeze_support"
            and isinstance(call.func.value, ast.Name)
            and any(
                alias.name == "multiprocessing"
                and (alias.asname or alias.name) == call.func.value.id
                for alias in first.names
            )
        )
    return False


def _ensure_freeze_support_prelude(guard: ast.If) -> None:
    if _has_freeze_support_prelude(guard.body):
        return
    guard.body[0:0] = _strict_freeze_support_prelude()


def _prepare_module_source(record: ModuleRecord, destination: Path, *, entry: bool) -> tuple[Path, bool]:
    try:
        tree = ast.parse(record.path.read_text(encoding="utf-8"), filename=str(record.path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise BuildError(f"could not parse {record.path}: {exc}") from exc
    guard_found = False
    if entry:
        for statement in tree.body:
            if isinstance(statement, ast.If) and _is_main_guard(statement.test):
                guard_found = True
                _ensure_freeze_support_prelude(statement)
                break
    if record.is_package:
        package_setup: list[ast.stmt] = [
            ast.Assign(
                targets=[ast.Name(id="__package__", ctx=ast.Store())],
                value=ast.Constant(value=record.name),
            ),
            ast.Assign(
                targets=[ast.Name(id="__path__", ctx=ast.Store())],
                value=ast.List(elts=[ast.Name(id="__name__", ctx=ast.Load())], ctx=ast.Load()),
            ),
        ]
        index = _insertion_index(tree.body)
        tree.body[index:index] = package_setup
    ast.fix_missing_locations(tree)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(ast.unparse(tree) + "\n", encoding="utf-8", newline="\n")
    return destination, guard_found


def cythonize_modules(report: AnalysisReport, build_dir: Path, expected_version: str) -> tuple[list[CythonUnit], list[str]]:
    require_cython_version(expected_version)
    prepared_dir = build_dir / "prepared"
    generated_dir = build_dir / "generated"
    warnings: list[str] = []
    units: list[CythonUnit] = []
    for name in report.reachable_modules:
        record = report.modules[name]
        digest = hashlib.sha256((name + "\0" + record.source_sha256).encode("utf-8")).hexdigest()[:20]
        safe_name = re.sub(r"[^0-9A-Za-z_]", "_", name)
        prepared = prepared_dir / f"{safe_name}_{digest}.py"
        prepared, guard_found = _prepare_module_source(record, prepared, entry=name == report.entry_module)
        if name == report.entry_module and not guard_found:
            warnings.append(
                "entry module has no canonical if __name__ == '__main__' guard; "
                "multiprocessing child dispatch is supported, but unguarded process creation can recurse"
            )
        generated = generated_dir / f"{safe_name}_{digest}.c"
        generated.parent.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable,
            "-m",
            "cython",
            "--3str",
            "--module-name",
            name,
            "--output-file",
            str(generated),
            str(prepared),
        ]
        result = subprocess.run(
            command,
            cwd=record.source_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode != 0 or not generated.is_file():
            raise BuildError(f"Cython failed for {name}:\n{result.stdout[-8000:]}")
        generated_text = generated.read_text(encoding="utf-8", errors="replace")
        init_matches = list(dict.fromkeys(INIT_SYMBOL_RE.findall(generated_text)))
        if len(init_matches) != 1:
            raise BuildError(f"could not identify one Cython init symbol for {name}: {init_matches}")
        main_matches = list(dict.fromkeys(MAIN_FLAG_RE.findall(generated_text)))
        original_init = init_matches[0]
        original_main = main_matches[0] if len(main_matches) == 1 else None
        unique_init = f"PyInit_pysuture_{digest}"
        unique_main = f"pysuture_module_is_main_{digest}" if original_main else None
        definitions = [f"{original_init}={unique_init}"]
        if original_main and unique_main:
            definitions.append(f"{original_main}={unique_main}")
        units.append(
            CythonUnit(
                module=record,
                prepared_source=prepared,
                c_source=generated,
                original_init_symbol=original_init,
                init_symbol=unique_init,
                original_main_flag=original_main,
                main_flag=unique_main,
                compile_definitions=tuple(definitions),
            )
        )
    return units, warnings
