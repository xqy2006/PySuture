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

def __pysuture_decimal_argument(argument, prefix, maximum):
    if not argument.startswith(prefix):
        return False
    value = argument[len(prefix):]
    if not value or not value.isascii() or not value.isdecimal():
        return False
    if len(value) > 1 and value[0] == "0":
        return False
    return len(value) < len(maximum) or (len(value) == len(maximum) and value <= maximum)

if (
    len(__pysuture_multiprocessing_sys.argv) == 4
    and __pysuture_multiprocessing_sys.argv[1] == "--multiprocessing-fork"
    and __pysuture_decimal_argument(
        __pysuture_multiprocessing_sys.argv[2], "parent_pid=", "4294967295"
    )
    and __pysuture_decimal_argument(
        __pysuture_multiprocessing_sys.argv[3], "pipe_handle=", "18446744073709551615"
    )
):
    __pysuture_freeze_support()
"""
    ).body


def _target_names(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.List, ast.Tuple)):
        return {name for item in target.elts for name in _target_names(item)}
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return set()


def _statement_bound_names(statement: ast.stmt) -> set[str]:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {statement.name}
    if isinstance(statement, ast.Import):
        return {alias.asname or alias.name.partition(".")[0] for alias in statement.names}
    if isinstance(statement, ast.ImportFrom):
        return {alias.asname or alias.name for alias in statement.names if alias.name != "*"}
    if isinstance(statement, ast.Assign):
        return {name for target in statement.targets for name in _target_names(target)}
    if isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        return _target_names(statement.target)
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        return _target_names(statement.target)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return {
            name
            for item in statement.items
            if item.optional_vars is not None
            for name in _target_names(item.optional_vars)
        }
    if isinstance(statement, ast.Delete):
        return {name for target in statement.targets for name in _target_names(target)}
    return set()


def _update_freeze_support_bindings(
    statement: ast.stmt,
    direct_names: set[str],
    module_names: set[str],
) -> None:
    bound_names = _statement_bound_names(statement)
    direct_names.difference_update(bound_names)
    module_names.difference_update(bound_names)
    if isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module == "multiprocessing":
        direct_names.update(
            alias.asname or alias.name
            for alias in statement.names
            if alias.name == "freeze_support"
        )
    elif isinstance(statement, ast.Import):
        module_names.update(
            alias.asname or "multiprocessing"
            for alias in statement.names
            if alias.name == "multiprocessing"
        )


def _freeze_support_bindings(statements: list[ast.stmt]) -> tuple[set[str], set[str]]:
    direct_names: set[str] = set()
    module_names: set[str] = set()
    for statement in statements:
        _update_freeze_support_bindings(statement, direct_names, module_names)
    return direct_names, module_names


def _is_bound_freeze_support_call(
    call: ast.Call,
    direct_names: set[str],
    module_names: set[str],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in direct_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "freeze_support"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in module_names
    )


def _remove_canonical_freeze_support_calls(
    body: list[ast.stmt],
    direct_names: set[str],
    module_names: set[str],
) -> None:
    # The generated C launcher dispatches real child signatures before importing
    # the application. Leaving a canonical call here would let the stdlib parser
    # consume malformed lookalikes that must instead remain application argv.
    retained: list[ast.stmt] = []
    for statement in body:
        call = _no_argument_call(statement)
        if call is not None and _is_bound_freeze_support_call(call, direct_names, module_names):
            continue
        retained.append(statement)
        _update_freeze_support_bindings(statement, direct_names, module_names)
    body[:] = retained


def _has_strict_freeze_support_prelude(body: list[ast.stmt]) -> bool:
    strict = _strict_freeze_support_prelude()
    return len(body) >= len(strict) and all(
        ast.dump(actual, include_attributes=False) == ast.dump(expected, include_attributes=False)
        for actual, expected in zip(body, strict)
    )


def _ensure_freeze_support_prelude(
    guard: ast.If,
    *,
    direct_names: set[str] | None = None,
    module_names: set[str] | None = None,
) -> None:
    direct_bindings = set(direct_names or ())
    module_bindings = set(module_names or ())
    _remove_canonical_freeze_support_calls(guard.body, direct_bindings, module_bindings)
    if _has_strict_freeze_support_prelude(guard.body):
        return
    guard.body[0:0] = _strict_freeze_support_prelude()


def _prepare_module_source(record: ModuleRecord, destination: Path, *, entry: bool) -> tuple[Path, bool]:
    try:
        tree = ast.parse(record.path.read_text(encoding="utf-8"), filename=str(record.path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise BuildError(f"could not parse {record.path}: {exc}") from exc
    guard_found = False
    if entry:
        for index, statement in enumerate(tree.body):
            if isinstance(statement, ast.If) and _is_main_guard(statement.test):
                guard_found = True
                direct_names, module_names = _freeze_support_bindings(tree.body[:index])
                _ensure_freeze_support_prelude(
                    statement,
                    direct_names=direct_names,
                    module_names=module_names,
                )
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
