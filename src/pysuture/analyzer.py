from __future__ import annotations

import ast
import hashlib
import importlib.machinery
import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .config import ProjectConfig
from .errors import AnalysisError


IGNORED_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pysuture",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}


@dataclass(frozen=True)
class ModuleRecord:
    name: str
    path: Path
    is_package: bool
    source_root: Path
    private_dependency: bool = False

    @property
    def source_sha256(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class DynamicImportGap:
    module: str
    path: str
    line: int
    expression: str


@dataclass
class AnalysisReport:
    entry_module: str
    modules: dict[str, ModuleRecord]
    reachable_modules: tuple[str, ...]
    namespace_packages: tuple[str, ...]
    import_graph: dict[str, tuple[str, ...]]
    external_imports: tuple[str, ...]
    dynamic_imports: tuple[str, ...]
    dynamic_gaps: tuple[DynamicImportGap, ...]
    unsupported_native_extensions: tuple[str, ...] = ()
    selected_packs: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "entry_module": self.entry_module,
            "modules": [
                {
                    "name": module.name,
                    "path": str(module.path),
                    "is_package": module.is_package,
                    "private_dependency": module.private_dependency,
                    "sha256": module.source_sha256,
                }
                for module in sorted(self.modules.values(), key=lambda item: item.name)
            ],
            "reachable_modules": list(self.reachable_modules),
            "namespace_packages": list(self.namespace_packages),
            "import_graph": {name: list(values) for name, values in sorted(self.import_graph.items())},
            "external_imports": list(self.external_imports),
            "dynamic_imports": list(self.dynamic_imports),
            "dynamic_gaps": [gap.__dict__ for gap in self.dynamic_gaps],
            "unsupported_native_extensions": list(self.unsupported_native_extensions),
            "selected_packs": dict(sorted(self.selected_packs.items())),
        }


def _module_name(source_root: Path, path: Path) -> tuple[str, bool] | None:
    relative = path.relative_to(source_root)
    if relative.name == "__init__.py":
        parts = relative.parent.parts
        is_package = True
    else:
        parts = (*relative.parent.parts, relative.stem)
        is_package = False
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return ".".join(parts), is_package


def _discover_under_root(source_root: Path, *, private_dependency: bool = False) -> dict[str, ModuleRecord]:
    modules: dict[str, ModuleRecord] = {}
    if not source_root.is_dir():
        raise AnalysisError(f"source root does not exist: {source_root}")
    for path in sorted(source_root.rglob("*.py")):
        relative = path.relative_to(source_root)
        if any(part in IGNORED_DIRECTORY_NAMES or part.startswith(".") for part in relative.parts[:-1]):
            continue
        resolved = _module_name(source_root, path)
        if resolved is None:
            continue
        name, is_package = resolved
        existing = modules.get(name)
        if existing is not None and existing.path != path:
            raise AnalysisError(f"module {name!r} is provided by both {existing.path} and {path}")
        modules[name] = ModuleRecord(name, path.resolve(), is_package, source_root.resolve(), private_dependency)
    return modules


def _private_package_modules(package_name: str) -> dict[str, ModuleRecord]:
    spec = importlib.util.find_spec(package_name)
    if spec is None:
        raise AnalysisError(f"explicit private package {package_name!r} is not installed")
    modules: dict[str, ModuleRecord] = {}
    if spec.submodule_search_locations:
        for location in spec.submodule_search_locations:
            root = Path(location).resolve()
            native_files = sorted(
                path for path in root.rglob("*")
                if path.is_file() and path.suffix.casefold() == ".pyd"
            )
            if native_files:
                preview = ", ".join(str(path) for path in native_files[:5])
                raise AnalysisError(
                    f"explicit private package {package_name!r} contains native extensions ({preview}); "
                    "a StaticPython pack is required"
                )
            for path in sorted(root.rglob("*.py")):
                relative = path.relative_to(root)
                if any(
                    part in IGNORED_DIRECTORY_NAMES or part.startswith(".")
                    for part in relative.parts[:-1]
                ):
                    continue
                if relative.name == "__init__.py":
                    suffix = relative.parent.parts
                    is_package = True
                else:
                    suffix = (*relative.parent.parts, relative.stem)
                    is_package = False
                if not all(part.isidentifier() for part in suffix):
                    continue
                name = ".".join((package_name, *suffix)) if suffix else package_name
                modules[name] = ModuleRecord(name, path.resolve(), is_package, root, True)
    elif spec.origin and spec.origin.endswith(".py"):
        path = Path(spec.origin).resolve()
        modules[package_name] = ModuleRecord(package_name, path, False, path.parent, True)
    else:
        raise AnalysisError(
            f"explicit private package {package_name!r} is not pure Python; a StaticPython pack is required"
        )
    if not modules:
        raise AnalysisError(f"no Python modules found for explicit private package {package_name!r}")
    return modules


def discover_modules(config: ProjectConfig) -> dict[str, ModuleRecord]:
    modules: dict[str, ModuleRecord] = {}
    for relative_root in config.source_roots:
        source_root = (config.root / relative_root).resolve()
        for name, record in _discover_under_root(source_root).items():
            existing = modules.get(name)
            if existing is not None and existing.path != record.path:
                raise AnalysisError(f"module {name!r} is ambiguous between {existing.path} and {record.path}")
            modules[name] = record
    for package_name in config.include_packages:
        for name, record in _private_package_modules(package_name).items():
            modules.setdefault(name, record)
    return modules


def _entry_module(config: ProjectConfig, modules: dict[str, ModuleRecord]) -> str:
    entry_path = config.entry_path
    matches = [name for name, module in modules.items() if module.path == entry_path]
    if len(matches) != 1:
        raise AnalysisError(
            f"entry file {entry_path} did not resolve to exactly one importable module; "
            "check tool.pysuture.source-roots"
        )
    return matches[0]


def _resolve_relative(current: ModuleRecord, module: str | None, level: int) -> str:
    package_parts = current.name.split(".") if current.is_package else current.name.split(".")[:-1]
    trim = max(level - 1, 0)
    if trim > len(package_parts):
        return module or ""
    base = package_parts[: len(package_parts) - trim]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _expression_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _imports_for_module(record: ModuleRecord) -> tuple[set[str], set[str], list[DynamicImportGap]]:
    try:
        source = record.path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(record.path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise AnalysisError(f"could not parse {record.path}: {exc}") from exc
    imports: set[str] = set()
    dynamic: set[str] = set()
    gaps: list[DynamicImportGap] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_relative(record, node.module, node.level) if node.level else (node.module or "")
            if base:
                imports.add(base)
                imports.update(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
        elif isinstance(node, ast.Call):
            is_import_module = (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
                and node.func.attr == "import_module"
            )
            is_dunder_import = isinstance(node.func, ast.Name) and node.func.id == "__import__"
            if not (is_import_module or is_dunder_import):
                continue
            argument = node.args[0] if node.args else None
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                dynamic.add(argument.value)
            else:
                gaps.append(
                    DynamicImportGap(
                        module=record.name,
                        path=str(record.path),
                        line=getattr(node, "lineno", 0),
                        expression=_expression_text(argument) if argument is not None else "<missing>",
                    )
                )
    return imports, dynamic, gaps


def _local_targets(import_name: str, modules: dict[str, ModuleRecord]) -> set[str]:
    targets: set[str] = set()
    parts = import_name.split(".")
    for length in range(1, len(parts) + 1):
        candidate = ".".join(parts[:length])
        if candidate in modules:
            targets.add(candidate)
    return targets


def _namespace_packages(modules: dict[str, ModuleRecord]) -> tuple[str, ...]:
    namespaces: set[str] = set()
    for name in modules:
        parts = name.split(".")
        for length in range(1, len(parts)):
            parent = ".".join(parts[:length])
            if parent not in modules:
                namespaces.add(parent)
    return tuple(sorted(namespaces, key=lambda value: (value.count("."), value)))


def _native_extension_without_pack(top_level: str) -> bool:
    try:
        spec = importlib.util.find_spec(top_level)
    except (ImportError, AttributeError, ValueError):
        return False
    if spec is None or not spec.origin:
        return False
    suffix = Path(spec.origin).suffix.casefold()
    return suffix in {value.casefold() for value in importlib.machinery.EXTENSION_SUFFIXES} or suffix == ".pyd"


def analyze_project(config: ProjectConfig) -> AnalysisReport:
    modules = discover_modules(config)
    entry = _entry_module(config, modules)
    raw_graph: dict[str, set[str]] = {}
    dynamic_by_module: dict[str, set[str]] = {}
    gaps: list[DynamicImportGap] = []
    external_by_module: dict[str, set[str]] = {}
    for name, record in modules.items():
        imports, dynamic, module_gaps = _imports_for_module(record)
        dynamic_by_module[name] = dynamic
        gaps.extend(module_gaps)
        external_by_module[name] = set()
        raw_graph[name] = set()
        for imported in imports | dynamic:
            targets = _local_targets(imported, modules)
            if targets:
                raw_graph[name].update(targets)
            else:
                external_by_module[name].add(imported.split(".", 1)[0])

    reachable: set[str] = set()
    pending = [entry]
    for explicit in config.include_modules:
        pending.extend(_local_targets(explicit, modules))
    for package in config.include_packages:
        pending.extend(name for name in modules if name == package or name.startswith(package + "."))
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(raw_graph.get(name, ()))

    reachable_modules = {name: module for name, module in modules.items() if name in reachable}
    external = set().union(*(external_by_module.get(name, set()) for name in reachable))
    external.update(
        name.split(".", 1)[0]
        for name in config.include_modules
        if not _local_targets(name, modules)
    )
    dynamic_imports = set(config.include_modules).union(
        *(dynamic_by_module.get(name, set()) for name in reachable)
    )
    gaps = [gap for gap in gaps if gap.module in reachable]
    reachable_graph = {
        name: tuple(sorted(target for target in raw_graph.get(name, ()) if target in reachable))
        for name in sorted(reachable)
    }
    unsupported = tuple(sorted(name for name in external if _native_extension_without_pack(name)))
    return AnalysisReport(
        entry_module=entry,
        modules=reachable_modules,
        reachable_modules=tuple(sorted(reachable)),
        namespace_packages=_namespace_packages(reachable_modules),
        import_graph=reachable_graph,
        external_imports=tuple(sorted(external)),
        dynamic_imports=tuple(sorted(dynamic_imports)),
        dynamic_gaps=tuple(sorted(gaps, key=lambda item: (item.path, item.line))),
        unsupported_native_extensions=unsupported,
    )
