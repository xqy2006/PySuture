from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .constants import DEFAULT_INDEX_URL, DEFAULT_PYTHON_SERIES, SUPPORTED_PYTHON_SERIES
from .errors import ConfigurationError


WINDOWS_RESERVED_FILENAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
WINDOWS_FORBIDDEN_FILENAME_CHARACTERS = frozenset('<>:"/\\|?*')
KNOWN_CONFIG_FIELDS = {
    "entry",
    "python",
    "mode",
    "output",
    "include-modules",
    "include-packages",
    "data",
    "packages",
    "source-roots",
    "index-url",
    "secret-policy",
}


@dataclass(frozen=True)
class DataMapping:
    source: str
    target: str


@dataclass(frozen=True)
class ProjectConfig:
    root: Path
    entry: str
    python: str = DEFAULT_PYTHON_SERIES
    mode: str = "console"
    output: str = "application"
    include_modules: tuple[str, ...] = ()
    include_packages: tuple[str, ...] = ()
    data: tuple[DataMapping, ...] = ()
    packages: dict[str, str] = field(default_factory=dict)
    source_roots: tuple[str, ...] = (".",)
    index_url: str = DEFAULT_INDEX_URL
    secret_policy: str = "error"

    @property
    def entry_path(self) -> Path:
        entry_file = self.entry.split(":", 1)[0]
        return (self.root / entry_file).resolve()

    @property
    def entry_callable(self) -> str | None:
        _separator, _colon, callable_name = self.entry.partition(":")
        return callable_name or None


def _string_list(table: dict, name: str) -> tuple[str, ...]:
    value = table.get(name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigurationError(f"tool.pysuture.{name} must be an array of non-empty strings")
    return tuple(value)


def _module_name_list(table: dict, name: str) -> tuple[str, ...]:
    values = _string_list(table, name)
    invalid = [
        value
        for value in values
        if any(not part.isidentifier() for part in value.split("."))
    ]
    if invalid:
        raise ConfigurationError(
            f"tool.pysuture.{name} must contain fully qualified Python module names: "
            + ", ".join(repr(value) for value in invalid)
        )
    if len(set(values)) != len(values):
        raise ConfigurationError(f"tool.pysuture.{name} contains duplicate module names")
    return values


def validate_output_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigurationError("tool.pysuture.output must be a non-empty filename stem")
    if (
        value in {".", ".."}
        or value.endswith((" ", "."))
        or any(character in WINDOWS_FORBIDDEN_FILENAME_CHARACTERS or ord(character) < 32 for character in value)
        or value.split(".", 1)[0].casefold() in WINDOWS_RESERVED_FILENAMES
    ):
        raise ConfigurationError(
            "tool.pysuture.output must be a valid Windows filename stem without directories"
        )
    if value.casefold().endswith(".exe"):
        raise ConfigurationError("tool.pysuture.output is a filename stem and must not end in .exe")
    return value


def _qualified_entry(entry: object) -> tuple[str, str | None]:
    if not isinstance(entry, str) or not entry:
        raise ConfigurationError("tool.pysuture.entry must be a non-empty path")
    entry_file, separator, callable_name = entry.partition(":")
    if not entry_file:
        raise ConfigurationError("tool.pysuture.entry must contain a Python file path")
    if separator and (not callable_name or not callable_name.isidentifier()):
        raise ConfigurationError(
            "tool.pysuture.entry callable must be one Python identifier, for example app.py:main"
        )
    if Path(entry_file).suffix.casefold() != ".py":
        raise ConfigurationError("tool.pysuture.entry must refer to a .py file")
    return entry_file, callable_name or None


def _project_path(root: Path, value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or path.drive or path.root:
        raise ConfigurationError(f"{label} must be relative to the project root")
    resolved = (root / path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ConfigurationError(f"{label} escapes the project root: {value!r}")
    return resolved


def _read_toml(path: Path) -> tuple[str, dict]:
    try:
        text = path.read_text(encoding="utf-8")
        payload = tomllib.loads(text)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"could not read valid UTF-8 TOML from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError(f"{path} must contain a TOML document")
    return text, payload


def _toml_string(value: str) -> str:
    # TOML basic strings accept JSON's escapes for quotes, backslashes,
    # control characters, and Unicode code points.
    return json.dumps(value, ensure_ascii=False)


def load_project_config(root: Path) -> ProjectConfig:
    root = root.resolve()
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        raise ConfigurationError(f"pyproject.toml not found under {root}; run 'pysuture init'")
    _text, payload = _read_toml(pyproject)
    tool = payload.get("tool")
    if tool is not None and not isinstance(tool, dict):
        raise ConfigurationError("pyproject.toml tool value is not a table")
    table = (tool or {}).get("pysuture")
    if not isinstance(table, dict):
        raise ConfigurationError("pyproject.toml does not contain [tool.pysuture]; run 'pysuture init'")
    unknown_fields = sorted(set(table) - KNOWN_CONFIG_FIELDS)
    if unknown_fields:
        raise ConfigurationError(
            "unknown tool.pysuture configuration field(s): " + ", ".join(unknown_fields)
        )
    entry = table.get("entry")
    entry_file, _entry_callable = _qualified_entry(entry)
    python = str(table.get("python", DEFAULT_PYTHON_SERIES))
    if python not in SUPPORTED_PYTHON_SERIES:
        raise ConfigurationError(
            f"tool.pysuture.python must be one of {', '.join(SUPPORTED_PYTHON_SERIES)}"
        )
    mode = table.get("mode", "console")
    if mode not in {"console", "windowed"}:
        raise ConfigurationError("tool.pysuture.mode must be 'console' or 'windowed'")
    output = validate_output_name(table.get("output", Path(entry_file).stem))
    packages = table.get("packages", {})
    if not isinstance(packages, dict) or not all(
        isinstance(name, str) and bool(name) and isinstance(specifier, str)
        for name, specifier in packages.items()
    ):
        raise ConfigurationError("tool.pysuture.packages must be a string-to-string table")
    data_items = table.get("data", [])
    if not isinstance(data_items, list):
        raise ConfigurationError("tool.pysuture.data must be an array of inline tables")
    data: list[DataMapping] = []
    for index, item in enumerate(data_items, start=1):
        if (
            not isinstance(item, dict)
            or set(item) != {"source", "target"}
            or not isinstance(item.get("source"), str)
            or not item["source"]
            or not isinstance(item.get("target"), str)
            or not item["target"]
        ):
            raise ConfigurationError(
                f"tool.pysuture.data item #{index} requires non-empty string source and target"
            )
        data.append(DataMapping(item["source"], item["target"]))
    source_roots = _string_list(table, "source-roots") or (".",)
    resolved_source_roots: list[Path] = []
    for index, source_root in enumerate(source_roots, start=1):
        resolved = _project_path(root, source_root, f"tool.pysuture.source-roots item #{index}")
        if not resolved.is_dir():
            raise ConfigurationError(f"tool.pysuture source root does not exist: {resolved}")
        if resolved in resolved_source_roots:
            raise ConfigurationError("tool.pysuture.source-roots contains duplicate paths")
        resolved_source_roots.append(resolved)
    index_url = table.get("index-url", DEFAULT_INDEX_URL)
    if not isinstance(index_url, str) or not index_url:
        raise ConfigurationError("tool.pysuture.index-url must be a non-empty URL or path")
    secret_policy = table.get("secret-policy", "error")
    if secret_policy not in {"error", "warn", "allow"}:
        raise ConfigurationError("tool.pysuture.secret-policy must be error, warn, or allow")
    config = ProjectConfig(
        root=root,
        entry=entry,
        python=python,
        mode=mode,
        output=output,
        include_modules=_module_name_list(table, "include-modules"),
        include_packages=_module_name_list(table, "include-packages"),
        data=tuple(data),
        packages=dict(packages),
        source_roots=source_roots,
        index_url=index_url,
        secret_policy=secret_policy,
    )
    entry_path = _project_path(root, entry_file, "tool.pysuture.entry")
    if not entry_path.is_file():
        raise ConfigurationError(f"entry file does not exist: {config.entry_path}")
    if not any(entry_path == source_root or source_root in entry_path.parents for source_root in resolved_source_roots):
        raise ConfigurationError("tool.pysuture.entry is not contained by any configured source root")
    return config


def initialize_project(root: Path, entry: str, python: str, mode: str, output: str | None) -> Path:
    root = root.resolve()
    if python not in SUPPORTED_PYTHON_SERIES:
        raise ConfigurationError(f"unsupported Python series {python!r}")
    if mode not in {"console", "windowed"}:
        raise ConfigurationError("mode must be console or windowed")
    entry_file, callable_name = _qualified_entry(entry)
    entry_path = _project_path(root, entry_file, "tool.pysuture.entry")
    if not entry_path.is_file():
        raise ConfigurationError(f"entry file does not exist: {entry_path}")
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        existing, payload = _read_toml(pyproject)
        tool = payload.get("tool")
        if tool is not None and not isinstance(tool, dict):
            raise ConfigurationError("pyproject.toml tool value is not a table")
        if isinstance(tool, dict) and "pysuture" in tool:
            raise ConfigurationError("pyproject.toml already contains tool.pysuture")
    else:
        existing = ""
    output_name = validate_output_name(entry_path.stem if output is None else output)
    canonical_entry = entry_path.relative_to(root).as_posix()
    if callable_name:
        canonical_entry += f":{callable_name}"
    block = (
        "[tool.pysuture]\n"
        f"entry = {_toml_string(canonical_entry)}\n"
        f"python = {_toml_string(python)}\n"
        f"mode = {_toml_string(mode)}\n"
        f"output = {_toml_string(output_name)}\n"
        "include-modules = []\n"
        "include-packages = []\n"
        "data = []\n"
        "secret-policy = \"error\"\n\n"
        "[tool.pysuture.packages]\n"
    )
    separator = "" if not existing or existing.endswith("\n\n") else ("\n" if existing.endswith("\n") else "\n\n")
    try:
        pyproject.write_text(existing + separator + block, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ConfigurationError(f"could not update {pyproject}: {exc}") from exc
    return pyproject
