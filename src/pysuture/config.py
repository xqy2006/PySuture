from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .constants import DEFAULT_INDEX_URL, DEFAULT_PYTHON_SERIES, SUPPORTED_PYTHON_SERIES
from .errors import ConfigurationError


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


def load_project_config(root: Path) -> ProjectConfig:
    root = root.resolve()
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        raise ConfigurationError(f"pyproject.toml not found under {root}; run 'pysuture init'")
    payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    table = payload.get("tool", {}).get("pysuture")
    if not isinstance(table, dict):
        raise ConfigurationError("pyproject.toml does not contain [tool.pysuture]; run 'pysuture init'")
    entry = table.get("entry")
    if not isinstance(entry, str) or not entry:
        raise ConfigurationError("tool.pysuture.entry must be a non-empty path")
    python = str(table.get("python", DEFAULT_PYTHON_SERIES))
    if python not in SUPPORTED_PYTHON_SERIES:
        raise ConfigurationError(
            f"tool.pysuture.python must be one of {', '.join(SUPPORTED_PYTHON_SERIES)}"
        )
    mode = table.get("mode", "console")
    if mode not in {"console", "windowed"}:
        raise ConfigurationError("tool.pysuture.mode must be 'console' or 'windowed'")
    output = table.get("output", Path(entry.split(":", 1)[0]).stem)
    if not isinstance(output, str) or not output or Path(output).name != output:
        raise ConfigurationError("tool.pysuture.output must be a filename stem without directories")
    packages = table.get("packages", {})
    if not isinstance(packages, dict) or not all(
        isinstance(name, str) and isinstance(specifier, str)
        for name, specifier in packages.items()
    ):
        raise ConfigurationError("tool.pysuture.packages must be a string-to-string table")
    data_items = table.get("data", [])
    if not isinstance(data_items, list):
        raise ConfigurationError("tool.pysuture.data must be an array of inline tables")
    data: list[DataMapping] = []
    for index, item in enumerate(data_items, start=1):
        if not isinstance(item, dict) or not isinstance(item.get("source"), str) or not isinstance(item.get("target"), str):
            raise ConfigurationError(f"tool.pysuture.data item #{index} requires string source and target")
        data.append(DataMapping(item["source"], item["target"]))
    source_roots = _string_list(table, "source-roots") or (".",)
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
        include_modules=_string_list(table, "include-modules"),
        include_packages=_string_list(table, "include-packages"),
        data=tuple(data),
        packages=dict(packages),
        source_roots=source_roots,
        index_url=index_url,
        secret_policy=secret_policy,
    )
    if not config.entry_path.is_file():
        raise ConfigurationError(f"entry file does not exist: {config.entry_path}")
    return config


def initialize_project(root: Path, entry: str, python: str, mode: str, output: str | None) -> Path:
    root = root.resolve()
    if python not in SUPPORTED_PYTHON_SERIES:
        raise ConfigurationError(f"unsupported Python series {python!r}")
    if mode not in {"console", "windowed"}:
        raise ConfigurationError("mode must be console or windowed")
    entry_path = (root / entry.split(":", 1)[0]).resolve()
    if not entry_path.is_file():
        raise ConfigurationError(f"entry file does not exist: {entry_path}")
    pyproject = root / "pyproject.toml"
    existing = pyproject.read_text(encoding="utf-8") if pyproject.exists() else ""
    if "[tool.pysuture]" in existing:
        raise ConfigurationError("pyproject.toml already contains [tool.pysuture]")
    output_name = output or entry_path.stem
    block = (
        "[tool.pysuture]\n"
        f'entry = "{entry.replace(chr(92), "/")}"\n'
        f'python = "{python}"\n'
        f'mode = "{mode}"\n'
        f'output = "{output_name}"\n'
        "include-modules = []\n"
        "include-packages = []\n"
        "data = []\n"
        "secret-policy = \"error\"\n\n"
        "[tool.pysuture.packages]\n"
    )
    separator = "" if not existing or existing.endswith("\n\n") else ("\n" if existing.endswith("\n") else "\n\n")
    pyproject.write_text(existing + separator + block, encoding="utf-8", newline="\n")
    return pyproject
