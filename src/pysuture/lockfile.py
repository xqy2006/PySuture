from __future__ import annotations

import json
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .analyzer import AnalysisReport
from .config import ProjectConfig
from .constants import LOCK_SCHEMA_VERSION, SUPPORTED_PLATFORM
from .errors import LockError


def lock_path(root: Path) -> Path:
    return root.resolve() / "pysuture.lock"


def write_lock(root: Path, payload: dict) -> Path:
    path = lock_path(root)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def load_lock(root: Path) -> dict:
    path = lock_path(root)
    if not path.is_file():
        raise LockError("pysuture.lock does not exist; run 'pysuture lock'")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LockError(f"could not read {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != LOCK_SCHEMA_VERSION:
        raise LockError(f"unsupported pysuture.lock schema; expected {LOCK_SCHEMA_VERSION}")
    if payload.get("platform") != SUPPORTED_PLATFORM:
        raise LockError(f"lock targets {payload.get('platform')!r}, expected {SUPPORTED_PLATFORM}")
    for field in (
        "python_series",
        "cpython_version",
        "cpython_abi",
        "staticpython_commit",
        "runtime_abi",
        "index",
        "runtime",
        "packs",
        "cython_version",
        "toolchain",
        "project",
    ):
        if field not in payload:
            raise LockError(f"pysuture.lock is missing {field!r}")
    return payload


def validate_lock_for_project(lock: dict, report: AnalysisReport, *, frozen: bool) -> None:
    locked_project = lock.get("project", {})
    if locked_project.get("entry_module") != report.entry_module:
        raise LockError("entry module differs from pysuture.lock; run 'pysuture lock --update'")
    if not frozen:
        return
    locked_modules = {
        item.get("name"): item.get("sha256")
        for item in locked_project.get("modules", [])
        if isinstance(item, dict)
    }
    current_modules = {
        name: report.modules[name].source_sha256
        for name in report.reachable_modules
    }
    if locked_modules != current_modules:
        added = sorted(set(current_modules) - set(locked_modules))
        removed = sorted(set(locked_modules) - set(current_modules))
        changed = sorted(
            name for name in set(current_modules).intersection(locked_modules)
            if current_modules[name] != locked_modules[name]
        )
        details = []
        if added:
            details.append("added=" + ",".join(added))
        if removed:
            details.append("removed=" + ",".join(removed))
        if changed:
            details.append("changed=" + ",".join(changed))
        raise LockError(
            "--frozen-lock project sources differ from pysuture.lock ("
            + "; ".join(details)
            + ")"
        )


def validate_lock_for_configuration(lock: dict, config: ProjectConfig) -> None:
    locked_python = lock.get("python_series")
    if locked_python != config.python:
        raise LockError(
            f"pysuture.lock targets Python {locked_python}, but the project requests {config.python}; "
            "run 'pysuture lock --update'"
        )

    pack_records = lock.get("packs")
    if not isinstance(pack_records, list):
        raise LockError("pysuture.lock packs must be an array")

    locked_packs: dict[str, tuple[str, str]] = {}
    for record in pack_records:
        if not isinstance(record, dict):
            raise LockError("pysuture.lock contains an invalid pack record")
        name = record.get("name")
        version = record.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise LockError("pysuture.lock contains a pack without a valid name and version")
        normalized_name = name.casefold()
        if normalized_name in locked_packs:
            raise LockError(f"pysuture.lock contains duplicate pack records for {name!r}")
        locked_packs[normalized_name] = (name, version)

    for requested_name, raw_specifier in config.packages.items():
        locked = locked_packs.get(requested_name.casefold())
        if locked is None:
            raise LockError(
                f"pysuture.lock does not contain requested pack {requested_name!r}; "
                "run 'pysuture lock --update'"
            )
        locked_name, locked_version = locked
        try:
            constraint = SpecifierSet(raw_specifier)
            parsed_version = Version(locked_version)
        except InvalidSpecifier as exc:
            raise LockError(
                f"invalid version constraint for {requested_name}: {raw_specifier!r}"
            ) from exc
        except InvalidVersion as exc:
            raise LockError(
                f"pysuture.lock contains invalid version {locked_version!r} for pack {locked_name}"
            ) from exc
        if parsed_version not in constraint:
            rendered = raw_specifier or " (any version)"
            raise LockError(
                f"pysuture.lock pins {locked_name}=={locked_version}, which does not satisfy "
                f"the requested constraint {requested_name}{rendered}; run 'pysuture lock --update'"
            )


def iter_locked_assets(lock: dict):
    yield lock["runtime"]
    yield from lock.get("packs", [])


def validate_asset_records(lock: dict) -> None:
    seen: set[str] = set()
    for asset in iter_locked_assets(lock):
        if not isinstance(asset, dict):
            raise LockError("lock asset record must be an object")
        for field in ("name", "version", "filename", "url", "sha256", "size"):
            if field not in asset:
                raise LockError(f"lock asset record is missing {field!r}")
        digest = str(asset["sha256"]).lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise LockError(f"invalid locked SHA-256 for {asset['name']}")
        identity = f"{asset['name']}=={asset['version']}"
        if identity in seen:
            raise LockError(f"duplicate lock asset: {identity}")
        seen.add(identity)
