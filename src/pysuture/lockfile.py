from __future__ import annotations

import json
from pathlib import Path

from .analyzer import AnalysisReport
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
