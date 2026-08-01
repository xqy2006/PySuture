from __future__ import annotations

import json
import sys
from dataclasses import dataclass

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .analyzer import AnalysisReport
from .cache import fetch_index, sha256_bytes
from .config import ProjectConfig
from .constants import DEFAULT_CYTHON_VERSION, SUPPORTED_PLATFORM
from .errors import LockError


WINDOWS_STDLIB_MODULES = {
    "msvcrt",
    "winreg",
    "winsound",
}


@dataclass(frozen=True)
class ResolvedAsset:
    name: str
    version: str
    filename: str
    url: str
    sha256: str
    size: int
    metadata: dict

    def lock_record(self) -> dict:
        record = {
            "name": self.name,
            "version": self.version,
            "filename": self.filename,
            "url": self.url,
            "sha256": self.sha256,
            "size": self.size,
            "descriptor_symbol": self.metadata.get("descriptor_symbol"),
            "libraries": self.metadata.get("libraries", []),
            "wholearchive": self.metadata.get("wholearchive", []),
            "system_libraries": self.metadata.get("system_libraries", []),
            "sources": self.metadata.get("sources", []),
            "license": self.metadata.get("license", {}),
            "top_level_import_names": self.metadata.get("top_level_import_names", []),
        }
        for field in (
            "runtime_abi",
            "cpython_abi",
            "core_library",
            "runtime_library",
            "base_pack_symbol",
            "include_directory",
            "library_directory",
            "link_libraries",
            "system_libraries",
        ):
            if field in self.metadata:
                record[field] = self.metadata[field]
        return record


@dataclass(frozen=True)
class Resolution:
    index: dict
    index_sha256: str
    runtime: ResolvedAsset
    packs: tuple[ResolvedAsset, ...]
    unresolved_imports: tuple[str, ...]


def load_verified_index(config: ProjectConfig, *, offline: bool = False) -> tuple[dict, str]:
    payload, _cache_path = fetch_index(config.index_url, offline=offline)
    digest = sha256_bytes(payload)
    try:
        index = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockError(f"StaticPython index is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(index, dict) or index.get("schema_version") != 1:
        raise LockError("unsupported StaticPython runtime index schema")
    if index.get("status") != "verified":
        raise LockError("StaticPython index is not marked verified")
    if index.get("target_platform") != SUPPORTED_PLATFORM:
        raise LockError(f"StaticPython index target is not {SUPPORTED_PLATFORM}")
    return index, digest


def _asset(name: str, version: str, record: dict) -> ResolvedAsset:
    required = ("filename", "url", "sha256", "size", "metadata")
    missing = [field for field in required if field not in record]
    if missing:
        raise LockError(f"asset {name} {version} is missing fields: {', '.join(missing)}")
    metadata = record["metadata"]
    if not isinstance(metadata, dict):
        raise LockError(f"asset {name} {version} metadata must be an object")
    return ResolvedAsset(
        name=name,
        version=version,
        filename=str(record["filename"]),
        url=str(record["url"]),
        sha256=str(record["sha256"]).lower(),
        size=int(record["size"]),
        metadata=metadata,
    )


def _pack_candidates(index: dict, abi: str, name: str, specifier: str) -> list[ResolvedAsset]:
    versions = index.get("packs", {}).get(name)
    if not isinstance(versions, dict):
        return []
    try:
        constraint = SpecifierSet(specifier or "")
    except InvalidSpecifier as exc:
        raise LockError(f"invalid version constraint for {name}: {specifier!r}") from exc
    candidates: list[tuple[Version, ResolvedAsset]] = []
    for raw_version, by_abi in versions.items():
        if not isinstance(by_abi, dict) or abi not in by_abi:
            continue
        try:
            parsed = Version(raw_version)
        except InvalidVersion:
            continue
        if parsed.is_prerelease or parsed.is_devrelease or parsed not in constraint:
            continue
        asset = _asset(name, raw_version, by_abi[abi])
        if asset.metadata.get("runtime_abi") != f"staticpython-pack-v1-{abi}":
            continue
        candidates.append((parsed, asset))
    candidates.sort(key=lambda item: item[0], reverse=True)
    return [asset for _version, asset in candidates]


def _top_level_map(index: dict, abi: str) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for name, versions in index.get("packs", {}).items():
        if not isinstance(versions, dict):
            continue
        for by_abi in versions.values():
            if not isinstance(by_abi, dict) or abi not in by_abi:
                continue
            metadata = by_abi[abi].get("metadata", {})
            for import_name in metadata.get("top_level_import_names", []):
                if isinstance(import_name, str) and import_name:
                    mapping.setdefault(import_name, set()).add(name)
    return mapping


def _is_stdlib(name: str) -> bool:
    return name in sys.stdlib_module_names or name in WINDOWS_STDLIB_MODULES


def resolve_assets(
    config: ProjectConfig,
    report: AnalysisReport,
    *,
    offline: bool = False,
) -> Resolution:
    index, index_sha256 = load_verified_index(config, offline=offline)
    abi = "cp" + config.python.replace(".", "")
    runtime_record = index.get("runtimes", {}).get(abi)
    if not isinstance(runtime_record, dict):
        raise LockError(f"verified StaticPython index has no runtime SDK for {abi}")
    runtime_metadata = runtime_record.get("metadata", {})
    runtime_version = runtime_metadata.get("cpython_version")
    runtime = _asset("runtime-sdk", str(runtime_version), runtime_record)
    expected_runtime_abi = f"staticpython-pack-v1-{abi}"
    if runtime.metadata.get("runtime_abi") != expected_runtime_abi:
        raise LockError(f"runtime SDK ABI mismatch: expected {expected_runtime_abi}")

    top_level = _top_level_map(index, abi)
    requested: dict[str, str] = dict(config.packages)
    unresolved: set[str] = set()
    for import_name in report.external_imports:
        if _is_stdlib(import_name):
            continue
        providers = top_level.get(import_name, set())
        if not providers:
            if import_name not in config.include_packages:
                unresolved.add(import_name)
            continue
        explicitly_requested = [name for name in providers if name in requested]
        if len(explicitly_requested) == 1:
            continue
        if len(providers) != 1:
            raise LockError(
                f"import {import_name!r} is provided by multiple packs ({', '.join(sorted(providers))}); "
                "select one under [tool.pysuture.packages]"
            )
        requested.setdefault(next(iter(providers)), "")

    if unresolved:
        raise LockError(
            "imports have no verified StaticPython pack: "
            + ", ".join(sorted(unresolved))
            + "; pure-Python dependencies must be explicitly listed in include-packages"
        )

    selected: dict[str, ResolvedAsset] = {}
    pending = list(requested)
    while pending:
        name = pending.pop(0)
        if name in selected:
            continue
        candidates = _pack_candidates(index, abi, name, requested.get(name, ""))
        if not candidates:
            raise LockError(f"no verified {abi} pack satisfies {name}{requested.get(name, '')}")
        asset = candidates[0]
        selected[name] = asset
        for dependency in asset.metadata.get("dependencies", []):
            if not isinstance(dependency, str) or not dependency:
                continue
            constraints = asset.metadata.get("dependency_constraints", {})
            dependency_constraint = constraints.get(dependency, "") if isinstance(constraints, dict) else ""
            existing = requested.get(dependency)
            if existing and dependency_constraint and existing != dependency_constraint:
                requested[dependency] = f"{existing},{dependency_constraint}"
            else:
                requested.setdefault(dependency, dependency_constraint)
            pending.append(dependency)

    selected_names = set(selected)
    for asset in selected.values():
        conflicts = selected_names.intersection(asset.metadata.get("conflicts", []))
        if conflicts:
            raise LockError(f"pack {asset.name} conflicts with {', '.join(sorted(conflicts))}")

    report.selected_packs = {
        import_name: next(
            (name for name in selected if name in top_level.get(import_name, set())),
            "",
        )
        for import_name in report.external_imports
        if top_level.get(import_name)
    }
    unsupported = set(report.unsupported_native_extensions)
    unsupported.difference_update(report.selected_packs)
    if unsupported:
        raise LockError(
            "native extensions require StaticPython packs: " + ", ".join(sorted(unsupported))
        )
    return Resolution(
        index=index,
        index_sha256=index_sha256,
        runtime=runtime,
        packs=tuple(sorted(selected.values(), key=lambda item: item.name.casefold())),
        unresolved_imports=tuple(sorted(unresolved)),
    )


def build_lock_payload(config: ProjectConfig, report: AnalysisReport, resolution: Resolution) -> dict:
    runtime = resolution.runtime
    return {
        "schema_version": 1,
        "platform": SUPPORTED_PLATFORM,
        "python_series": config.python,
        "cpython_version": runtime.metadata["cpython_version"],
        "cpython_abi": runtime.metadata["cpython_abi"],
        "staticpython_commit": resolution.index["staticpython_commit"],
        "runtime_abi": runtime.metadata["runtime_abi"],
        "index": {"url": config.index_url, "sha256": resolution.index_sha256},
        "runtime": runtime.lock_record(),
        "packs": [asset.lock_record() for asset in resolution.packs],
        "cython_version": DEFAULT_CYTHON_VERSION,
        "toolchain": runtime.metadata.get("toolchain", {}),
        "project": {
            "entry": config.entry,
            "entry_module": report.entry_module,
            "mode": config.mode,
            "output": config.output,
            "modules": [
                {"name": name, "sha256": report.modules[name].source_sha256}
                for name in report.reachable_modules
            ],
            "namespace_packages": list(report.namespace_packages),
            "dynamic_imports": list(report.dynamic_imports),
        },
    }
