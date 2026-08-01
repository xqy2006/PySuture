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
            "stdlib_top_level_import_names",
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


def _is_stdlib(name: str, runtime_metadata: dict | None = None) -> bool:
    if runtime_metadata is not None and "stdlib_top_level_import_names" in runtime_metadata:
        names = runtime_metadata.get("stdlib_top_level_import_names")
        if not isinstance(names, list) or not all(isinstance(item, str) and item for item in names):
            raise LockError("runtime SDK stdlib_top_level_import_names must be a list of module names")
        return name in names
    # Compatibility for indexes produced before StaticPython published the
    # target runtime's exact frozen/builtin module inventory.
    return name in sys.stdlib_module_names or name in WINDOWS_STDLIB_MODULES


def validate_pack_composition(runtime_metadata: dict, packs: list[tuple[str, dict]]) -> None:
    claimed_frozen: dict[str, str] = {}
    claimed_builtins: dict[str, str] = {"_staticpython_resource_store": "runtime SDK"}
    claimed_resources: dict[str, str] = {}
    claimed_descriptors: dict[str, str] = {}

    runtime_frozen = runtime_metadata.get("frozen_module_names", [])
    if not isinstance(runtime_frozen, list):
        raise LockError("runtime SDK frozen_module_names must be a list")
    for module_name in runtime_frozen:
        if isinstance(module_name, str) and module_name:
            claimed_frozen[module_name] = "runtime SDK"
    runtime_builtins = runtime_metadata.get("builtin_module_registrations", [])
    if not isinstance(runtime_builtins, list):
        raise LockError("runtime SDK builtin_module_registrations must be a list")
    for registration in runtime_builtins:
        if isinstance(registration, dict) and isinstance(registration.get("name"), str):
            claimed_builtins[registration["name"]] = "runtime SDK"

    def claim(table: dict[str, str], value: object, owner: str, kind: str) -> None:
        if not isinstance(value, str) or not value:
            raise LockError(f"pack {owner} has an invalid {kind}")
        previous = table.get(value)
        if previous is not None:
            raise LockError(f"pack {owner} {kind} {value!r} conflicts with {previous}")
        table[value] = owner

    for owner, metadata in packs:
        descriptor = metadata.get("descriptor_symbol")
        claim(claimed_descriptors, descriptor, owner, "descriptor symbol")
        frozen_modules = metadata.get("frozen_modules", [])
        builtin_modules = metadata.get("builtin_modules", [])
        resources = metadata.get("resources", [])
        if not isinstance(frozen_modules, list):
            raise LockError(f"pack {owner} frozen_modules must be a list")
        if not isinstance(builtin_modules, list):
            raise LockError(f"pack {owner} builtin_modules must be a list")
        if not isinstance(resources, list):
            raise LockError(f"pack {owner} resources must be a list")
        for module_name in frozen_modules:
            claim(claimed_frozen, module_name, owner, "frozen module")
        for registration in builtin_modules:
            if not isinstance(registration, dict):
                raise LockError(f"pack {owner} has an invalid builtin module registration")
            claim(claimed_builtins, registration.get("name"), owner, "builtin module")
        for resource in resources:
            if not isinstance(resource, dict):
                raise LockError(f"pack {owner} has an invalid resource record")
            claim(claimed_resources, resource.get("path"), owner, "resource path")


def _solve_pack_dependencies(index: dict, abi: str, requested: dict[str, str]) -> dict[str, ResolvedAsset]:
    initial_constraints = {
        name: tuple([specifier] if specifier else [])
        for name, specifier in requested.items()
    }
    failures: list[str] = []

    def rendered(constraints: tuple[str, ...]) -> str:
        return ",".join(item for item in constraints if item)

    def version_satisfies(asset: ResolvedAsset, constraints: tuple[str, ...]) -> bool:
        try:
            return Version(asset.version) in SpecifierSet(rendered(constraints))
        except (InvalidSpecifier, InvalidVersion) as exc:
            raise LockError(f"invalid locked dependency constraint for {asset.name}") from exc

    def solve(
        selected: dict[str, ResolvedAsset],
        constraints: dict[str, tuple[str, ...]],
    ) -> dict[str, ResolvedAsset] | None:
        pending = [name for name in constraints if name not in selected]
        if not pending:
            return selected

        candidate_sets: dict[str, list[ResolvedAsset]] = {}
        for name in pending:
            candidates = _pack_candidates(index, abi, name, rendered(constraints[name]))
            if not candidates:
                failures.append(
                    f"no verified {abi} pack satisfies {name}{rendered(constraints[name])}"
                )
                return None
            candidate_sets[name] = candidates
        name = min(pending, key=lambda item: (len(candidate_sets[item]), item.casefold()))

        for asset in candidate_sets[name]:
            asset_conflicts = set(asset.metadata.get("conflicts", []))
            incompatible = any(
                other_name in asset_conflicts
                or name in set(other.metadata.get("conflicts", []))
                for other_name, other in selected.items()
            )
            if incompatible:
                continue
            next_selected = dict(selected)
            next_selected[name] = asset
            next_constraints = dict(constraints)
            dependencies = asset.metadata.get("dependencies", [])
            dependency_constraints = asset.metadata.get("dependency_constraints", {})
            if not isinstance(dependencies, list) or not isinstance(dependency_constraints, dict):
                raise LockError(f"pack {name} has invalid dependency metadata")
            valid = True
            for dependency in dependencies:
                if not isinstance(dependency, str) or not dependency:
                    raise LockError(f"pack {name} has an invalid dependency name")
                raw_constraint = dependency_constraints.get(dependency, "")
                if not isinstance(raw_constraint, str):
                    raise LockError(f"pack {name} has an invalid constraint for {dependency}")
                values = list(next_constraints.get(dependency, ()))
                if raw_constraint and raw_constraint not in values:
                    values.append(raw_constraint)
                next_constraints[dependency] = tuple(values)
                assigned = next_selected.get(dependency)
                if assigned is not None and not version_satisfies(assigned, next_constraints[dependency]):
                    valid = False
                    break
            if not valid:
                continue
            result = solve(next_selected, next_constraints)
            if result is not None:
                return result
        return None

    result = solve({}, initial_constraints)
    if result is None:
        if failures:
            raise LockError(failures[-1])
        raise LockError("could not resolve a mutually compatible StaticPython pack set")
    return result


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
        if _is_stdlib(import_name, runtime.metadata):
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

    selected = _solve_pack_dependencies(index, abi, requested)

    selected_names = set(selected)
    for asset in selected.values():
        conflicts = selected_names.intersection(asset.metadata.get("conflicts", []))
        if conflicts:
            raise LockError(f"pack {asset.name} conflicts with {', '.join(sorted(conflicts))}")
    validate_pack_composition(
        runtime.metadata,
        [(asset.name, asset.metadata) for asset in selected.values()],
    )

    report.selected_packs = {
        import_name: next(
            (name for name in selected if name in top_level.get(import_name, set())),
            "",
        )
        for import_name in report.external_imports
        if top_level.get(import_name)
    }
    unsupported = {
        name
        for name in report.unsupported_native_extensions
        if not _is_stdlib(name, runtime.metadata)
    }
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
