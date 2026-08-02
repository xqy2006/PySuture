from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .analyzer import AnalysisReport, analyze_project
from .builder import build_executable
from .config import (
    DataMapping,
    ProjectConfig,
    initialize_project,
    load_project_config,
    validate_output_name,
)
from .errors import AnalysisError, BuildError, ConfigurationError, LockError, PySutureError
from .lockfile import (
    load_lock,
    lock_path,
    validate_lock_for_configuration,
    validate_lock_for_project,
    write_lock,
)
from .resolver import build_lock_payload, resolve_assets
from .toolchain import doctor_report


def _json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _project_root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _unresolved_dynamic_gaps(report: AnalysisReport, config: ProjectConfig):
    has_explicit_targets = bool(config.include_modules or config.include_packages)
    return () if has_explicit_targets else report.dynamic_gaps


def _require_no_dynamic_gaps(report: AnalysisReport, config: ProjectConfig) -> None:
    gaps = _unresolved_dynamic_gaps(report, config)
    if not gaps:
        return
    previews = [
        f"{gap.module}:{gap.line} ({gap.expression})"
        for gap in gaps[:10]
    ]
    raise AnalysisError(
        "dynamic imports could not be resolved: "
        + ", ".join(previews)
        + "; declare concrete modules in tool.pysuture.include-modules or a pure-Python "
        "package in tool.pysuture.include-packages"
    )


def _create_lock(config: ProjectConfig, report: AnalysisReport, *, offline: bool) -> tuple[Path, dict]:
    _require_no_dynamic_gaps(report, config)
    resolution = resolve_assets(config, report, offline=offline)
    payload = build_lock_payload(config, report, resolution)
    return write_lock(config.root, payload), payload


def _parse_data_mapping(value: str) -> DataMapping:
    source, separator, target = value.partition("=")
    if not separator or not source or not target:
        raise argparse.ArgumentTypeError("data mapping must be SOURCE=VIRTUAL/TARGET")
    return DataMapping(source, target)


def _apply_build_overrides(config: ProjectConfig, args: argparse.Namespace) -> ProjectConfig:
    include_modules = tuple(dict.fromkeys([*config.include_modules, *args.include_module]))
    include_packages = tuple(dict.fromkeys([*config.include_packages, *args.include_package]))
    data = (*config.data, *args.include_data)
    output = config.output if args.output is None else args.output
    return replace(
        config,
        python=args.python or config.python,
        mode=args.mode or config.mode,
        output=validate_output_name(output),
        include_modules=include_modules,
        include_packages=include_packages,
        data=tuple(data),
    )


def command_init(args: argparse.Namespace) -> int:
    path = initialize_project(args.root, args.entry, args.python, args.mode, args.output)
    print(f"initialized {path}")
    return 0


def command_analyze(args: argparse.Namespace) -> int:
    config = load_project_config(args.root)
    report = analyze_project(config)
    resolution_error = None
    try:
        resolution = resolve_assets(config, report, offline=args.offline)
    except LockError as exc:
        resolution = None
        resolution_error = str(exc)
    payload = report.as_dict()
    unresolved_dynamic_gaps = _unresolved_dynamic_gaps(report, config)
    if resolution is not None:
        payload["runtime"] = {
            "version": resolution.runtime.version,
            "abi": resolution.runtime.metadata.get("runtime_abi"),
        }
        payload["packs"] = [
            {"name": asset.name, "version": asset.version}
            for asset in resolution.packs
        ]
    if resolution_error:
        payload["resolution_error"] = resolution_error
    payload["status"] = "incomplete" if unresolved_dynamic_gaps or resolution_error else "ready"
    if args.json:
        _json(payload)
    else:
        print(f"entry: {report.entry_module}")
        print(f"reachable Cython modules: {len(report.reachable_modules)}")
        print(f"namespace packages: {len(report.namespace_packages)}")
        print("external imports: " + (", ".join(report.external_imports) or "<none>"))
        if resolution is not None:
            print("selected packs: " + (", ".join(f"{asset.name}=={asset.version}" for asset in resolution.packs) or "<none>"))
        if report.dynamic_gaps:
            label = "dynamic import sites covered by explicit includes:" if not unresolved_dynamic_gaps else "dynamic import gaps:"
            print(label)
            for gap in report.dynamic_gaps:
                print(f"  {gap.path}:{gap.line}: {gap.expression}")
        if resolution_error:
            print(f"resolution: {resolution_error}")
    return 1 if unresolved_dynamic_gaps or resolution_error else 0


def command_lock(args: argparse.Namespace) -> int:
    config = load_project_config(args.root)
    if args.python:
        config = replace(config, python=args.python)
    report = analyze_project(config)
    _require_no_dynamic_gaps(report, config)
    path = lock_path(config.root)
    if path.exists() and not args.update:
        payload = load_lock(config.root)
        validate_lock_for_configuration(payload, config)
        validate_lock_for_project(payload, report, frozen=False)
        _validate_locked_imports(payload, report, config)
        print(f"lock unchanged: {path}")
        return 0
    path, payload = _create_lock(config, report, offline=args.offline)
    print(
        f"wrote {path}: CPython {payload['cpython_version']}, "
        f"StaticPython {payload['staticpython_commit'][:12]}, {len(payload['packs'])} pack(s)"
    )
    return 0


def _validate_locked_imports(lock: dict, report: AnalysisReport, config: ProjectConfig) -> None:
    from .resolver import _is_stdlib

    pack_records = lock.get("packs")
    if not isinstance(pack_records, list):
        raise LockError("pysuture.lock packs must be an array")
    by_name: dict[str, dict] = {}
    providers: dict[str, set[str]] = {}
    for record in pack_records:
        if not isinstance(record, dict):
            raise LockError("pysuture.lock contains an invalid pack record")
        pack_name = record.get("name")
        if not isinstance(pack_name, str) or not pack_name:
            raise LockError("pysuture.lock contains a pack without a valid name")
        key = pack_name.casefold()
        if key in by_name:
            raise LockError(f"pysuture.lock contains duplicate pack records for {pack_name!r}")
        by_name[key] = record
        import_names = record.get("top_level_import_names")
        if not isinstance(import_names, list) or not all(
            isinstance(name, str) and name for name in import_names
        ):
            raise LockError(f"pysuture.lock pack {pack_name} has invalid top-level import names")
        for import_name in import_names:
            providers.setdefault(import_name, set()).add(key)

    required = {
        requested_name.casefold()
        for requested_name in config.packages
    }
    absent_requested = sorted(
        requested_name
        for requested_name in config.packages
        if requested_name.casefold() not in by_name
    )
    if absent_requested:
        raise LockError(
            "pysuture.lock does not contain explicitly requested pack(s): "
            + ", ".join(absent_requested)
            + "; run 'pysuture lock --update'"
        )

    missing: list[str] = []
    ambiguous: list[str] = []
    for name in report.external_imports:
        if _is_stdlib(name, lock.get("runtime", {})) or name in config.include_packages:
            continue
        matches = providers.get(name, set())
        if not matches:
            missing.append(name)
        elif len(matches) > 1:
            owners = ", ".join(sorted(str(by_name[key]["name"]) for key in matches))
            ambiguous.append(f"{name} ({owners})")
        else:
            required.update(matches)
    if missing:
        raise LockError(
            "current sources import dependencies absent from pysuture.lock: "
            + ", ".join(sorted(missing))
            + "; run 'pysuture lock --update'"
        )
    if ambiguous:
        raise LockError(
            "current imports have multiple providers in pysuture.lock: "
            + ", ".join(sorted(ambiguous))
            + "; run 'pysuture lock --update'"
        )

    pending = list(required)
    while pending:
        key = pending.pop()
        record = by_name[key]
        dependencies = record.get("dependencies")
        if not isinstance(dependencies, list) or not all(
            isinstance(name, str) and name for name in dependencies
        ):
            raise LockError(f"pysuture.lock pack {record['name']} has invalid dependencies")
        for dependency in dependencies:
            dependency_key = dependency.casefold()
            if dependency_key not in by_name:
                raise LockError(
                    f"pysuture.lock pack {record['name']} requires missing pack {dependency!r}; "
                    "run 'pysuture lock --update'"
                )
            if dependency_key not in required:
                required.add(dependency_key)
                pending.append(dependency_key)

    extra = sorted(
        str(record["name"])
        for key, record in by_name.items()
        if key not in required
    )
    if extra:
        raise LockError(
            "pysuture.lock contains packs no longer required by current imports: "
            + ", ".join(extra)
            + "; run 'pysuture lock --update'"
        )


def command_build(args: argparse.Namespace) -> int:
    config = _apply_build_overrides(load_project_config(args.root), args)
    report = analyze_project(config)
    _require_no_dynamic_gaps(report, config)
    path = lock_path(config.root)
    if not path.exists():
        if args.frozen_lock:
            raise LockError("--frozen-lock requires an existing pysuture.lock; run 'pysuture lock' first")
        _path, lock = _create_lock(config, report, offline=args.offline)
    else:
        lock = load_lock(config.root)
    validate_lock_for_configuration(lock, config)
    validate_lock_for_project(lock, report, frozen=args.frozen_lock)
    _validate_locked_imports(lock, report, config)
    destination, build_report = build_executable(
        config,
        report,
        lock,
        offline=args.offline,
        mode=config.mode,
        output=config.output,
    )
    print(f"built {destination}")
    print(f"sha256 {build_report['output_sha256']}")
    if build_report["warnings"]:
        for warning in build_report["warnings"]:
            print(f"warning: {warning}", file=sys.stderr)
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    path = lock_path(args.root)
    lock_error = None
    try:
        lock = load_lock(args.root)
    except LockError as exc:
        lock = None
        if path.exists():
            lock_error = str(exc)
    report = doctor_report(lock, lock_error=lock_error)
    if args.json:
        _json(report)
    else:
        for check in report["checks"]:
            print(f"{check['status']:>6}  {check['name']}: {check['detail']}")
    return 0 if report["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pysuture", description="Build non-extracting static Windows Python applications")
    parser.add_argument("--version", action="version", version=f"PySuture {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="add [tool.pysuture] to pyproject.toml")
    init.add_argument("--root", type=_project_root, default=Path.cwd())
    init.add_argument("--entry", required=True)
    init.add_argument("--python", default="3.13")
    init.add_argument("--mode", choices=("console", "windowed"), default="console")
    init.add_argument("--output")
    init.set_defaults(func=command_init)

    analyze = subparsers.add_parser("analyze", help="show imports, packs, dynamic gaps, and native blockers")
    analyze.add_argument("--root", type=_project_root, default=Path.cwd())
    analyze.add_argument("--offline", action="store_true")
    analyze.add_argument("--json", action="store_true")
    analyze.set_defaults(func=command_analyze)

    lock = subparsers.add_parser("lock", help="create or update pysuture.lock")
    lock.add_argument("--root", type=_project_root, default=Path.cwd())
    lock.add_argument("--python", help="target Python series for the generated lock")
    lock.add_argument("--update", action="store_true")
    lock.add_argument("--offline", action="store_true")
    lock.set_defaults(func=command_lock)

    build = subparsers.add_parser("build", help="compile and link one static executable")
    build.add_argument("--root", type=_project_root, default=Path.cwd())
    build.add_argument("--python")
    build.add_argument("--mode", choices=("console", "windowed"))
    build.add_argument("--output")
    build.add_argument("--include-module", action="append", default=[])
    build.add_argument("--include-package", action="append", default=[])
    build.add_argument("--include-data", action="append", default=[], type=_parse_data_mapping, metavar="SOURCE=TARGET")
    build.add_argument("--offline", action="store_true")
    build.add_argument("--frozen-lock", action="store_true")
    build.set_defaults(func=command_build)

    doctor = subparsers.add_parser("doctor", help="check VS 2022, Windows SDK, cache, and lock compatibility")
    doctor.add_argument("--root", type=_project_root, default=Path.cwd())
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=command_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except PySutureError as exc:
        print(f"pysuture: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("pysuture: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
