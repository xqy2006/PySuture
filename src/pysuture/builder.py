from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .analyzer import AnalysisReport
from .cache import extract_asset, fetch_asset, sha256_file
from .config import ProjectConfig
from .cythonizer import CythonUnit, cythonize_modules
from .errors import BuildError, LockError
from .launcher import write_launcher
from .lockfile import validate_asset_records
from .resources import ResourceRecord, collect_application_resources, write_resource_sources
from .resolver import validate_pack_composition
from .toolchain import MSVCToolchain, discover_msvc, validate_locked_toolchain


RUNTIME_METADATA_PATH = Path("metadata") / "runtime-sdk.v1.json"
FORBIDDEN_DEPENDENCY_PATTERNS = (
    re.compile(r"^python\d*\.dll$", re.IGNORECASE),
    re.compile(r"^vcruntime\d*\.dll$", re.IGNORECASE),
    re.compile(r"^msvcp\d*\.dll$", re.IGNORECASE),
    re.compile(r"^ucrtbase\.dll$", re.IGNORECASE),
)
FORBIDDEN_ENTRY_SYMBOLS = ("Py_Main", "Py_BytesMain", "Py_RunMain", "Py_SandboxMain")


@dataclass(frozen=True)
class MaterializedAssets:
    runtime_root: Path
    runtime_metadata: dict
    packs: tuple[tuple[dict, Path, dict], ...]


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"could not read asset metadata {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BuildError(f"asset metadata must be an object: {path}")
    return value


def materialize_assets(lock: dict, *, offline: bool) -> MaterializedAssets:
    validate_asset_records(lock)
    runtime_record = lock["runtime"]
    runtime_archive = fetch_asset(runtime_record["url"], runtime_record["sha256"], offline=offline)
    runtime_root = extract_asset(runtime_archive, runtime_record["sha256"])
    runtime_metadata = _read_json(runtime_root / RUNTIME_METADATA_PATH)
    for field in ("cpython_version", "cpython_abi", "runtime_abi"):
        if runtime_metadata.get(field) != lock.get(field):
            raise BuildError(
                f"runtime SDK {field} {runtime_metadata.get(field)!r} does not match lock {lock.get(field)!r}"
            )
    if runtime_metadata.get("staticpython_commit") != lock.get("staticpython_commit"):
        raise BuildError("runtime SDK StaticPython commit does not match pysuture.lock")
    if runtime_metadata.get("toolchain") != lock.get("toolchain"):
        raise BuildError("runtime SDK toolchain metadata does not match pysuture.lock")

    packs = []
    for record in lock.get("packs", []):
        archive = fetch_asset(record["url"], record["sha256"], offline=offline)
        root = extract_asset(archive, record["sha256"])
        metadata = _read_json(root / "pack.json")
        if metadata.get("name") != record["name"] or metadata.get("version") != record["version"]:
            raise BuildError(f"pack identity mismatch in {archive}")
        if metadata.get("runtime_abi") != lock["runtime_abi"]:
            raise BuildError(f"pack {record['name']} runtime ABI does not match the lock")
        if metadata.get("staticpython_commit") != lock["staticpython_commit"]:
            raise BuildError(f"pack {record['name']} was built from a different StaticPython commit")
        packs.append((record, root, metadata))
    validate_pack_composition(
        runtime_metadata,
        [(metadata.get("name", record["name"]), metadata) for record, _root, metadata in packs],
    )
    return MaterializedAssets(runtime_root, runtime_metadata, tuple(packs))


def _safe_member(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    resolved_root = root.resolve()
    if path != resolved_root and resolved_root not in path.parents:
        raise BuildError(f"asset metadata points outside its archive: {relative}")
    if not path.is_file():
        raise BuildError(f"asset file is missing: {path}")
    return path


def _write_response(path: Path, arguments: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [subprocess.list2cmdline([argument]) for argument in arguments]
    path.write_text("\n".join(lines) + "\n", encoding="utf-16", newline="\n")
    return path


def _run(command: list[str], *, environment: dict[str, str], cwd: Path, label: str) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise BuildError(f"{label} failed with exit code {result.returncode}:\n{result.stdout[-12000:]}")
    return result.stdout


def _compile_source(
    toolchain: MSVCToolchain,
    source: Path,
    object_path: Path,
    response_path: Path,
    include_dirs: list[Path],
    definitions: tuple[str, ...],
    project_root: Path,
    build_dir: Path,
) -> tuple[Path, str]:
    arguments = [
        "/nologo",
        "/c",
        "/O2",
        "/Ob2",
        "/GL",
        "/Gy",
        "/Gw",
        "/MT",
        "/DNDEBUG",
        "/DPy_NO_ENABLE_SHARED",
        "/utf-8",
        "/bigobj",
        "/Brepro",
        "/Z7",
        f"/pathmap:{project_root}=.",
        f"/pathmap:{build_dir}=.pysuture/build",
        *[f"/I{directory}" for directory in include_dirs],
        *[f"/D{definition}" for definition in definitions],
        f"/Fo{object_path}",
        str(source),
    ]
    _write_response(response_path, arguments)
    output = _run(
        [str(toolchain.cl), f"@{response_path}"],
        environment=toolchain.environment,
        cwd=build_dir,
        label=f"compile {source.name}",
    )
    if not object_path.is_file():
        raise BuildError(f"compiler did not produce {object_path}")
    return object_path, output


def _dependency_names(dumpbin_output: str) -> list[str]:
    names = []
    in_dependencies = False
    for line in dumpbin_output.splitlines():
        stripped = line.strip()
        if stripped == "Image has the following dependencies:":
            in_dependencies = True
            continue
        if in_dependencies and not stripped:
            if names:
                break
            continue
        if in_dependencies and stripped.lower().endswith(".dll"):
            names.append(stripped)
    return sorted(set(names), key=str.casefold)


def audit_executable(
    executable: Path,
    map_path: Path,
    toolchain: MSVCToolchain,
) -> dict:
    dependents = _run(
        [str(toolchain.dumpbin), "/NOLOGO", "/DEPENDENTS", str(executable)],
        environment=toolchain.environment,
        cwd=executable.parent,
        label="PE dependency audit",
    )
    dependencies = _dependency_names(dependents)
    forbidden_dependencies = [
        name for name in dependencies
        if any(pattern.match(name) for pattern in FORBIDDEN_DEPENDENCY_PATTERNS)
        or name.casefold().endswith(".pyd")
    ]
    system32 = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
    non_system_dependencies = [
        name for name in dependencies
        if not name.lower().startswith(("api-ms-win-", "ext-ms-win-"))
        and not (system32 / name).is_file()
    ]
    map_text = map_path.read_text(encoding="utf-8", errors="replace") if map_path.is_file() else ""
    forbidden_symbols = [
        symbol for symbol in FORBIDDEN_ENTRY_SYMBOLS
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])", map_text)
    ]
    main_objects = sorted(set(re.findall(r"(?im)^.*\bmain\.obj\b.*$", map_text)))
    report = {
        "status": "passed",
        "dependencies": dependencies,
        "forbidden_dependencies": forbidden_dependencies,
        "non_system_dependencies": non_system_dependencies,
        "forbidden_entry_symbols": forbidden_symbols,
        "main_object_records": main_objects,
        "executable_sha256": sha256_file(executable),
    }
    failures = []
    if forbidden_dependencies:
        failures.append("forbidden DLLs: " + ", ".join(forbidden_dependencies))
    if non_system_dependencies:
        failures.append("non-system DLLs: " + ", ".join(non_system_dependencies))
    if forbidden_symbols:
        failures.append("generic Python entry symbols: " + ", ".join(forbidden_symbols))
    if main_objects:
        failures.append("main.obj was linked")
    if failures:
        report["status"] = "failed"
        raise BuildError("PE audit failed: " + "; ".join(failures))
    return report


def _build_identity(lock: dict, report: AnalysisReport, mode: str, resources: list) -> str:
    payload = {
        "lock": lock,
        "mode": mode,
        "modules": {name: report.modules[name].source_sha256 for name in report.reachable_modules},
        "resources": [(record.target, record.sha256) for record in resources],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:20]


def _license_resources(assets: MaterializedAssets) -> list[ResourceRecord]:
    records: list[ResourceRecord] = []
    roots = [("runtime-sdk", assets.runtime_root / "licenses")]
    roots.extend((record["name"], root / "licenses") for record, root, _metadata in assets.packs)
    targets: set[str] = set()
    for owner, root in roots:
        if not root.is_dir():
            continue
        for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
            target = f"licenses/{owner}/{path.relative_to(root).as_posix()}"
            if target in targets:
                raise BuildError(f"duplicate embedded license target: {target}")
            targets.add(target)
            payload = path.read_bytes()
            records.append(
                ResourceRecord(
                    source=path,
                    target=target,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size=len(payload),
                )
            )
    return records


def build_executable(
    config: ProjectConfig,
    report: AnalysisReport,
    lock: dict,
    *,
    offline: bool = False,
    mode: str | None = None,
    output: str | None = None,
) -> tuple[Path, dict]:
    selected_mode = mode or config.mode
    if selected_mode not in {"console", "windowed"}:
        raise BuildError("build mode must be console or windowed")
    output_name = output or config.output
    if Path(output_name).name != output_name:
        raise BuildError("output must be a filename stem")
    assets = materialize_assets(lock, offline=offline)
    toolchain = discover_msvc()
    validate_locked_toolchain(lock.get("toolchain", {}), toolchain)
    resources, resource_warnings = collect_application_resources(config)
    resources.extend(_license_resources(assets))
    resources.sort(key=lambda item: item.target)
    build_id = _build_identity(lock, report, selected_mode, resources)
    build_dir = config.root / ".pysuture" / "build" / build_id
    object_dir = build_dir / "obj"
    response_dir = build_dir / "rsp"
    source_dir = build_dir / "src"
    for directory in (object_dir, response_dir, source_dir):
        directory.mkdir(parents=True, exist_ok=True)

    units, cython_warnings = cythonize_modules(report, build_dir, lock["cython_version"])
    generated_resources = write_resource_sources(resources, source_dir / "resources")
    pack_symbols = []
    pack_sources: list[Path] = []
    pack_libraries: list[Path] = []
    pack_libraries_by_name: dict[str, tuple[Path, str]] = {}
    wholearchive_paths: list[Path] = []
    system_libraries: list[str] = []
    for locked_record, pack_root, metadata in assets.packs:
        symbol = locked_record.get("descriptor_symbol") or metadata.get("descriptor_symbol")
        if not isinstance(symbol, str) or not symbol:
            raise BuildError(f"pack {locked_record['name']} has no descriptor symbol")
        pack_symbols.append(symbol)
        for relative in locked_record.get("sources", metadata.get("sources", [])):
            pack_sources.append(_safe_member(pack_root, relative))
        library_by_name = {}
        for library_name in metadata.get("libraries", []):
            path = _safe_member(pack_root, f"lib/{library_name}")
            key = str(library_name).casefold()
            digest = sha256_file(path)
            previous = pack_libraries_by_name.get(key)
            if previous is not None and previous[1] != digest:
                raise BuildError(
                    f"selected packs contain different payloads for native library {library_name}"
                )
            if previous is None:
                pack_libraries_by_name[key] = (path, digest)
                pack_libraries.append(path)
                library_by_name[key] = path
            else:
                library_by_name[key] = previous[0]
        for library_name in metadata.get("wholearchive", []):
            path = library_by_name.get(str(library_name).casefold())
            if path is None:
                raise BuildError(f"pack {locked_record['name']} wholearchive library is missing: {library_name}")
            wholearchive_paths.append(path)
        system_libraries.extend(metadata.get("system_libraries", []))

    wholearchive_paths = list(dict.fromkeys(wholearchive_paths))

    launcher = write_launcher(
        source_dir / "launcher.c",
        units=units,
        entry_module=report.entry_module,
        entry_callable=config.entry_callable,
        namespace_packages=report.namespace_packages,
        pack_symbols=pack_symbols,
        resources=generated_resources,
        windowed=selected_mode == "windowed",
    )
    include_dir = assets.runtime_root / assets.runtime_metadata.get("include_directory", "include")
    library_dir = assets.runtime_root / assets.runtime_metadata.get("library_directory", "lib")
    if not include_dir.is_dir() or not library_dir.is_dir():
        raise BuildError("runtime SDK include or library directory is missing")

    compile_jobs: list[tuple[Path, tuple[str, ...], str]] = []
    for unit in units:
        compile_jobs.append((unit.c_source, unit.compile_definitions, f"module-{unit.init_symbol}"))
    compile_jobs.append((launcher, (), "launcher"))
    compile_jobs.extend((Path(record["source"]), (), f"app-resource-{index:06d}") for index, record in enumerate(generated_resources, 1))
    compile_jobs.extend((source, (), f"pack-source-{index:06d}") for index, source in enumerate(pack_sources, 1))

    object_paths: list[Path] = []
    compile_logs: dict[str, str] = {}
    max_workers = max(1, min(len(compile_jobs), (os.cpu_count() or 2) - 1))

    def compile_job(job: tuple[Path, tuple[str, ...], str]):
        source, definitions, label = job
        digest = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:12]
        object_path = object_dir / f"{label}-{digest}.obj"
        response_path = response_dir / f"{label}-{digest}.rsp"
        result_path, output_text = _compile_source(
            toolchain,
            source,
            object_path,
            response_path,
            [include_dir],
            definitions,
            config.root,
            build_dir,
        )
        return label, result_path, output_text

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(compile_job, job) for job in compile_jobs]
        for future in concurrent.futures.as_completed(futures):
            label, object_path, output_text = future.result()
            object_paths.append(object_path)
            compile_logs[label] = output_text
    object_paths.sort(key=lambda path: path.name)

    runtime_libraries = []
    for library_name in assets.runtime_metadata.get("link_libraries", []):
        runtime_libraries.append(_safe_member(library_dir, library_name))
    system_libraries.extend(assets.runtime_metadata.get("system_libraries", []))
    system_libraries.extend(["shell32.lib", "user32.lib"])
    system_libraries = list(dict.fromkeys(str(name) for name in system_libraries))

    executable = build_dir / f"{output_name}.exe"
    map_path = build_dir / f"{output_name}.map"
    pdb_path = build_dir / f"{output_name}.pdb"
    link_arguments = [
        "/NOLOGO",
        f"/OUT:{executable}",
        f"/MAP:{map_path}",
        f"/PDB:{pdb_path}",
        "/PDBALTPATH:%_PDB%",
        "/DEBUG:FULL",
        "/LTCG",
        "/OPT:REF",
        "/OPT:ICF",
        "/INCREMENTAL:NO",
        "/MANIFEST:EMBED",
        "/DYNAMICBASE",
        "/NXCOMPAT",
        "/HIGHENTROPYVA",
        "/Brepro",
        f"/SUBSYSTEM:{'WINDOWS' if selected_mode == 'windowed' else 'CONSOLE'}",
        *[str(path) for path in object_paths],
        *[str(path) for path in pack_libraries],
        *[str(path) for path in runtime_libraries],
        *[f"/WHOLEARCHIVE:{path}" for path in wholearchive_paths],
        *system_libraries,
    ]
    link_response = _write_response(response_dir / "link.rsp", link_arguments)
    link_log = _run(
        [str(toolchain.link), f"@{link_response}"],
        environment=toolchain.environment,
        cwd=build_dir,
        label="link executable",
    )
    if not executable.is_file():
        raise BuildError("linker did not produce the executable")
    audit = audit_executable(executable, map_path, toolchain)
    dist_dir = config.root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    destination = dist_dir / executable.name
    shutil.copy2(executable, destination)
    report_payload = {
        "schema_version": 1,
        "status": "passed",
        "build_id": build_id,
        "mode": selected_mode,
        "output": str(destination),
        "output_sha256": sha256_file(destination),
        "runtime": lock["runtime"],
        "packs": lock.get("packs", []),
        "modules": [
            {
                "name": unit.module.name,
                "source": str(unit.module.path),
                "source_sha256": unit.module.source_sha256,
                "init_symbol": unit.init_symbol,
            }
            for unit in units
        ],
        "namespace_packages": list(report.namespace_packages),
        "resources": [
            {"target": item.target, "source": str(item.source), "sha256": item.sha256, "size": item.size}
            for item in resources
        ],
        "warnings": [*resource_warnings, *cython_warnings],
        "toolchain": toolchain.fingerprint(),
        "pe_audit": audit,
        "artifacts": {
            "pdb": str(pdb_path),
            "map": str(map_path),
            "build_report": str(build_dir / "build-report.json"),
        },
        "compile_logs": compile_logs,
        "link_log": link_log,
    }
    report_path = build_dir / "build-report.json"
    report_path.write_text(
        json.dumps(report_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
        newline="\n",
    )
    return destination, report_payload
