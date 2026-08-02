from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from dataclasses import replace
from pathlib import Path
from zipfile import ZipFile


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from pysuture.analyzer import _private_package_modules, analyze_project
from pysuture.builder import REQUIRED_WINDOWS_SYSTEM_LIBRARIES
from pysuture.cache import (
    _latest_prerelease_asset_url,
    _publish_extracted_cache,
    _safe_extract,
    extract_asset,
    sha256_bytes,
    sha256_file,
)
from pysuture.cli import main as cli_main
from pysuture.config import DataMapping, initialize_project, load_project_config
from pysuture.cythonizer import cythonize_modules, installed_cython_version
from pysuture.errors import AnalysisError, BuildError, LockError
from pysuture.launcher import write_launcher
from pysuture.lockfile import (
    validate_lock_for_configuration,
    validate_lock_for_project,
    write_lock,
)
from pysuture.resolver import (
    _solve_pack_dependencies,
    build_lock_payload,
    load_verified_index,
    resolve_assets,
    validate_pack_composition,
    validate_pack_runtime_compatibility,
)
from pysuture.resources import collect_application_resources
from pysuture.toolchain import MSVCToolchain, locked_toolchain_mismatches, validate_locked_toolchain


class CoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_asset_archive(
        self,
        entries: list[tuple[str, bytes | str]],
        *,
        name: str = "asset.zip",
    ) -> tuple[Path, str]:
        archive_path = self.root / name
        with ZipFile(archive_path, "w") as archive:
            for member, payload in entries:
                archive.writestr(member, payload)
        return archive_path, sha256_file(archive_path)

    def test_windows_link_baseline_includes_security_apis(self) -> None:
        self.assertIn("advapi32.lib", REQUIRED_WINDOWS_SYSTEM_LIBRARIES)

    def test_latest_prerelease_asset_uses_publication_time_not_api_order(self) -> None:
        releases = [
            {
                "id": 10,
                "draft": False,
                "prerelease": True,
                "published_at": "2026-08-02T06:08:06Z",
                "assets": [
                    {
                        "name": "runtime-index.v1.json",
                        "browser_download_url": "https://example.invalid/old-index.json",
                    }
                ],
            },
            {
                "id": 20,
                "draft": False,
                "prerelease": True,
                "published_at": "2026-08-02T08:15:51Z",
                "assets": [
                    {
                        "name": "runtime-index.v1.json",
                        "browser_download_url": "https://example.invalid/new-index.json",
                    }
                ],
            },
        ]
        self.assertEqual(
            _latest_prerelease_asset_url(releases, "runtime-index.v1.json"),
            "https://example.invalid/new-index.json",
        )

    def _write_project(self, app_source: str, *, index: dict | None = None) -> None:
        (self.root / "app.py").write_text(app_source, encoding="utf-8")
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "__init__.py").write_text("from . import helper\n", encoding="utf-8")
        (self.root / "pkg" / "helper.py").write_text("VALUE = 42\n", encoding="utf-8")
        (self.root / "ns" / "child").mkdir(parents=True)
        (self.root / "ns" / "child" / "module.py").write_text("VALUE = 'namespace'\n", encoding="utf-8")
        index_path = self.root / "runtime-index.v1.json"
        index_path.write_text(json.dumps(index or self._index()), encoding="utf-8")
        (self.root / "pyproject.toml").write_text(
            "[tool.pysuture]\n"
            'entry = "app.py"\n'
            'python = "3.13"\n'
            'mode = "console"\n'
            'output = "demo"\n'
            'include-modules = ["ns.child.module"]\n'
            'include-packages = []\n'
            'source-roots = ["."]\n'
            f'index-url = "{index_path.as_posix()}"\n'
            'secret-policy = "error"\n'
            "data = []\n\n"
            "[tool.pysuture.packages]\n",
            encoding="utf-8",
        )

    @staticmethod
    def _index() -> dict:
        commit = "a" * 40
        runtime_metadata = {
            "cpython_version": "3.13.7",
            "cpython_abi": "cp313",
            "cpython_commit": "b" * 40,
            "cpython_tag": "v3.13.7",
            "runtime_abi": "staticpython-pack-v1-cp313",
            "staticpython_commit": commit,
            "toolchain": {"platform_toolset": "v143"},
            "verification": {"status": "passed"},
            "stdlib_top_level_import_names": sorted(
                set(sys.stdlib_module_names) | {"msvcrt", "winreg", "winsound", "target_only_stdlib"}
            ),
        }
        pack_metadata = {
            "name": "attrs",
            "version": "25.3.0",
            "cpython_version": "3.13.7",
            "cpython_abi": "cp313",
            "cpython_commit": "b" * 40,
            "cpython_tag": "v3.13.7",
            "runtime_abi": "staticpython-pack-v1-cp313",
            "staticpython_commit": commit,
            "toolchain": {"platform_toolset": "v143"},
            "top_level_import_names": ["attrs"],
            "dependencies": [],
            "dependency_constraints": {},
            "conflicts": [],
            "descriptor_symbol": "StaticPython_Pack_attrs",
            "libraries": [],
            "sources": ["src/pack.c"],
            "license": {"status": "complete", "expression": "MIT"},
            "verification": {"status": "passed"},
        }
        return {
            "schema_version": 1,
            "kind": "staticpython-runtime-index",
            "status": "verified",
            "target_platform": "windows-x64",
            "staticpython_commit": commit,
            "runtimes": {
                "cp313": {
                    "filename": "runtime.zip",
                    "url": "https://example.invalid/runtime.zip",
                    "sha256": "1" * 64,
                    "size": 10,
                    "metadata": runtime_metadata,
                }
            },
            "packs": {
                "attrs": {
                    "25.3.0": {
                        "cp313": {
                            "filename": "attrs.zip",
                            "url": "https://example.invalid/attrs.zip",
                            "sha256": "2" * 64,
                            "size": 20,
                            "metadata": pack_metadata,
                        }
                    }
                }
            },
        }

    def test_analyzer_follows_relative_and_namespace_modules(self) -> None:
        self._write_project("import pkg\nimport attrs\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        self.assertEqual(report.entry_module, "app")
        self.assertEqual(
            set(report.reachable_modules),
            {"app", "pkg", "pkg.helper", "ns.child.module"},
        )
        self.assertEqual(report.namespace_packages, ("ns", "ns.child"))
        self.assertIn("attrs", report.external_imports)

    def test_dynamic_import_gap_requires_explicit_declaration(self) -> None:
        self._write_project("import importlib\nname = 'pkg.helper'\nimportlib.import_module(name)\n")
        report = analyze_project(load_project_config(self.root))
        self.assertEqual(len(report.dynamic_gaps), 1)
        self.assertEqual(report.dynamic_gaps[0].module, "app")

    def test_dynamic_import_aliases_and_relative_literals_are_reachable(self) -> None:
        self._write_project(
            "import importlib as loader\n"
            "loader.import_module('pkg.alias_target')\n"
            "import pkg\n"
        )
        (self.root / "pkg" / "alias_target.py").write_text(
            "VALUE = 1\n",
            encoding="utf-8",
        )
        (self.root / "pkg" / "__init__.py").write_text(
            "from importlib import import_module as load\n"
            "load('.helper', package=__package__)\n",
            encoding="utf-8",
        )
        report = analyze_project(load_project_config(self.root))
        self.assertIn("pkg.helper", report.reachable_modules)
        self.assertIn("pkg.alias_target", report.reachable_modules)
        self.assertIn("pkg.helper", report.dynamic_imports)
        self.assertIn("pkg.alias_target", report.dynamic_imports)
        self.assertEqual(report.dynamic_gaps, ())

    def test_relative_dynamic_import_without_package_is_a_gap(self) -> None:
        self._write_project("import importlib\nimportlib.import_module('.helper')\n")
        report = analyze_project(load_project_config(self.root))
        self.assertEqual(len(report.dynamic_gaps), 1)
        self.assertEqual(report.dynamic_gaps[0].expression, "'.helper'")

    def test_explicit_dynamic_module_selects_its_pack(self) -> None:
        self._write_project("import importlib\nname = 'attrs'\nimportlib.import_module(name)\n")
        project_path = self.root / "pyproject.toml"
        project_path.write_text(
            project_path.read_text(encoding="utf-8").replace(
                'include-modules = ["ns.child.module"]',
                'include-modules = ["ns.child.module", "attrs.plugins"]',
            ),
            encoding="utf-8",
        )
        config = load_project_config(self.root)
        report = analyze_project(config)
        self.assertIn("attrs", report.external_imports)
        self.assertEqual([(pack.name, pack.version) for pack in resolve_assets(config, report).packs], [
            ("attrs", "25.3.0")
        ])

    def test_resolver_selects_minimum_verified_pack(self) -> None:
        self._write_project("import attrs\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        resolution = resolve_assets(config, report)
        self.assertEqual(resolution.runtime.version, "3.13.7")
        self.assertEqual([(pack.name, pack.version) for pack in resolution.packs], [("attrs", "25.3.0")])
        payload = build_lock_payload(config, report, resolution)
        self.assertEqual(payload["cython_version"], "3.2.9")
        self.assertEqual(payload["packs"][0]["descriptor_symbol"], "StaticPython_Pack_attrs")

    def test_reviewed_catalog_resolves_exact_hashed_index(self) -> None:
        self._write_project("import attrs\n")
        reviewed_index = self._index()
        versions = {
            "cp311": "3.11.15",
            "cp312": "3.12.13",
            "cp313": "3.13.7",
            "cp314": "3.14.4",
            "cp315": "3.15.0a8",
        }
        base_runtime = reviewed_index["runtimes"]["cp313"]
        reviewed_index["runtimes"] = {}
        for abi, version in versions.items():
            record = json.loads(json.dumps(base_runtime))
            record["metadata"]["cpython_version"] = version
            record["metadata"]["cpython_abi"] = abi
            record["metadata"]["runtime_abi"] = f"staticpython-pack-v1-{abi}"
            reviewed_index["runtimes"][abi] = record

        index_path = self.root / "reviewed-index.json"
        index_payload = json.dumps(reviewed_index, sort_keys=True).encode("utf-8")
        index_path.write_bytes(index_payload)
        catalog = {
            "schema_version": 1,
            "kind": "pysuture-reviewed-runtime-catalog",
            "status": "reviewed",
            "target_platform": "windows-x64",
            "staticpython_commit": "a" * 40,
            "index_url": index_path.as_posix(),
            "index_sha256": sha256_bytes(index_payload),
            "runtimes": {
                abi: {
                    "cpython_version": record["metadata"]["cpython_version"],
                    "runtime_abi": record["metadata"]["runtime_abi"],
                    "sha256": record["sha256"],
                }
                for abi, record in reviewed_index["runtimes"].items()
            },
            "pack_asset_count": 1,
            "validation": {
                "status": "passed",
                "python_series": ["3.11", "3.12", "3.13", "3.14", "3.15"],
                "modes": ["console", "windowed"],
            },
        }
        catalog_path = self.root / "runtime-catalog.lock.json"
        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        config = replace(load_project_config(self.root), index_url=str(catalog_path))
        loaded, digest = load_verified_index(config)
        self.assertEqual(loaded["staticpython_commit"], "a" * 40)
        self.assertEqual(digest, catalog["index_sha256"])

        catalog["index_sha256"] = "0" * 64
        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        with self.assertRaisesRegex(LockError, "SHA-256 mismatch"):
            load_verified_index(config)

    def test_resolver_uses_target_runtime_stdlib_inventory(self) -> None:
        self._write_project("import target_only_stdlib\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        resolution = resolve_assets(config, report)
        self.assertEqual(resolution.packs, ())
        payload = build_lock_payload(config, report, resolution)
        self.assertIn("target_only_stdlib", payload["runtime"]["stdlib_top_level_import_names"])

    def test_legacy_runtime_inventory_keeps_intrinsic_builtins(self) -> None:
        index = self._index()
        runtime = index["runtimes"]["cp313"]["metadata"]
        runtime["stdlib_top_level_import_names"] = ["target_only_stdlib"]
        self._write_project("import sys\n", index=index)
        config = load_project_config(self.root)
        resolution = resolve_assets(config, analyze_project(config))
        self.assertEqual(resolution.packs, ())

    def test_runtime_builtin_inventory_is_preserved_in_lock(self) -> None:
        index = self._index()
        runtime = index["runtimes"]["cp313"]["metadata"]
        runtime["stdlib_top_level_import_names"] = ["target_only_stdlib"]
        runtime["builtin_module_names"] = ["sys", "builtins"]
        self._write_project("import sys\n", index=index)
        config = load_project_config(self.root)
        report = analyze_project(config)
        payload = build_lock_payload(config, report, resolve_assets(config, report))
        self.assertEqual(payload["runtime"]["builtin_module_names"], ["sys", "builtins"])

    def test_target_runtime_builtin_is_not_an_unsupported_host_extension(self) -> None:
        self._write_project("import _ssl\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        self.assertIn("_ssl", report.unsupported_native_extensions)
        self.assertEqual(resolve_assets(config, report).packs, ())

    def test_locked_toolchain_requires_exact_recorded_versions(self) -> None:
        toolchain = MSVCToolchain(
            installation_path=self.root,
            environment={},
            cl=self.root / "cl.exe",
            link=self.root / "link.exe",
            lib=self.root / "lib.exe",
            dumpbin=self.root / "dumpbin.exe",
            msbuild=self.root / "msbuild.exe",
            visual_studio_version="17.0",
            vscmd_version="17.14.19",
            vc_tools_version="14.44.35207",
            windows_sdk_version="10.0.26100.0\\",
        )
        expected = {
            "visual_studio_version": "17.0",
            "vscmd_version": "17.14.19",
            "vc_tools_version": "14.44.35207",
            "windows_sdk_version": "10.0.26100.0",
            "platform_toolset": "v143",
            "runtime_library": "MultiThreaded",
        }
        self.assertEqual(locked_toolchain_mismatches(expected, toolchain), {})
        validate_locked_toolchain(expected, toolchain)
        expected["vscmd_version"] = "17.14.999"
        self.assertEqual(locked_toolchain_mismatches(expected, toolchain), {})
        expected["vc_tools_version"] = "14.43.34808"
        with self.assertRaisesRegex(BuildError, "does not match pysuture.lock"):
            validate_locked_toolchain(expected, toolchain)

    def test_pack_composition_rejects_link_time_table_collisions(self) -> None:
        runtime = {
            "frozen_module_names": ["json"],
            "builtin_module_registrations": [{"name": "_ssl"}],
        }
        first = {
            "descriptor_symbol": "StaticPython_Pack_first",
            "frozen_modules": ["demo.shared"],
            "builtin_modules": [],
            "resources": [{"path": "demo/data.bin"}],
        }
        second = {
            "descriptor_symbol": "StaticPython_Pack_second",
            "frozen_modules": ["demo.shared"],
            "builtin_modules": [],
            "resources": [],
        }
        with self.assertRaisesRegex(LockError, "frozen module.*conflicts"):
            validate_pack_composition(runtime, [("first", first), ("second", second)])

    def test_pack_runtime_contract_rejects_missing_locked_dependency(self) -> None:
        index = self._index()
        runtime = index["runtimes"]["cp313"]["metadata"]
        pack = index["packs"]["attrs"]["25.3.0"]["cp313"]["metadata"]
        pack["dependencies"] = ["missing"]
        with self.assertRaisesRegex(LockError, "dependencies are missing from the lock"):
            validate_pack_runtime_compatibility(
                runtime,
                [("attrs", pack)],
                staticpython_commit=index["staticpython_commit"],
            )

    def test_dependency_solver_backtracks_across_combined_constraints(self) -> None:
        index = self._index()

        def record(name: str, version: str, dependencies: list[str], constraint: str = "") -> dict:
            return {
                "filename": f"{name}-{version}.zip",
                "url": f"https://example.invalid/{name}-{version}.zip",
                "sha256": (name[0] * 64),
                "size": 1,
                "metadata": {
                    "name": name,
                    "version": version,
                    "runtime_abi": "staticpython-pack-v1-cp313",
                    "descriptor_symbol": f"StaticPython_Pack_{name}",
                    "dependencies": dependencies,
                    "dependency_constraints": {"c": constraint} if constraint else {},
                    "conflicts": [],
                },
            }

        index["packs"] = {
            "a": {
                "2.0": {"cp313": record("a", "2.0", ["c"], ">=2")},
                "1.0": {"cp313": record("a", "1.0", ["c"], "<2")},
            },
            "b": {"1.0": {"cp313": record("b", "1.0", ["c"], "<2")}},
            "c": {
                "2.5": {"cp313": record("c", "2.5", [])},
                "1.5": {"cp313": record("c", "1.5", [])},
            },
        }
        selected = _solve_pack_dependencies(index, "cp313", {"a": "", "b": ""})
        self.assertEqual({name: asset.version for name, asset in selected.items()}, {
            "a": "1.0",
            "b": "1.0",
            "c": "1.5",
        })

    def test_dependency_solver_accepts_pack_cycles(self) -> None:
        index = self._index()

        def record(name: str, dependencies: list[str]) -> dict:
            return {
                "filename": f"{name}-1.0.zip",
                "url": f"https://example.invalid/{name}-1.0.zip",
                "sha256": name * 64,
                "size": 1,
                "metadata": {
                    "name": name,
                    "version": "1.0",
                    "runtime_abi": "staticpython-pack-v1-cp313",
                    "descriptor_symbol": f"StaticPython_Pack_{name}",
                    "dependencies": dependencies,
                    "dependency_constraints": {},
                    "conflicts": [],
                },
            }

        index["packs"] = {
            "a": {"1.0": {"cp313": record("a", ["b"])}},
            "b": {"1.0": {"cp313": record("b", ["a"])}},
        }
        selected = _solve_pack_dependencies(index, "cp313", {"a": ""})
        self.assertEqual(set(selected), {"a", "b"})

    def test_resolver_rejects_unknown_dependency(self) -> None:
        self._write_project("import missing_dependency\n")
        config = load_project_config(self.root)
        with self.assertRaisesRegex(LockError, "no verified StaticPython pack"):
            resolve_assets(config, analyze_project(config))

    def test_private_package_scan_is_scoped_and_rejects_native_extensions(self) -> None:
        package_root = self.root / "site-packages" / "private_demo"
        package_root.mkdir(parents=True)
        (package_root / "__init__.py").write_text("from . import helper\n", encoding="utf-8")
        (package_root / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
        (package_root.parent / "unrelated.py").write_text("VALUE = 2\n", encoding="utf-8")
        spec = mock.Mock(submodule_search_locations=[str(package_root)], origin=str(package_root / "__init__.py"))
        with mock.patch("pysuture.analyzer.importlib.util.find_spec", return_value=spec):
            modules = _private_package_modules("private_demo")
        self.assertEqual(set(modules), {"private_demo", "private_demo.helper"})

        (package_root / "native_backend.pyd").write_bytes(b"not-a-real-extension")
        with mock.patch("pysuture.analyzer.importlib.util.find_spec", return_value=spec):
            with self.assertRaisesRegex(AnalysisError, "contains native extensions"):
                _private_package_modules("private_demo")

    def test_frozen_lock_detects_source_drift(self) -> None:
        self._write_project("import pkg\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        resolution = resolve_assets(config, report)
        payload = build_lock_payload(config, report, resolution)
        write_lock(self.root, payload)
        validate_lock_for_project(payload, report, frozen=True)
        (self.root / "pkg" / "helper.py").write_text("VALUE = 43\n", encoding="utf-8")
        changed = analyze_project(config)
        with self.assertRaisesRegex(LockError, "sources differ"):
            validate_lock_for_project(payload, changed, frozen=True)

    def test_existing_lock_rejects_python_and_pack_constraint_drift(self) -> None:
        self._write_project("import attrs\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        payload = build_lock_payload(config, report, resolve_assets(config, report))

        validate_lock_for_configuration(
            payload,
            replace(config, packages={"attrs": ">=25,<26"}),
        )
        with self.assertRaisesRegex(LockError, "targets Python 3.13.*requests 3.14"):
            validate_lock_for_configuration(payload, replace(config, python="3.14"))
        with self.assertRaisesRegex(LockError, "does not satisfy.*--update"):
            validate_lock_for_configuration(
                payload,
                replace(config, packages={"attrs": ">=26"}),
            )
        with self.assertRaisesRegex(LockError, "does not contain requested pack.*--update"):
            validate_lock_for_configuration(
                payload,
                replace(config, packages={"missing-pack": ""}),
            )
        duplicate = dict(payload)
        duplicate["packs"] = [
            *payload["packs"],
            {**payload["packs"][0], "name": payload["packs"][0]["name"].upper()},
        ]
        with self.assertRaisesRegex(LockError, "duplicate pack records"):
            validate_lock_for_configuration(duplicate, config)
        malformed = dict(payload)
        malformed["packs"] = None
        with self.assertRaisesRegex(LockError, "packs must be an array"):
            validate_lock_for_configuration(malformed, config)

        write_lock(self.root, payload)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = cli_main(
                ["lock", "--root", str(self.root), "--python", "3.14"]
            )
        self.assertEqual(result, 2)
        self.assertIn("run 'pysuture lock --update'", stderr.getvalue())

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = cli_main(
                ["build", "--root", str(self.root), "--python", "3.14", "--offline"]
            )
        self.assertEqual(result, 2)
        self.assertIn("run 'pysuture lock --update'", stderr.getvalue())

    def test_frozen_build_requires_preexisting_lock(self) -> None:
        self._write_project("pass\n")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = cli_main(["build", "--root", str(self.root), "--frozen-lock"])
        self.assertEqual(result, 2)
        self.assertIn("requires an existing pysuture.lock", stderr.getvalue())
        self.assertFalse((self.root / "pysuture.lock").exists())

    def test_secret_resource_is_rejected(self) -> None:
        self._write_project("pass\n")
        secret = self.root / ".env"
        secret.write_text("TOKEN=secret\n", encoding="utf-8")
        config = replace(
            load_project_config(self.root),
            data=(DataMapping(".env", "config/.env"),),
        )
        with self.assertRaisesRegex(BuildError, "credential"):
            collect_application_resources(config)

    def test_zip_extraction_rejects_parent_traversal(self) -> None:
        archive_path = self.root / "unsafe.zip"
        with ZipFile(archive_path, "w") as archive:
            archive.writestr("../escape.txt", "bad")
        with ZipFile(archive_path) as archive:
            with self.assertRaisesRegex(LockError, "unsafe path"):
                _safe_extract(archive, self.root / "extract")

    def test_zip_extraction_rejects_windows_unsafe_path(self) -> None:
        archive_path = self.root / "unsafe-windows.zip"
        with ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.txt:stream", "bad")
        with ZipFile(archive_path) as archive:
            with self.assertRaisesRegex(LockError, "unsafe Windows path"):
                _safe_extract(archive, self.root / "extract")

    def test_extract_asset_reuses_valid_manifest(self) -> None:
        archive_path, digest = self._write_asset_archive(
            [("sdk/include/Python.h", "header"), ("sdk/libs/python.lib", b"library")]
        )
        cache = self.root / "cache"
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(cache)}):
            first = extract_asset(archive_path, digest)
            marker = json.loads((first / ".pysuture-extracted.json").read_text(encoding="utf-8"))
            self.assertEqual(marker["manifest_version"], 1)
            self.assertEqual(
                [entry["path"] for entry in marker["files"]],
                ["sdk/include/Python.h", "sdk/libs/python.lib"],
            )
            with mock.patch("pysuture.cache._publish_extracted_cache") as publish:
                second = extract_asset(archive_path, digest)
            publish.assert_not_called()
        self.assertEqual(first, second)

    def test_extract_asset_rebuilds_tampered_file(self) -> None:
        archive_path, digest = self._write_asset_archive([("payload/data.bin", b"verified")])
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(self.root / "cache")}):
            extracted = extract_asset(archive_path, digest)
            target = extracted / "payload" / "data.bin"
            target.write_bytes(b"tampered")
            rebuilt = extract_asset(archive_path, digest)
        self.assertEqual(rebuilt, extracted)
        self.assertEqual(target.read_bytes(), b"verified")

    def test_extract_asset_rebuilds_truncated_file(self) -> None:
        archive_path, digest = self._write_asset_archive([("payload/data.bin", b"verified")])
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(self.root / "cache")}):
            extracted = extract_asset(archive_path, digest)
            target = extracted / "payload" / "data.bin"
            target.write_bytes(b"ver")
            extract_asset(archive_path, digest)
        self.assertEqual(target.read_bytes(), b"verified")

    def test_extract_asset_rebuilds_deleted_file(self) -> None:
        archive_path, digest = self._write_asset_archive([("payload/data.bin", b"verified")])
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(self.root / "cache")}):
            extracted = extract_asset(archive_path, digest)
            target = extracted / "payload" / "data.bin"
            target.unlink()
            extract_asset(archive_path, digest)
        self.assertEqual(target.read_bytes(), b"verified")

    def test_extract_asset_rebuilds_cache_with_extra_file(self) -> None:
        archive_path, digest = self._write_asset_archive([("payload/data.bin", b"verified")])
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(self.root / "cache")}):
            extracted = extract_asset(archive_path, digest)
            extra = extracted / "unexpected.txt"
            extra.write_text("not in archive", encoding="utf-8")
            extract_asset(archive_path, digest)
        self.assertFalse(extra.exists())

    def test_extract_asset_rejects_forged_file_manifest(self) -> None:
        archive_path, digest = self._write_asset_archive([("payload/data.bin", b"verified")])
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(self.root / "cache")}):
            extracted = extract_asset(archive_path, digest)
            target = extracted / "payload" / "data.bin"
            target.write_bytes(b"tampered")
            marker_path = extracted / ".pysuture-extracted.json"
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            marker["files"][0].update(
                size=len(b"tampered"),
                sha256=sha256_bytes(b"tampered"),
            )
            marker_path.write_text(json.dumps(marker), encoding="utf-8")
            extract_asset(archive_path, digest)
        self.assertEqual(target.read_bytes(), b"verified")

    def test_extract_asset_rejects_duplicate_normalized_members(self) -> None:
        archive_path, digest = self._write_asset_archive(
            [("Payload/data.bin", b"first"), ("payload/data.bin", b"second")]
        )
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(self.root / "cache")}):
            with self.assertRaisesRegex(LockError, "duplicate archive member"):
                extract_asset(archive_path, digest)

    def test_extract_asset_serializes_concurrent_initialization(self) -> None:
        archive_path, digest = self._write_asset_archive([("payload/data.bin", b"verified")])
        with mock.patch.dict(os.environ, {"PYSUTURE_CACHE_DIR": str(self.root / "cache")}):
            with ThreadPoolExecutor(max_workers=4) as executor:
                extracted = list(executor.map(lambda _index: extract_asset(archive_path, digest), range(4)))
        self.assertTrue(all(path == extracted[0] for path in extracted))
        self.assertEqual((extracted[0] / "payload" / "data.bin").read_bytes(), b"verified")

    def test_extracted_cache_publish_restores_previous_tree_on_failure(self) -> None:
        workspace = self.root / "workspace"
        staging = workspace / "payload"
        destination = self.root / "extracted"
        staging.mkdir(parents=True)
        destination.mkdir()
        (staging / "new.txt").write_text("new", encoding="utf-8")
        (destination / "old.txt").write_text("old", encoding="utf-8")
        original_replace = Path.replace

        def replace_with_failure(source: Path, target: Path) -> Path:
            if source == staging:
                raise OSError("injected publish failure")
            return original_replace(source, target)

        with mock.patch.object(Path, "replace", autospec=True, side_effect=replace_with_failure):
            with self.assertRaisesRegex(LockError, "could not publish extracted cache"):
                _publish_extracted_cache(staging, destination, workspace)

        self.assertEqual((destination / "old.txt").read_text(encoding="utf-8"), "old")
        self.assertFalse((destination / "new.txt").exists())

    def test_cython_generates_unique_init_and_launcher_has_no_generic_entry(self) -> None:
        self._write_project("if __name__ == '__main__':\n    print('ok')\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        units, warnings = cythonize_modules(report, self.root / ".pysuture" / "test", installed_cython_version())
        self.assertTrue(all(unit.init_symbol.startswith("PyInit_pysuture_") for unit in units))
        launcher = write_launcher(
            self.root / ".pysuture" / "test" / "launcher.c",
            units=units,
            entry_module=report.entry_module,
            entry_callable=None,
            namespace_packages=report.namespace_packages,
            pack_symbols=[],
            resources=[],
            windowed=False,
        )
        text = launcher.read_text(encoding="utf-8")
        self.assertIn("config.parse_argv = 0", text)
        self.assertIn("&config.stdio_encoding, L\"utf-8\"", text)
        self.assertIn("&config.stdio_errors, L\"strict\"", text)
        self.assertIn("--multiprocessing-fork", text)
        self.assertIn("return argc == 4", text)
        self.assertIn('L"parent_pid="', text)
        self.assertIn('L"pipe_handle="', text)
        self.assertIn("wmain(int argc", text)
        self.assertNotIn("Py_Main(", text)
        self.assertNotIn("Py_RunMain(", text)
        prepared = next(unit.prepared_source for unit in units if unit.module.name == "app")
        prepared_text = prepared.read_text(encoding="utf-8")
        self.assertIn("freeze_support", prepared_text)

    def test_root_dunder_main_registers_one_builtin_entry(self) -> None:
        self._write_project("print('ok')\n")
        (self.root / "app.py").rename(self.root / "__main__.py")
        project_path = self.root / "pyproject.toml"
        project_path.write_text(
            project_path.read_text(encoding="utf-8").replace('entry = "app.py"', 'entry = "__main__.py"'),
            encoding="utf-8",
        )
        config = load_project_config(self.root)
        report = analyze_project(config)
        units, _warnings = cythonize_modules(
            report,
            self.root / ".pysuture" / "dunder-main",
            installed_cython_version(),
        )
        launcher = write_launcher(
            self.root / ".pysuture" / "dunder-main" / "launcher.c",
            units=units,
            entry_module=report.entry_module,
            entry_callable=None,
            namespace_packages=report.namespace_packages,
            pack_symbols=[],
            resources=[],
            windowed=False,
        )
        self.assertEqual(launcher.read_text(encoding="utf-8").count('{"__main__",'), 1)

    def test_init_preserves_existing_pyproject(self) -> None:
        (self.root / "app.py").write_text("pass\n", encoding="utf-8")
        (self.root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
        initialize_project(self.root, "app.py", "3.13", "console", None)
        text = (self.root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[project]", text)
        self.assertIn("[tool.pysuture]", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
