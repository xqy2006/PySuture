from __future__ import annotations

import json
import contextlib
import io
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
from pysuture.cache import _safe_extract, sha256_bytes
from pysuture.cli import main as cli_main
from pysuture.config import DataMapping, initialize_project, load_project_config
from pysuture.cythonizer import cythonize_modules, installed_cython_version
from pysuture.errors import AnalysisError, BuildError, LockError
from pysuture.launcher import write_launcher
from pysuture.lockfile import validate_lock_for_project, write_lock
from pysuture.resolver import (
    _solve_pack_dependencies,
    build_lock_payload,
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

    def test_resolver_uses_target_runtime_stdlib_inventory(self) -> None:
        self._write_project("import target_only_stdlib\n")
        config = load_project_config(self.root)
        report = analyze_project(config)
        resolution = resolve_assets(config, report)
        self.assertEqual(resolution.packs, ())
        payload = build_lock_payload(config, report, resolution)
        self.assertIn("target_only_stdlib", payload["runtime"]["stdlib_top_level_import_names"])

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
