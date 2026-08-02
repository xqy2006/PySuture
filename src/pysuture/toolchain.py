from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .cache import cache_root
from .errors import BuildError, LockError
from .lockfile import validate_asset_records


@dataclass(frozen=True)
class MSVCToolchain:
    installation_path: Path
    environment: dict[str, str]
    cl: Path
    link: Path
    lib: Path
    dumpbin: Path
    msbuild: Path
    visual_studio_version: str | None
    vscmd_version: str | None
    vc_tools_version: str | None
    windows_sdk_version: str | None

    def identity(self) -> dict:
        return {
            "visual_studio_version": self.visual_studio_version,
            "vscmd_version": self.vscmd_version,
            "vc_tools_version": self.vc_tools_version,
            "windows_sdk_version": self.windows_sdk_version,
            "platform_toolset": "v143",
            "runtime_library": "MultiThreaded",
        }

    def fingerprint(self) -> dict:
        result = subprocess.run(
            [str(self.cl), "/Bv"],
            env=self.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return {
            **self.identity(),
            "cl_path": str(self.cl),
            "cl_banner": result.stdout.strip(),
        }


def _normalized_identity_value(value: object) -> str:
    return str(value or "").strip().rstrip("\\/").casefold()


def locked_toolchain_mismatches(expected: dict, actual: MSVCToolchain) -> dict[str, dict[str, str | None]]:
    if not isinstance(expected, dict):
        raise BuildError("pysuture.lock toolchain must be an object")
    actual_identity = actual.identity()
    mismatches = {}
    for field in (
        "visual_studio_version",
        "vc_tools_version",
        "windows_sdk_version",
        "platform_toolset",
        "runtime_library",
    ):
        expected_value = expected.get(field)
        if expected_value is None or expected_value == "":
            continue
        if not isinstance(expected_value, str):
            raise BuildError(f"pysuture.lock toolchain field {field} must be a string")
        actual_value = actual_identity.get(field)
        if _normalized_identity_value(expected_value) != _normalized_identity_value(actual_value):
            mismatches[field] = {"expected": str(expected_value), "actual": actual_value}
    return mismatches


def validate_locked_toolchain(expected: dict, actual: MSVCToolchain) -> None:
    mismatches = locked_toolchain_mismatches(expected, actual)
    if mismatches:
        details = ", ".join(
            f"{field}={values['actual']!r} (locked {values['expected']!r})"
            for field, values in sorted(mismatches.items())
        )
        raise BuildError(f"installed MSVC toolchain does not match pysuture.lock: {details}")


def _vswhere_path() -> Path | None:
    candidates = []
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if program_files_x86:
        candidates.append(Path(program_files_x86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe")
    found = shutil.which("vswhere")
    if found:
        candidates.append(Path(found))
    return next((path for path in candidates if path.is_file()), None)


def _installation_path() -> Path:
    vswhere = _vswhere_path()
    if vswhere is None:
        raise BuildError("vswhere.exe was not found; install Visual Studio 2022 Build Tools")
    result = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    path = Path(result.stdout.strip())
    if result.returncode != 0 or not path.is_dir():
        raise BuildError("Visual Studio 2022 C++ Build Tools were not found")
    return path


def _developer_environment(installation: Path) -> dict[str, str]:
    devcmd = installation / "Common7" / "Tools" / "VsDevCmd.bat"
    if not devcmd.is_file():
        raise BuildError(f"Visual Studio developer command script is missing: {devcmd}")
    # Passing this embedded command as an argv element makes Python quote the
    # inner batch-file path for CreateProcess instead of for cmd.exe.  Invoke
    # it through the Windows command shell; `call` then guarantees execution
    # continues after the batch file so `set` can print the new environment.
    command = f'call "{devcmd}" -no_logo -arch=amd64 -host_arch=amd64 && set'
    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildError("Visual Studio developer environment initialization timed out") from exc
    if result.returncode != 0:
        raise BuildError(f"could not initialize the VS 2022 environment: {result.stderr.strip()}")
    # Windows environment names are case-insensitive, while a Python dict is
    # not.  VsDevCmd commonly prints `Path=` even when the inherited mapping
    # contains `PATH=`, leaving two entries and making discovery use the stale
    # one unless keys are normalized.
    environment = {name.upper(): value for name, value in os.environ.items()}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        if separator and name:
            environment[name.upper()] = value
    return environment


def _tool(name: str, environment: dict[str, str]) -> Path:
    path = shutil.which(name, path=environment.get("PATH"))
    if not path:
        raise BuildError(f"{name} was not found in the VS 2022 developer environment")
    return Path(path).resolve()


def discover_msvc() -> MSVCToolchain:
    if sys.platform != "win32":
        raise BuildError("PySuture v1 builds Windows x64 executables and must run on Windows")
    installation = _installation_path()
    environment = _developer_environment(installation)
    return MSVCToolchain(
        installation_path=installation,
        environment=environment,
        cl=_tool("cl.exe", environment),
        link=_tool("link.exe", environment),
        lib=_tool("lib.exe", environment),
        dumpbin=_tool("dumpbin.exe", environment),
        msbuild=_tool("msbuild.exe", environment),
        visual_studio_version=environment.get("VISUALSTUDIOVERSION"),
        vscmd_version=environment.get("VSCMD_VER"),
        vc_tools_version=environment.get("VCTOOLSVERSION"),
        windows_sdk_version=environment.get("WINDOWSSDKVERSION"),
    )


def doctor_report(lock: dict | None = None, *, lock_error: str | None = None) -> dict:
    checks: list[dict] = []
    try:
        toolchain = discover_msvc()
    except BuildError as exc:
        checks.append({"name": "vs2022", "status": "failed", "detail": str(exc)})
        toolchain = None
    else:
        checks.append(
            {
                "name": "vs2022",
                "status": "passed",
                "detail": str(toolchain.installation_path),
            }
        )
        checks.append(
            {
                "name": "windows-sdk",
                "status": "passed" if toolchain.windows_sdk_version else "failed",
                "detail": toolchain.windows_sdk_version,
            }
        )
    cache = cache_root()
    try:
        cache.mkdir(parents=True, exist_ok=True)
        probe = cache / ".write-probe"
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        checks.append({"name": "cache", "status": "failed", "detail": str(exc)})
    else:
        checks.append({"name": "cache", "status": "passed", "detail": str(cache)})
    if lock_error is not None:
        checks.append({"name": "lock", "status": "failed", "detail": lock_error})
    elif lock is None:
        checks.append(
            {
                "name": "lock",
                "status": "skipped",
                "detail": "pysuture.lock does not exist",
            }
        )
    else:
        try:
            validate_asset_records(lock)
        except LockError as exc:
            checks.append({"name": "lock", "status": "failed", "detail": str(exc)})
        else:
            checks.append(
                {
                    "name": "lock",
                    "status": "passed",
                    "detail": f"{1 + len(lock['packs'])} immutable asset record(s)",
                }
            )
    if lock is not None:
        locked_toolchain = lock.get("toolchain", {})
        try:
            mismatches = (
                locked_toolchain_mismatches(locked_toolchain, toolchain)
                if toolchain is not None
                else {"toolchain": {"expected": "available", "actual": None}}
            )
        except BuildError as exc:
            checks.append({"name": "locked-toolchain", "status": "failed", "detail": str(exc)})
        else:
            checks.append(
                {
                    "name": "locked-toolchain",
                    "status": "passed" if not mismatches else "failed",
                    "detail": mismatches or toolchain.identity(),
                }
            )
    return {
        "status": "failed" if any(check["status"] == "failed" for check in checks) else "passed",
        "checks": checks,
    }
