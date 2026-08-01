from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .cache import cache_root
from .errors import BuildError


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
    windows_sdk_version: str | None

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
            "visual_studio_version": self.visual_studio_version,
            "windows_sdk_version": self.windows_sdk_version,
            "cl_path": str(self.cl),
            "cl_banner": result.stdout.strip(),
            "platform_toolset": "v143",
            "runtime_library": "MultiThreaded",
        }


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
    command = f'"{devcmd}" -no_logo -arch=amd64 -host_arch=amd64 && set'
    result = subprocess.run(
        ["cmd.exe", "/d", "/s", "/c", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise BuildError(f"could not initialize the VS 2022 environment: {result.stderr.strip()}")
    environment = dict(os.environ)
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        if separator and name:
            environment[name] = value
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
        visual_studio_version=environment.get("VisualStudioVersion"),
        windows_sdk_version=environment.get("WindowsSDKVersion"),
    )


def doctor_report(lock: dict | None = None) -> dict:
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
    if lock is not None:
        locked_toolchain = lock.get("toolchain", {})
        expected = locked_toolchain.get("platform_toolset")
        actual = "v143" if toolchain is not None else None
        checks.append(
            {
                "name": "locked-toolset",
                "status": "passed" if expected in {None, actual} else "failed",
                "detail": {"expected": expected, "actual": actual},
            }
        )
    return {
        "status": "passed" if all(check["status"] == "passed" for check in checks) else "failed",
        "checks": checks,
    }
