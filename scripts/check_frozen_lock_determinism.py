from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REQUIRED_IDENTICAL_ARTIFACTS = ("executable", "map")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(arguments: list[str], *, root: Path, environment: dict[str, str]) -> None:
    command = [sys.executable, "-m", "pysuture", *arguments, "--root", str(root)]
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.stdout.strip():
        print(result.stdout.rstrip())
    if result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(command)} failed with exit code {result.returncode}"
        )


def _copy_project(template: Path, destination: Path, index: Path) -> None:
    shutil.copytree(
        template,
        destination,
        ignore=shutil.ignore_patterns(
            ".pysuture",
            "dist",
            "pysuture.lock",
            "runtime-index.v1.json",
            "__pycache__",
            "*.pyc",
        ),
    )
    shutil.copy2(index, destination / "runtime-index.v1.json")


def _build_artifacts(project: Path, output: str) -> dict[str, Path]:
    reports = list((project / ".pysuture" / "build").glob("*/build-report.json"))
    if len(reports) != 1:
        raise RuntimeError(
            f"expected one build report below {project}, found {len(reports)}"
        )
    payload = json.loads(reports[0].read_text(encoding="utf-8"))
    if payload.get("status") != "passed":
        raise RuntimeError(f"build report did not pass: {reports[0]}")
    executable = project / "dist" / f"{output}.exe"
    artifacts = payload.get("artifacts", {})
    result = {
        "executable": executable,
        "map": Path(artifacts.get("map", "")),
        "pdb": Path(artifacts.get("pdb", "")),
        "report": reports[0],
    }
    missing = [name for name, path in result.items() if not path.is_file()]
    if missing:
        raise RuntimeError(f"build is missing artifact(s): {', '.join(missing)}")
    return result


def _work_root(argument: Path | None) -> tuple[Path, bool]:
    if argument is None:
        return Path(tempfile.mkdtemp(prefix="pysuture-frozen-lock-determinism-")), True
    root = argument.resolve()
    if root.exists() and any(root.iterdir()):
        raise RuntimeError(f"determinism work root must be empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    return root, False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build one frozen PySuture lock under two roots and compare artifacts"
    )
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--python", default="3.13")
    parser.add_argument("--mode", choices=("console", "windowed"), default="console")
    parser.add_argument("--output", default="pysuture-determinism")
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)

    template = args.project.resolve()
    index = args.index.resolve()
    if not template.is_dir():
        parser.error(f"project template is not a directory: {template}")
    if not index.is_file():
        parser.error(f"runtime index is not a file: {index}")

    work_root, temporary = _work_root(args.work_root)
    first = work_root / "first-location" / "project"
    second = work_root / "second-location-with-a-different-length" / "project"
    environment = os.environ.copy()
    environment["PYSUTURE_CACHE_DIR"] = str(work_root / "shared-cache")
    try:
        _copy_project(template, first, index)
        _copy_project(template, second, index)
        _run(["lock", "--update", "--python", args.python], root=first, environment=environment)
        first_lock = first / "pysuture.lock"
        locked_bytes = first_lock.read_bytes()
        (second / "pysuture.lock").write_bytes(locked_bytes)

        common_build = [
            "build",
            "--python",
            args.python,
            "--mode",
            args.mode,
            "--output",
            args.output,
            "--frozen-lock",
        ]
        _run(common_build, root=first, environment=environment)
        _run([*common_build, "--offline"], root=second, environment=environment)

        for project in (first, second):
            if (project / "pysuture.lock").read_bytes() != locked_bytes:
                raise RuntimeError(f"frozen build mutated pysuture.lock below {project}")

        first_artifacts = _build_artifacts(first, args.output)
        second_artifacts = _build_artifacts(second, args.output)
        first_report = json.loads(first_artifacts["report"].read_text(encoding="utf-8"))
        second_report = json.loads(second_artifacts["report"].read_text(encoding="utf-8"))
        if first_report.get("build_id") != second_report.get("build_id"):
            raise RuntimeError(
                "identical frozen locks produced different build identities: "
                f"{first_report.get('build_id')} != {second_report.get('build_id')}"
            )

        hashes = {
            name: (_sha256(first_artifacts[name]), _sha256(second_artifacts[name]))
            for name in ("executable", "map", "pdb")
        }
        mismatches = {
            name: pair
            for name, pair in hashes.items()
            if pair[0] != pair[1] and name in REQUIRED_IDENTICAL_ARTIFACTS
        }
        if mismatches:
            raise RuntimeError(
                "the same frozen lock produced different final artifacts across roots: "
                f"{mismatches}"
            )
        print(f"frozen lock SHA-256: {hashlib.sha256(locked_bytes).hexdigest()}")
        for name, (first_hash, second_hash) in hashes.items():
            if first_hash == second_hash:
                print(f"deterministic {name} SHA-256: {first_hash}")
            else:
                print(f"non-gated {name} differs: {first_hash} != {second_hash}")
        return 0
    except Exception:
        print(f"retained frozen-lock diagnostics at {work_root}", file=sys.stderr)
        raise
    finally:
        if temporary and not args.keep and sys.exc_info()[0] is None:
            shutil.rmtree(work_root)


if __name__ == "__main__":
    raise SystemExit(main())
