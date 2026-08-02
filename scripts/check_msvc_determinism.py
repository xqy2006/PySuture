from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from pysuture.builder import _compile_source, _write_response  # noqa: E402
from pysuture.toolchain import MSVCToolchain, discover_msvc  # noqa: E402


PROBE_SOURCE = """\
#include "determinism_header.h"

static const char pysuture_source_path[] = __FILE__;

int pysuture_determinism_probe(void)
{
    return pysuture_source_path[0] == '\\0' || pysuture_header_path[0] == '\\0';
}
"""

PROBE_HEADER = """\
static const char pysuture_header_path[] = __FILE__;
"""
# `/Z7` deliberately retains complete source-level debug records in each object
# so the final linker PDB remains useful. MSVC toolset revisions may serialize
# those intermediate records differently even when the linked image and map are
# byte-identical, so the distribution and stable diagnostic artifacts are the
# reproducibility gate. Object hashes remain visible as diagnostics below.
REQUIRED_REPRODUCIBLE_ARTIFACTS = ("executable", "map")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _compile_probe(toolchain: MSVCToolchain, root: Path) -> tuple[dict[str, str], str]:
    project_root = root / "project"
    build_dir = project_root / ".pysuture" / "build"
    source = project_root / "src" / "determinism_probe.c"
    include_dir = root / "immutable-sdk" / "include"
    source.parent.mkdir(parents=True)
    include_dir.mkdir(parents=True)
    build_dir.mkdir(parents=True)
    source.write_text(PROBE_SOURCE, encoding="utf-8", newline="\n")
    (include_dir / "determinism_header.h").write_text(PROBE_HEADER, encoding="utf-8", newline="\n")
    object_dir = build_dir / "obj"
    object_dir.mkdir()
    object_path, output = _compile_source(
        toolchain,
        source,
        object_dir / "determinism_probe.obj",
        build_dir / "rsp" / "determinism_probe.rsp",
        [include_dir],
        (),
        project_root,
        build_dir,
    )
    if "D9007" in output or "pathmap" in output.casefold():
        raise RuntimeError(f"MSVC rejected deterministic path mapping:\n{output}")
    executable = build_dir / "determinism_probe.exe"
    linker_pdb = build_dir / "determinism_probe.pdb"
    arguments = [
        "/NOLOGO",
        "/OUT:determinism_probe.exe",
        "/MAP:determinism_probe.map",
        "/PDB:determinism_probe.pdb",
        "/PDBALTPATH:%_PDB%",
        "/DEBUG:FULL",
        "/LTCG",
        "/OPT:REF",
        "/OPT:ICF",
        "/INCREMENTAL:NO",
        "/DYNAMICBASE",
        "/NXCOMPAT",
        "/HIGHENTROPYVA",
        "/Brepro",
        "/SUBSYSTEM:CONSOLE",
        "/ENTRY:pysuture_determinism_probe",
        "/NODEFAULTLIB",
        r"obj\determinism_probe.obj",
    ]
    response = _write_response(build_dir / "rsp" / "determinism_link.rsp", arguments)
    link = subprocess.run(
        [str(toolchain.link), f"@{response.relative_to(build_dir)}"],
        cwd=build_dir,
        env=toolchain.environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if link.returncode != 0:
        raise RuntimeError(f"MSVC deterministic probe link failed:\n{link.stdout}")
    map_path = build_dir / "determinism_probe.map"
    if not linker_pdb.is_file() or linker_pdb.stat().st_size == 0:
        raise RuntimeError("MSVC deterministic probe did not retain a linker PDB")
    return {
        "object": _sha256(object_path),
        "executable": _sha256(executable),
        "map": _sha256(map_path),
    }, "\n".join(part for part in (output.strip(), link.stdout.strip()) if part)


def main() -> int:
    toolchain = discover_msvc()
    root = Path(tempfile.mkdtemp(prefix="pysuture-determinism-"))
    try:
        first, first_output = _compile_probe(toolchain, root / "first-location")
        second, second_output = _compile_probe(toolchain, root / "second-location")
        mismatches = {
            artifact: (first[artifact], second[artifact])
            for artifact in first
            if first[artifact] != second[artifact]
        }
        required_mismatches = {
            artifact: digests
            for artifact, digests in mismatches.items()
            if artifact in REQUIRED_REPRODUCIBLE_ARTIFACTS
        }
        if required_mismatches:
            raise RuntimeError(
                "identical sources produced different final MSVC artifacts after path "
                f"normalization: {required_mismatches}"
            )
        for artifact, first_digest in first.items():
            second_digest = second[artifact]
            if first_digest == second_digest:
                print(f"MSVC deterministic {artifact} SHA-256: {first_digest}")
            else:
                print(
                    f"MSVC intermediate {artifact} hashes differ while final artifacts match: "
                    f"{first_digest} != {second_digest}"
                )
        for output in (first_output, second_output):
            if output.strip():
                print(output.strip())
        shutil.rmtree(root)
        return 0
    except Exception:
        print(f"retained deterministic-build diagnostics at {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
