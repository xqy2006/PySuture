# PySuture

PySuture builds a Python application as one statically linked Windows x64
executable that does not extract files at runtime. Every reachable project
module is compiled with a lock-pinned Cython. CPython, the frozen standard
library, native extensions, package resources, and third-party static libraries
come from hash-verified [StaticPython](https://github.com/xqy2006/StaticPython)
SDK and pack assets.

PySuture is pre-release software. The build machine needs Visual Studio 2022
Build Tools, the MSVC v143 C++ toolset, and a Windows SDK. The target machine is
designed not to need Python, the Visual C++ redistributable, `python*.dll`,
`.pyd` files, or third-party DLLs.

## Quick start

```powershell
python -m pip install -e ".[build]"
pysuture init --entry app.py --python 3.13 --mode console
pysuture doctor
pysuture analyze
pysuture lock
pysuture build --frozen-lock
```

The default output is `dist/<name>.exe`. PDB, map, response, generated C, and
audit reports remain under `.pysuture/build`; the distribution directory
contains only the executable.

## Project configuration

`pysuture init` adds a minimal section to `pyproject.toml`. A complete example
looks like this:

```toml
[tool.pysuture]
entry = "app.py"                 # or "app.py:main"
python = "3.13"                  # 3.11, 3.12, 3.13, 3.14, or 3.15
mode = "console"                 # console or windowed
output = "my-application"
source-roots = ["."]
include-modules = ["plugins.csv_backend"]
include-packages = ["private_pure_python_package"]
secret-policy = "error"         # error, warn, or allow
data = [
  { source = "assets/**/*.json", target = "assets/" },
]

[tool.pysuture.packages]
requests = ">=2.32,<3"
```

`include-modules` declares concrete dynamic imports. `include-packages` freezes
an installed pure-Python dependency into the application-private module set;
packages containing native extensions are rejected and need a StaticPython
pack. Data mappings create read-only virtual resources. `.env`, private-key,
and credential-like files are rejected by default.

Entry files and `source-roots` must be relative paths contained by the project
root. Module declarations use fully qualified Python names, and `output` is a
Windows-safe filename stem (without `.exe`). `pysuture init` parses an existing
`pyproject.toml` before changing it and emits escaped, valid TOML.

## Commands

- `pysuture init` creates `[tool.pysuture]` without replacing an existing
  project configuration.
- `pysuture analyze` prints the reachable module graph, selected StaticPython
  packs, unresolved dynamic imports, and unsupported native extensions. Use
  `--json` for automation.
- `pysuture lock` creates `pysuture.lock` from PySuture's reviewed runtime
  catalog, which points to an immutable, hash-pinned StaticPython index only
  after all five Python targets pass the PySuture E2E matrix. An existing lock
  is reused; only `lock --update` changes the runtime or packages.
- `pysuture build` Cythonizes, compiles, links, and audits the executable.
  `--offline` forbids downloads and `--frozen-lock` additionally rejects project
  source drift, making it suitable for CI.
- `pysuture doctor` checks VS 2022, MSVC, the Windows SDK, cache state, and exact
  lock/toolchain compatibility.

Build-time overrides include `--python`, `--mode`, `--output`, repeated
`--include-module`, repeated `--include-package`, and repeated
`--include-data SOURCE=VIRTUAL/TARGET`.

## Locking and runtime guarantees

`pysuture.lock` pins the CPython patch version, StaticPython commit, runtime ABI,
every SDK and pack URL/SHA-256, package version, Cython version, and exact MSVC
toolchain. Pack dependencies, conflicts, licenses, validation status, CPython
source commit, and link-compatible toolchain fields are rechecked both while
locking and after extracting the cached build assets. The recorded
`vscmd_version` remains provenance rather than an object/link ABI gate.
Descriptor symbols, source lists, libraries, and other build metadata must
exactly match the metadata inside the hash-verified asset; the lock file cannot
override archive contents.

The generated PEP 587 launcher is isolated from environment and user-site
injection, preserves Unicode application arguments, and does not expose CPython
`-c`, `-m`, REPL, IDLE, or generic script execution. Console and windowed entry
points share the same runtime. Windows multiprocessing child and resource
tracker signatures are dispatched before the application entry point; other
arguments pass through unchanged.

StaticPython's `full` profile is only a scheduled all-library link/conflict
regression. PySuture never downloads it, links it, or falls back to it.
The default catalog is updated through a reviewable PR; user builds therefore
do not follow StaticPython `master` or a newly published but not yet
PySuture-validated prerelease. An explicit `index-url` remains available for
integration development and offline mirrors.

## License

PySuture is Apache-2.0. CPython and third-party components keep their own
licenses and notices; applicable notices are embedded from the exact locked
runtime and package assets.
