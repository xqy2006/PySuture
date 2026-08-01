# PySuture

PySuture turns a Python application into one statically linked Windows x64
executable. Project modules are compiled with a lock-pinned Cython, CPython and
integrated native dependencies come from hash-verified
[StaticPython](https://github.com/xqy2006/StaticPython) SDK/packs, and the final
program does not extract files at runtime.

This repository is pre-release software. A build requires Visual Studio 2022
Build Tools with the MSVC v143 C++ toolset and a Windows SDK. The generated
program is designed not to require Python, the Visual C++ redistributable,
Python DLLs, `.pyd` files, or third-party DLLs on the target machine.

```powershell
python -m pip install -e ".[build]"
pysuture init --entry app.py
pysuture analyze
pysuture lock
pysuture build --frozen-lock
```

`pysuture.lock` pins the exact StaticPython commit, CPython patch version,
runtime ABI, SDK and pack SHA-256 values, Cython version, and toolchain. Normal
builds strictly reuse it; only `pysuture lock --update` changes dependencies.

The `full` StaticPython profile is a conflict-regression test. PySuture never
downloads or links it and never falls back to it.
