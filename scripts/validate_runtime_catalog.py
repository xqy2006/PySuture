from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from pysuture.constants import SUPPORTED_PYTHON_SERIES
from pysuture.resolver import load_verified_index_url


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate PySuture's reviewed runtime catalog")
    parser.add_argument("catalog", type=Path, nargs="?", default=REPO_ROOT / "runtime-catalog.lock.json")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    index, digest = load_verified_index_url(str(args.catalog.resolve()), offline=args.offline)
    expected = {"cp" + series.replace(".", "") for series in SUPPORTED_PYTHON_SERIES}
    if set(index.get("runtimes", {})) != expected:
        raise RuntimeError("reviewed index does not contain exactly CPython 3.11 through 3.15")
    print(f"validated reviewed StaticPython {index['staticpython_commit']} ({digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
