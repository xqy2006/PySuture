from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Update PySuture's reviewed StaticPython catalog pointer")
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("runtime-catalog.lock.json"))
    parser.add_argument("--repository", default="xqy2006/StaticPython")
    args = parser.parse_args()
    raw = args.index.read_bytes()
    index = json.loads(raw.decode("utf-8"))
    if index.get("schema_version") != 1 or index.get("status") != "verified":
        raise RuntimeError("candidate index is not a verified StaticPython index v1")
    runtimes = index.get("runtimes", {})
    expected = {"cp311", "cp312", "cp313", "cp314", "cp315"}
    if set(runtimes) != expected:
        raise RuntimeError("candidate index does not contain exactly cp311 through cp315")
    runtime_tag = index["runtime_release_tag"]
    payload = {
        "schema_version": 1,
        "staticpython_repository": args.repository,
        "staticpython_commit": index["staticpython_commit"],
        "index_url": (
            f"https://github.com/{args.repository}/releases/download/"
            f"{runtime_tag}/runtime-index.v1.json"
        ),
        "index_sha256": hashlib.sha256(raw).hexdigest(),
        "runtimes": {
            abi: {
                "cpython_version": record["metadata"]["cpython_version"],
                "runtime_abi": record["metadata"]["runtime_abi"],
                "sha256": record["sha256"],
            }
            for abi, record in sorted(runtimes.items())
        },
        "pack_count": sum(
            len(by_abi)
            for versions in index.get("packs", {}).values()
            for by_abi in versions.values()
        ),
    }
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"updated {args.output} for StaticPython {index['staticpython_commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
