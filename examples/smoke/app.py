from __future__ import annotations

import json
import multiprocessing
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


def square(value: int) -> int:
    return value * value


def queue_worker(queue) -> None:
    queue.put(("child", sys.argv[1:]))


def self_test() -> int:
    payload = json.loads(Path("assets/payload.json").read_text(encoding="utf-8"))
    if payload != {"message": "静态资源", "ok": True}:
        return 10
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    process = context.Process(target=queue_worker, args=(queue,))
    process.start()
    child, arguments = queue.get(timeout=30)
    process.join(timeout=30)
    if process.exitcode != 0 or child != "child" or arguments != sys.argv[1:]:
        return 11
    with context.Pool(2) as pool:
        if pool.map(square, [2, 3, 4]) != [4, 9, 16]:
            return 12
    with ProcessPoolExecutor(max_workers=2, mp_context=context) as executor:
        if list(executor.map(square, [5, 6])) != [25, 36]:
            return 13
    print(json.dumps({"argv": sys.argv[1:], "resource": payload}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test() if "--self-test" in sys.argv else 0)
