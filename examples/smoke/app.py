from __future__ import annotations

import email
import importlib.util
import json
import multiprocessing
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import attrs
import regex
import smoke_ns
from smoke_ns.child.probe import namespace_value


@attrs.define(frozen=True)
class SmokeRecord:
    message: str
    ok: bool


def square(value: int) -> int:
    return value * value


def queue_worker(queue) -> None:
    queue.put(("child", sys.argv[1:]))


def indexed_worker(queue, value: int) -> None:
    queue.put(value)


def nested_leaf(queue, value: int) -> None:
    queue.put(value + 1)


def nested_parent(queue, value: int) -> None:
    context = multiprocessing.get_context("spawn")
    inner_queue = context.Queue()
    child = context.Process(target=nested_leaf, args=(inner_queue, value))
    child.start()
    result = inner_queue.get(timeout=30)
    child.join(timeout=30)
    queue.put((result, child.exitcode))


def self_test() -> int:
    if sys.argv[1:] != ["--self-test", "参数 空格", "路径-中文"]:
        return 9
    payload = json.loads(Path("assets/payload.json").read_text(encoding="utf-8"))
    if payload != {"message": "静态资源", "ok": True}:
        return 10
    record = SmokeRecord(**payload)
    if attrs.asdict(record) != payload:
        return 16
    match = regex.fullmatch(r"\p{Letter}+", "路径中文")
    if match is None or match.group(0) != "路径中文":
        return 17
    namespace_spec = importlib.util.find_spec("smoke_ns")
    child_spec = importlib.util.find_spec("smoke_ns.child")
    if (
        namespace_spec is None
        or namespace_spec.loader is None
        or namespace_spec.loader is not smoke_ns.__loader__
        or namespace_spec.submodule_search_locations is None
        or namespace_spec.submodule_search_locations is not smoke_ns.__path__
        or list(smoke_ns.__path__) != []
        or child_spec is None
        or child_spec.loader is None
        or child_spec.loader is not smoke_ns.child.__loader__
        or child_spec.submodule_search_locations is None
        or child_spec.submodule_search_locations is not smoke_ns.child.__path__
        or list(smoke_ns.child.__path__) != []
        or smoke_ns.child is not sys.modules["smoke_ns.child"]
        or namespace_value() != "namespace-ok"
    ):
        return 18
    # ``email`` also has an application namespace portion under this source
    # tree. Its regular frozen stdlib package must win over that portion.
    if not callable(getattr(email, "message_from_string", None)):
        return 19
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    process = context.Process(target=queue_worker, args=(queue,))
    process.start()
    child, arguments = queue.get(timeout=30)
    process.join(timeout=30)
    if process.exitcode != 0 or child != "child" or arguments != sys.argv[1:]:
        return 11
    concurrent_queue = context.Queue()
    concurrent = [
        context.Process(target=indexed_worker, args=(concurrent_queue, value))
        for value in range(6)
    ]
    for item in concurrent:
        item.start()
    concurrent_values = sorted(concurrent_queue.get(timeout=30) for _item in concurrent)
    for item in concurrent:
        item.join(timeout=30)
    if concurrent_values != list(range(6)) or any(item.exitcode != 0 for item in concurrent):
        return 12
    nested_queue = context.Queue()
    nested = context.Process(target=nested_parent, args=(nested_queue, 40))
    nested.start()
    nested_result = nested_queue.get(timeout=60)
    nested.join(timeout=60)
    if nested.exitcode != 0 or nested_result != (41, 0):
        return 13
    with context.Pool(2) as pool:
        if pool.map(square, [2, 3, 4]) != [4, 9, 16]:
            return 14
    with ProcessPoolExecutor(max_workers=2, mp_context=context) as executor:
        if list(executor.map(square, [5, 6])) != [25, 36]:
            return 15
    print(json.dumps({"argv": sys.argv[1:], "resource": payload}, ensure_ascii=False))
    return 0


def argv_probe() -> int:
    print(json.dumps({"argv": sys.argv[1:]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    if os.environ.get("PYSUTURE_SMOKE_ARGV_PROBE") == "1":
        raise SystemExit(argv_probe())
    raise SystemExit(0)
