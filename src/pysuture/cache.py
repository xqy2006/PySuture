from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import stat
import shutil
import tempfile
import time
import zlib
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile, ZipInfo

from .errors import LockError


_EXTRACTED_MARKER_NAME = ".pysuture-extracted.json"
_EXTRACTED_MANIFEST_VERSION = 1
_CACHE_LOCK_TIMEOUT_SECONDS = 120.0
_ARCHIVE_ERRORS = (
    BadZipFile,
    EOFError,
    NotImplementedError,
    OSError,
    RuntimeError,
    UnicodeError,
    zlib.error,
)
try:
    from lzma import LZMAError as _LZMAError
except ImportError:  # pragma: no cover - zipfile also treats lzma as optional
    pass
else:
    _ARCHIVE_ERRORS += (_LZMAError,)
try:
    from compression.zstd import ZstdError as _ZstdError
except ImportError:  # Python 3.11-3.13 do not provide stdlib Zstandard support
    pass
else:
    _ARCHIVE_ERRORS += (_ZstdError,)
_WINDOWS_RESERVED_NAMES = {
    "aux",
    "clock$",
    "con",
    "conin$",
    "conout$",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
    *(f"com{number}" for number in "¹²³"),
    *(f"lpt{number}" for number in "¹²³"),
}


def _latest_prerelease_asset_url(releases: object, asset_name: str) -> str:
    if not isinstance(releases, list):
        return ""
    candidates: list[tuple[str, int, str]] = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or not release.get("prerelease"):
            continue
        timestamp = str(release.get("published_at") or release.get("created_at") or "")
        release_id = release.get("id")
        numeric_id = release_id if isinstance(release_id, int) else 0
        for asset in release.get("assets", []):
            if not isinstance(asset, dict):
                continue
            asset_url = asset.get("browser_download_url")
            if asset.get("name") == asset_name and isinstance(asset_url, str) and asset_url:
                candidates.append((timestamp, numeric_id, asset_url))
                break
    return max(candidates, default=("", 0, ""))[2]


def cache_root() -> Path:
    configured = os.environ.get("PYSUTURE_CACHE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return (Path(local_app_data) / "PySuture" / "cache").resolve()
    return (Path.home() / ".cache" / "pysuture").resolve()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _local_source(url: str) -> Path | None:
    parsed = urlparse(url)
    if os.name == "nt" and len(parsed.scheme) == 1 and len(url) >= 3 and url[1] == ":":
        return Path(url).expanduser().resolve()
    if parsed.scheme == "file":
        path = Path(parsed.path.lstrip("/") if os.name == "nt" and parsed.path.startswith("/") else parsed.path)
        return path.resolve()
    if not parsed.scheme:
        return Path(url).expanduser().resolve()
    return None


def fetch_index(url: str, *, offline: bool = False) -> tuple[bytes, Path]:
    local = _local_source(url)
    if local is not None:
        if not local.is_file():
            raise LockError(f"index file does not exist: {local}")
        return local.read_bytes(), local
    destination = cache_root() / "indexes" / f"{hashlib.sha256(url.encode('utf-8')).hexdigest()}.json"
    if offline:
        if not destination.is_file():
            raise LockError(f"offline mode: index is not cached for {url}")
        return destination.read_bytes(), destination
    resolved_url = url
    if url.startswith("github+latest://"):
        target = url.removeprefix("github+latest://")
        owner, separator, remainder = target.partition("/")
        repository, separator2, asset_name = remainder.partition("/")
        if not separator or not separator2 or not owner or not repository or not asset_name:
            raise LockError(f"invalid github+latest index URL: {url}")
        api_url = f"https://api.github.com/repos/{owner}/{repository}/releases?per_page=30"
        api_request = Request(
            api_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "PySuture/0.1 (+https://github.com/xqy2006/PySuture)",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(api_request, timeout=60) as response:
                releases = json.loads(response.read().decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            if destination.is_file():
                return destination.read_bytes(), destination
            raise LockError(f"could not resolve latest verified StaticPython prerelease: {exc}") from exc
        resolved_url = _latest_prerelease_asset_url(releases, asset_name)
        if not resolved_url:
            raise LockError(f"no verified prerelease asset named {asset_name!r} was found in {owner}/{repository}")
    request = Request(resolved_url, headers={"User-Agent": "PySuture/0.1 (+https://github.com/xqy2006/PySuture)"})
    try:
        with urlopen(request, timeout=60) as response:
            payload = response.read()
    except OSError as exc:
        if destination.is_file():
            return destination.read_bytes(), destination
        raise LockError(f"could not download StaticPython index {url}: {exc}") from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(payload)
    temporary.replace(destination)
    return payload, destination


def fetch_asset(url: str, sha256: str, *, offline: bool = False) -> Path:
    if len(sha256) != 64 or any(character not in "0123456789abcdefABCDEF" for character in sha256):
        raise LockError(f"invalid SHA-256 for asset {url}")
    destination = cache_root() / "assets" / sha256.lower() / (Path(urlparse(url).path).name or "asset.zip")
    if destination.is_file() and sha256_file(destination) == sha256.lower():
        return destination
    if offline:
        raise LockError(f"offline mode: verified asset is not cached: {url}")
    local = _local_source(url)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    if local is not None:
        if not local.is_file():
            raise LockError(f"asset file does not exist: {local}")
        shutil.copy2(local, temporary)
    else:
        request = Request(url, headers={"User-Agent": "PySuture/0.1 (+https://github.com/xqy2006/PySuture)"})
        try:
            with urlopen(request, timeout=180) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise LockError(f"could not download asset {url}: {exc}") from exc
    actual = sha256_file(temporary)
    if actual != sha256.lower():
        temporary.unlink(missing_ok=True)
        raise LockError(f"SHA-256 mismatch for {url}: expected {sha256.lower()}, got {actual}")
    temporary.replace(destination)
    return destination


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _hash_stream(handle: object) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = handle.read(1024 * 1024)  # type: ignore[attr-defined]
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return size, digest.hexdigest()


def _is_reparse_point(stat_result: os.stat_result) -> bool:
    return bool(getattr(stat_result, "st_file_attributes", 0) & 0x400)


def _validated_member_name(member: ZipInfo) -> tuple[tuple[str, ...], str, bool]:
    raw_name = member.filename.replace("\\", "/")
    is_directory = raw_name.endswith("/")
    name = raw_name[:-1] if is_directory else raw_name
    if not name or raw_name.startswith("/") or "\x00" in raw_name:
        raise LockError(f"unsafe path in archive: {member.filename}")

    parts = tuple(name.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise LockError(f"unsafe path in archive: {member.filename}")
    for part in parts:
        reserved_stem = part.split(".", 1)[0].casefold()
        if (
            any(ord(character) < 32 or character in '<>:"|?*' for character in part)
            or part.endswith((" ", "."))
            or reserved_stem in _WINDOWS_RESERVED_NAMES
        ):
            raise LockError(f"unsafe Windows path in archive: {member.filename}")
    if len(parts) == 1 and parts[0].casefold() == _EXTRACTED_MARKER_NAME.casefold():
        raise LockError(f"archive contains reserved cache marker: {member.filename}")

    unix_mode = member.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if file_type and not (
        (is_directory and stat.S_ISDIR(unix_mode))
        or (not is_directory and stat.S_ISREG(unix_mode))
    ):
        raise LockError(f"unsupported special file in archive: {member.filename}")
    return parts, "/".join(parts), is_directory


def _validated_archive_members(
    archive: ZipFile,
) -> list[tuple[ZipInfo, tuple[str, ...], str, bool]]:
    planned: list[tuple[ZipInfo, tuple[str, ...], str, bool]] = []
    member_types: dict[str, tuple[str, bool]] = {}
    for member in archive.infolist():
        parts, name, is_directory = _validated_member_name(member)
        key = "/".join(part.casefold() for part in parts)
        if key in member_types:
            previous = member_types[key][0]
            raise LockError(
                f"duplicate archive member after Windows path normalization: "
                f"{previous!r} and {member.filename!r}"
            )
        member_types[key] = (member.filename, is_directory)
        planned.append((member, parts, name, is_directory))

    for _member, parts, name, _is_directory in planned:
        folded_parts = [part.casefold() for part in parts]
        for length in range(1, len(folded_parts)):
            parent_key = "/".join(folded_parts[:length])
            parent = member_types.get(parent_key)
            if parent is not None and not parent[1]:
                raise LockError(
                    f"archive file conflicts with child path: {parent[0]!r} and {name!r}"
                )
    _archive_directories(planned)
    return planned


def _archive_directories(
    members: list[tuple[ZipInfo, tuple[str, ...], str, bool]],
) -> list[str]:
    directories: dict[str, str] = {}
    for member, parts, _name, is_directory in members:
        prefix_count = len(parts) if is_directory else len(parts) - 1
        for length in range(1, prefix_count + 1):
            directory = "/".join(parts[:length])
            key = directory.casefold()
            previous = directories.get(key)
            if previous is not None and previous != directory:
                raise LockError(
                    f"archive directory has ambiguous Windows casing: "
                    f"{previous!r} and {directory!r} from {member.filename!r}"
                )
            directories[key] = directory
    return sorted(directories.values())


def _archive_tree_manifest(
    archive: ZipFile,
    members: list[tuple[ZipInfo, tuple[str, ...], str, bool]],
) -> dict[str, object]:
    files: list[dict[str, object]] = []
    for member, _parts, name, is_directory in members:
        if is_directory:
            continue
        with archive.open(member) as source:
            size, digest = _hash_stream(source)
        if size != member.file_size:
            raise LockError(
                f"archive member size changed while reading {member.filename!r}: "
                f"expected {member.file_size}, got {size}"
            )
        files.append({"path": name, "size": size, "sha256": digest})
    return {
        "directories": _archive_directories(members),
        "files": sorted(files, key=lambda item: str(item["path"])),
    }


def _extract_validated_members(
    archive: ZipFile,
    destination: Path,
    members: list[tuple[ZipInfo, tuple[str, ...], str, bool]],
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_resolved = destination.resolve()
    for member, parts, _name, is_directory in members:
        if is_directory:
            destination.joinpath(*parts).mkdir(parents=True, exist_ok=True)
            continue
        target = destination.joinpath(*parts)
        target_resolved = target.resolve()
        if target_resolved != destination_resolved and destination_resolved not in target_resolved.parents:
            raise LockError(f"unsafe path in archive: {member.filename}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("wb") as output:
            shutil.copyfileobj(source, output)


def _safe_extract(archive: ZipFile, destination: Path) -> None:
    _extract_validated_members(archive, destination, _validated_archive_members(archive))


def _tree_manifest(root: Path) -> dict[str, object]:
    root_stat = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(root_stat.st_mode) or _is_reparse_point(root_stat):
        raise LockError(f"extracted cache root is not a regular directory: {root}")

    directories: list[str] = []
    files: list[dict[str, object]] = []

    def visit(directory: Path, relative_parts: tuple[str, ...]) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            parts = (*relative_parts, entry.name)
            relative = "/".join(parts)
            entry_stat = entry.stat(follow_symlinks=False)
            if _is_reparse_point(entry_stat) or stat.S_ISLNK(entry_stat.st_mode):
                raise LockError(f"extracted cache contains a link or reparse point: {relative}")
            if not relative_parts and entry.name == _EXTRACTED_MARKER_NAME:
                if not stat.S_ISREG(entry_stat.st_mode):
                    raise LockError(f"extracted cache marker is not a regular file: {relative}")
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                directories.append(relative)
                visit(Path(entry.path), parts)
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise LockError(f"extracted cache contains a special file: {relative}")
            path = Path(entry.path)
            size = entry_stat.st_size
            digest = sha256_file(path)
            if path.stat(follow_symlinks=False).st_size != size:
                raise LockError(f"extracted cache file changed while hashing: {relative}")
            files.append({"path": relative, "size": size, "sha256": digest})

    visit(root, ())
    return {
        "directories": sorted(directories),
        "files": sorted(files, key=lambda item: str(item["path"])),
    }


def _cache_matches_manifest(
    destination: Path,
    asset_sha256: str,
    tree: dict[str, object],
) -> bool:
    marker = destination / _EXTRACTED_MARKER_NAME
    try:
        marker_stat = marker.stat(follow_symlinks=False)
        if not stat.S_ISREG(marker_stat.st_mode) or _is_reparse_point(marker_stat):
            return False
        payload = json.loads(marker.read_text(encoding="utf-8"))
        if (
            payload.get("manifest_version") != _EXTRACTED_MANIFEST_VERSION
            or payload.get("asset_sha256") != asset_sha256
            or payload.get("directories") != tree["directories"]
            or payload.get("files") != tree["files"]
        ):
            return False
        return _tree_manifest(destination) == tree
    except (LockError, OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        return False


def _lock_file(handle: object, *, unlock: bool = False) -> None:
    handle.seek(0)  # type: ignore[attr-defined]
    if os.name == "nt":
        import msvcrt

        mode = msvcrt.LK_UNLCK if unlock else msvcrt.LK_NBLCK
        msvcrt.locking(handle.fileno(), mode, 1)  # type: ignore[attr-defined]
    else:
        import fcntl

        mode = fcntl.LOCK_UN if unlock else fcntl.LOCK_EX | fcntl.LOCK_NB
        fcntl.flock(handle.fileno(), mode)  # type: ignore[attr-defined]


@contextmanager
def _extraction_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        deadline = time.monotonic() + _CACHE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                _lock_file(handle)
                break
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    raise LockError(f"timed out waiting for extracted-cache lock {path}") from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            try:
                _lock_file(handle, unlock=True)
            except OSError:
                pass


@contextmanager
def _open_verified_archive(path: Path, expected_sha256: str):
    try:
        handle = path.open("rb")
    except OSError as exc:
        raise LockError(f"could not open asset archive {path}: {exc}") from exc

    archive: ZipFile | None = None
    try:
        try:
            _size, actual_sha256 = _hash_stream(handle)
            handle.seek(0)
        except OSError as exc:
            raise LockError(f"could not hash or rewind asset archive {path}: {exc}") from exc
        if actual_sha256 != expected_sha256:
            raise LockError(
                f"SHA-256 mismatch for cached asset {path}: "
                f"expected {expected_sha256}, got {actual_sha256}"
            )
        try:
            archive = ZipFile(handle)
            members = _validated_archive_members(archive)
            tree = _archive_tree_manifest(archive, members)
        except LockError:
            raise
        except _ARCHIVE_ERRORS as exc:
            raise LockError(f"could not validate asset archive {path}: {exc}") from exc
        yield handle, archive, members, tree
    finally:
        if archive is not None:
            archive.close()
        handle.close()


def _verify_open_archive_sha256(handle: object, expected_sha256: str) -> None:
    try:
        position = handle.tell()  # type: ignore[attr-defined]
        handle.seek(0)  # type: ignore[attr-defined]
        _size, actual_sha256 = _hash_stream(handle)
        handle.seek(position)  # type: ignore[attr-defined]
    except OSError as exc:
        raise LockError(f"could not recheck the open asset archive: {exc}") from exc
    if actual_sha256 != expected_sha256:
        raise LockError(
            "asset archive changed during manifest generation or extraction: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )


def _path_entry_exists(path: Path) -> bool:
    return os.path.lexists(path)


def _publish_extracted_cache(staging: Path, destination: Path, workspace: Path) -> None:
    previous = workspace / "previous"
    moved_previous = False
    if _path_entry_exists(destination):
        try:
            destination.replace(previous)
            moved_previous = True
        except OSError as exc:
            raise LockError(f"could not move invalid extracted cache aside: {destination}") from exc
    try:
        staging.replace(destination)
    except OSError as exc:
        restoration_error: OSError | None = None
        if moved_previous and not _path_entry_exists(destination):
            try:
                previous.replace(destination)
            except OSError as restore_exc:
                restoration_error = restore_exc
        detail = ""
        if restoration_error is not None:
            detail = f"; previous cache restoration also failed: {restoration_error}"
        raise LockError(f"could not publish extracted cache {destination}{detail}") from exc


def extract_asset(path: Path, sha256: str) -> Path:
    if not _valid_sha256(sha256):
        raise LockError(f"invalid SHA-256 for asset {path}")
    expected_sha256 = sha256.lower()
    destination = cache_root() / "extracted" / expected_sha256
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock_path = destination.parent / f".{expected_sha256}.lock"
    with _extraction_lock(lock_path):
        with _open_verified_archive(path, expected_sha256) as (handle, archive, members, tree):
            if _cache_matches_manifest(destination, expected_sha256, tree):
                return destination

            workspace = Path(tempfile.mkdtemp(prefix="pysuture-extract-", dir=destination.parent))
            staging = workspace / "payload"
            try:
                try:
                    _extract_validated_members(archive, staging, members)
                except LockError:
                    raise
                except _ARCHIVE_ERRORS as exc:
                    raise LockError(f"could not extract verified asset archive {path}: {exc}") from exc
                _verify_open_archive_sha256(handle, expected_sha256)
                try:
                    verified_tree = _archive_tree_manifest(archive, members)
                except LockError:
                    raise
                except _ARCHIVE_ERRORS as exc:
                    raise LockError(f"could not revalidate asset archive {path}: {exc}") from exc
                if verified_tree != tree:
                    raise LockError(f"asset archive contents changed during extraction: {path}")
                if _tree_manifest(staging) != verified_tree:
                    raise LockError(f"extracted asset contents do not match verified archive {path}")
                marker_payload = {
                    "asset_name": path.name,
                    "asset_sha256": expected_sha256,
                    "directories": verified_tree["directories"],
                    "files": verified_tree["files"],
                    "manifest_version": _EXTRACTED_MANIFEST_VERSION,
                }
                (staging / _EXTRACTED_MARKER_NAME).write_text(
                    json.dumps(marker_payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                _publish_extracted_cache(staging, destination, workspace)
            finally:
                shutil.rmtree(workspace, ignore_errors=True)
    return destination
