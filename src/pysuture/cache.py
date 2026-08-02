from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from zipfile import ZipFile

from .errors import LockError


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


def _safe_extract(archive: ZipFile, destination: Path) -> None:
    destination_resolved = destination.resolve()
    for member in archive.infolist():
        name = member.filename.replace("\\", "/")
        if not name or name.endswith("/"):
            continue
        target = (destination / Path(name)).resolve()
        if target != destination_resolved and destination_resolved not in target.parents:
            raise LockError(f"unsafe path in archive: {member.filename}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("wb") as output:
            shutil.copyfileobj(source, output)


def extract_asset(path: Path, sha256: str) -> Path:
    destination = cache_root() / "extracted" / sha256.lower()
    marker = destination / ".pysuture-extracted.json"
    if marker.is_file():
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if payload.get("asset_sha256") == sha256.lower():
            return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pysuture-extract-", dir=destination.parent) as temporary_dir:
        staging = Path(temporary_dir)
        with ZipFile(path) as archive:
            _safe_extract(archive, staging)
        marker_payload = {"asset_sha256": sha256.lower(), "asset_name": path.name}
        (staging / ".pysuture-extracted.json").write_text(
            json.dumps(marker_payload, sort_keys=True),
            encoding="utf-8",
            newline="\n",
        )
        if destination.exists():
            shutil.rmtree(destination)
        staging.replace(destination)
    return destination
