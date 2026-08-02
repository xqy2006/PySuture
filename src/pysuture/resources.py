from __future__ import annotations

import glob
import hashlib
import re
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .config import ProjectConfig
from .constants import SECRET_BASENAMES, SECRET_SUFFIXES
from .errors import BuildError


SECRET_NAME_PATTERNS = (
    re.compile(r"^\.env(?:rc|[._-].+)?$"),
    re.compile(
        r"^(?:credentials|secrets?|client[_-]?secret|service[_-]?account)(?:[._-].+)?"
        r"(?:\.json|\.toml|\.ya?ml)?$"
    ),
    re.compile(
        r"^id_(?:dsa|ecdsa|ed25519|rsa)"
        r"(?!\.pub(?:$|[._-]))(?:[._-].+)?$"
    ),
)
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"PuTTY-User-Key-File-",
)


@dataclass(frozen=True)
class ResourceRecord:
    source: Path
    target: str
    sha256: str
    size: int


def _wildcard_anchor(pattern: str) -> Path:
    parts = Path(pattern).parts
    stable = []
    for part in parts:
        if any(character in part for character in "*?["):
            break
        stable.append(part)
    return Path(*stable) if stable else Path(".")


def _safe_target(value: str) -> str:
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    path = PurePosixPath(normalized)
    try:
        normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BuildError(
            f"resource target must be a safe relative virtual path: {value!r}"
        ) from exc
    if (
        not normalized
        or path.is_absolute()
        or bool(PureWindowsPath(normalized).drive)
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise BuildError(f"resource target must be a safe relative virtual path: {value!r}")
    return "/".join(parts)


def _looks_secret(path: Path, payload: bytes) -> bool:
    name = path.name.casefold()
    if (
        name in SECRET_BASENAMES
        or path.suffix.casefold() in SECRET_SUFFIXES
        or any(pattern.fullmatch(name) for pattern in SECRET_NAME_PATTERNS)
    ):
        return True
    return any(marker in payload for marker in PRIVATE_KEY_MARKERS)


def collect_application_resources(config: ProjectConfig) -> tuple[list[ResourceRecord], list[str]]:
    root = config.root.resolve()
    records: dict[str, ResourceRecord] = {}
    warnings: list[str] = []
    for mapping in config.data:
        pattern = mapping.source.replace("\\", "/")
        absolute_pattern = str(root / Path(pattern))
        matches = sorted(Path(value) for value in glob.glob(absolute_pattern, recursive=True))
        files = [path for path in matches if path.is_file()]
        if not files:
            raise BuildError(f"resource include pattern matched no files: {mapping.source}")
        anchor = (root / _wildcard_anchor(pattern)).resolve()
        has_wildcard = any(character in pattern for character in "*?[")
        for path in files:
            resolved = path.resolve()
            if root != resolved and root not in resolved.parents:
                raise BuildError(f"resource escapes the project root: {path}")
            try:
                payload = resolved.read_bytes()
            except OSError as exc:
                raise BuildError(f"could not read matched resource: {resolved}") from exc
            if _looks_secret(resolved, payload):
                message = f"resource looks like a credential or private key: {resolved.relative_to(root)}"
                if config.secret_policy == "error":
                    raise BuildError(message)
                if config.secret_policy == "warn":
                    warnings.append(message)
            if has_wildcard:
                try:
                    suffix = resolved.relative_to(anchor).as_posix()
                except ValueError as exc:
                    raise BuildError(f"resource {resolved} is outside wildcard anchor {anchor}") from exc
                target_root = mapping.target.rstrip("/\\")
                target = _safe_target(f"{target_root}/{suffix}")
            else:
                target_value = mapping.target
                if target_value.endswith(("/", "\\")):
                    target_value += resolved.name
                target = _safe_target(target_value)
            if target in records:
                raise BuildError(f"multiple resources map to virtual path {target!r}")
            records[target] = ResourceRecord(
                source=resolved,
                target=target,
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
            )
    return [records[name] for name in sorted(records)], warnings


def write_resource_sources(records: list[ResourceRecord], source_dir: Path) -> list[dict]:
    targets: dict[str, Path] = {}
    for record in records:
        target = _safe_target(record.target)
        if target != record.target:
            raise BuildError(f"resource target is not canonical: {record.target!r}")
        if target in targets:
            raise BuildError(
                f"multiple resources map to virtual path {target!r}: "
                f"{targets[target]} and {record.source}"
            )
        targets[target] = record.source

    verified_payloads: list[tuple[ResourceRecord, bytes, str]] = []
    for record in records:
        try:
            payload = record.source.read_bytes()
        except OSError as exc:
            raise BuildError(f"could not reread collected resource: {record.source}") from exc
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if len(payload) != record.size or actual_sha256 != record.sha256.lower():
            raise BuildError(
                f"resource changed after collection: {record.source} "
                f"(expected {record.size} bytes/{record.sha256.lower()}, "
                f"got {len(payload)} bytes/{actual_sha256})"
            )
        verified_payloads.append((record, payload, actual_sha256))

    # Validate every input before emitting the first generated source. A late
    # mismatch must not leave a plausible-looking partial resource table.
    source_dir.mkdir(parents=True, exist_ok=True)
    generated: list[dict] = []
    for index, (record, payload, actual_sha256) in enumerate(verified_payloads, start=1):
        compressed = zlib.compress(payload, level=9)
        symbol = f"pysuture_resource_{index:06d}_{actual_sha256[:16]}"
        values = [str(value) for value in compressed]
        rows = ["    " + ", ".join(values[offset : offset + 24]) + "," for offset in range(0, len(values), 24)]
        path = source_dir / f"resource_{index:06d}.c"
        path.write_text(
            "/* Auto-generated by PySuture. SPDX-License-Identifier: Apache-2.0 */\n"
            "#include <stddef.h>\n\n"
            f"const unsigned char {symbol}[] = {{\n"
            + ("\n".join(rows) if rows else "    0,")
            + "\n};\n",
            encoding="utf-8",
            newline="\n",
        )
        generated.append(
            {
                "target": record.target,
                "source": str(path),
                "symbol": symbol,
                "size": len(payload),
                "compressed_size": len(compressed),
                "sha256": actual_sha256,
            }
        )
    return generated
