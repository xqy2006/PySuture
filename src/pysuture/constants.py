from __future__ import annotations

DEFAULT_PYTHON_SERIES = "3.13"
DEFAULT_CYTHON_VERSION = "3.2.9"
DEFAULT_INDEX_URL = (
    "https://raw.githubusercontent.com/xqy2006/PySuture/master/runtime-catalog.lock.json"
)
LOCK_SCHEMA_VERSION = 1
CONFIG_SCHEMA_VERSION = 1
SUPPORTED_PYTHON_SERIES = ("3.11", "3.12", "3.13", "3.14", "3.15")
SUPPORTED_PLATFORM = "windows-x64"
SECRET_BASENAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "_netrc",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "service-account.json",
}
SECRET_SUFFIXES = {".jks", ".key", ".keystore", ".p12", ".pfx", ".ppk"}
