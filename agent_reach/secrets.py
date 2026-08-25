# -*- coding: utf-8 -*-
"""OS secret store for Agent Reach (Phase 3).

Product path is the platform store, not plaintext YAML:

- macOS: Security.framework via ctypes (no ``security -w`` argv leak)
- Linux: libsecret ``secret-tool`` (password on stdin, not argv)
- Windows: Credential Manager via ctypes (``cmdkey`` cannot read secrets)

No ``keyring`` extra. No required runtime dependency. Tests inject
``MemoryBackend``. Never log or raise secret values.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from typing import Any, Iterable, Mapping, Optional, Protocol, runtime_checkable

from agent_reach.utils.process import utf8_subprocess_env

SERVICE_NAME = "agent-reach"
YAML_SECRETS_ENV = "AGENT_REACH_SECRETS"
VAULT_ITEMS_KEY = "vault_items"

# Same substring markers as Config.to_dict(). Keep in one module so redaction
# and store routing cannot drift.
SENSITIVE_MARKERS = (
    "key",
    "token",
    "password",
    "proxy",
    "cookie",
    "secret",
    "session",
    "sessdata",
    "csrf",
    "auth",
    "cred",
    "ct0",
)

# ADR-004 B: Twitter cookies are process-env only. Never persist.
NEVER_STORE_KEYS = frozenset({"twitter_auth_token", "twitter_ct0"})

# Uninstall catalog if YAML index is gone. Names only, never values.
KNOWN_SECRET_KEYS = frozenset(
    {
        "github_token",
        "groq_api_key",
        "openai_api_key",
        "exa_api_key",
        "proxy",
        "bilibili_proxy",
        "youtube_cookies_from",
        "bilibili_sessdata",
        "bilibili_csrf",
        "xueqiu_cookie",
    }
)

_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_CLI_TIMEOUT = 15

_backend_override: Optional["SecretBackend"] = None


class SecretStoreError(RuntimeError):
    """Store failed. Message must never include a secret value."""


@runtime_checkable
class SecretBackend(Protocol):
    def get(self, account: str) -> Optional[str]:
        ...

    def set(self, account: str, value: str) -> None:
        ...

    def delete(self, account: str) -> None:
        ...

    def list_accounts(self) -> list[str]:
        ...


class MemoryBackend:
    """In-memory store for pytest. Not used in production."""

    def __init__(self) -> None:
        self._items: dict[str, str] = {}

    def get(self, account: str) -> Optional[str]:
        _validate_account(account)
        return self._items.get(account)

    def set(self, account: str, value: str) -> None:
        _validate_account(account)
        _validate_secret_value(value)
        self._items[account] = value

    def delete(self, account: str) -> None:
        _validate_account(account)
        self._items.pop(account, None)

    def list_accounts(self) -> list[str]:
        return sorted(self._items)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered == VAULT_ITEMS_KEY:
        return False
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def is_never_store_key(key: str) -> bool:
    return key in NEVER_STORE_KEYS


def yaml_dual_write_enabled() -> bool:
    import os

    return os.environ.get(YAML_SECRETS_ENV, "").strip().lower() == "yaml"


def yaml_leftover_secret_keys(data: Mapping[str, Any] | None) -> list[str]:
    """Return sensitive YAML key *names* that still hold non-empty values.

    Never returns or logs values. Used by doctor to nudge ``migrate-secrets``.
    """
    if not data:
        return []
    names: list[str] = []
    for key, value in data.items():
        if key == VAULT_ITEMS_KEY:
            continue
        if not is_sensitive_key(key):
            continue
        if value in (None, ""):
            continue
        names.append(key)
    return sorted(names)


def set_backend(backend: Optional[SecretBackend]) -> None:
    """Replace the process-wide backend. Tests pass ``MemoryBackend``."""
    global _backend_override
    _backend_override = backend


def get_backend() -> SecretBackend:
    if _backend_override is not None:
        return _backend_override
    return default_backend()


def default_backend() -> SecretBackend:
    if sys.platform == "darwin":
        return MacOSKeychainBackend()
    if sys.platform == "win32":
        return WindowsCredentialBackend()
    return LibsecretBackend()


def migrate_from_mapping(data: Mapping[str, Any]) -> list[str]:
    """Copy sensitive YAML values into the store. Do not delete YAML keys.

    Returns account names copied into the store. Never returns values.
    Skips Twitter keys (never-store).
    """
    backend = get_backend()
    copied: list[str] = []
    for key, value in data.items():
        if key == VAULT_ITEMS_KEY or is_never_store_key(key):
            continue
        if not is_sensitive_key(key):
            continue
        if not isinstance(value, str) or not value:
            continue
        existing = backend.get(key)
        if not existing:
            backend.set(key, value)
        copied.append(key)
    return copied


def delete_accounts(accounts: Iterable[str]) -> None:
    backend = get_backend()
    for account in accounts:
        if not account or is_never_store_key(account):
            continue
        try:
            backend.delete(account)
        except SecretStoreError:
            continue


def collect_store_accounts(data: Mapping[str, Any] | None) -> set[str]:
    accounts = set(KNOWN_SECRET_KEYS)
    if data:
        raw_items = data.get(VAULT_ITEMS_KEY) or []
        if isinstance(raw_items, list):
            accounts.update(str(item) for item in raw_items if item)
        for key in data:
            if is_sensitive_key(key) and not is_never_store_key(key):
                accounts.add(key)
    try:
        accounts.update(get_backend().list_accounts())
    except SecretStoreError:
        pass
    return {name for name in accounts if name and _ACCOUNT_RE.fullmatch(name)}


def _validate_account(account: str) -> None:
    if not account or not _ACCOUNT_RE.fullmatch(account):
        raise SecretStoreError("invalid secret account name")


def _validate_secret_value(value: str) -> None:
    if not value:
        raise SecretStoreError("refusing to store an empty secret")
    if "\n" in value or "\r" in value or "\0" in value:
        raise SecretStoreError("refusing to store a secret that contains a newline")


def _run_cli(argv: list[str], *, stdin: Optional[str] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=_CLI_TIMEOUT,
        env=utf8_subprocess_env(),
    )


class MacOSKeychainBackend:
    """macOS Keychain via Security.framework (ctypes). Never puts secrets in argv."""

    def get(self, account: str) -> Optional[str]:
        _validate_account(account)
        return _macos_secitem_get(account)

    def set(self, account: str, value: str) -> None:
        _validate_account(account)
        _validate_secret_value(value)
        _macos_secitem_set(account, value)

    def delete(self, account: str) -> None:
        _validate_account(account)
        _macos_secitem_delete(account)

    def list_accounts(self) -> list[str]:
        return []


class LibsecretBackend:
    """Wrap ``secret-tool`` (libsecret). Password on stdin, never argv."""

    def get(self, account: str) -> Optional[str]:
        _validate_account(account)
        if not shutil.which("secret-tool"):
            return None
        try:
            result = _run_cli(
                [
                    "secret-tool",
                    "lookup",
                    "service",
                    SERVICE_NAME,
                    "account",
                    account,
                ]
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        return (result.stdout or "").removesuffix("\n").removesuffix("\r") or None

    def set(self, account: str, value: str) -> None:
        _validate_account(account)
        _validate_secret_value(value)
        if not shutil.which("secret-tool"):
            raise SecretStoreError("secret-tool not found (install libsecret)")
        try:
            # Password on stdin only (no trailing newline; values forbid \\n).
            result = _run_cli(
                [
                    "secret-tool",
                    "store",
                    "--label",
                    f"Agent Reach {account}",
                    "service",
                    SERVICE_NAME,
                    "account",
                    account,
                ],
                stdin=value,
            )
        except subprocess.TimeoutExpired as exc:
            raise SecretStoreError("libsecret timed out") from exc
        except OSError as exc:
            raise SecretStoreError("libsecret is unavailable") from exc
        if result.returncode != 0:
            raise SecretStoreError("libsecret write failed")

    def delete(self, account: str) -> None:
        _validate_account(account)
        if not shutil.which("secret-tool"):
            return
        try:
            _run_cli(
                [
                    "secret-tool",
                    "clear",
                    "service",
                    SERVICE_NAME,
                    "account",
                    account,
                ]
            )
        except (OSError, subprocess.TimeoutExpired):
            return

    def list_accounts(self) -> list[str]:
        return []


class WindowsCredentialBackend:
    """Windows Credential Manager via ctypes.

    CredMan uses DPAPI under the user profile. ACL story is weaker than macOS
    Keychain / libsecret; do not dual-write YAML (``AGENT_REACH_SECRETS=yaml``)
    on shared Windows machines.
    """

    def get(self, account: str) -> Optional[str]:
        _validate_account(account)
        return _win_cred_get(_windows_target(account))

    def set(self, account: str, value: str) -> None:
        _validate_account(account)
        _validate_secret_value(value)
        _win_cred_set(_windows_target(account), value)

    def delete(self, account: str) -> None:
        _validate_account(account)
        _win_cred_delete(_windows_target(account))

    def list_accounts(self) -> list[str]:
        return _win_cred_list()


# ── macOS Security.framework ───────────────────────────────────────────────

_ERR_SEC_SUCCESS = 0
_ERR_SEC_ITEM_NOT_FOUND = -25300
_ERR_SEC_DUPLICATE_ITEM = -25299


def _macos_secitem_get(account: str) -> Optional[str]:
    if sys.platform != "darwin":
        return None
    try:
        data = _macos_secitem_copy(account)
    except SecretStoreError:
        return None
    if data is None:
        return None
    try:
        return data.decode("utf-8") or None
    except UnicodeDecodeError:
        return None


def _macos_secitem_set(account: str, value: str) -> None:
    if sys.platform != "darwin":
        raise SecretStoreError("macOS Keychain is not available")
    status = _macos_secitem_add(account, value.encode("utf-8"))
    if status == _ERR_SEC_SUCCESS:
        return
    if status == _ERR_SEC_DUPLICATE_ITEM:
        status = _macos_secitem_update(account, value.encode("utf-8"))
        if status == _ERR_SEC_SUCCESS:
            return
    raise SecretStoreError("macOS Keychain write failed")


def _macos_secitem_delete(account: str) -> None:
    if sys.platform != "darwin":
        return
    try:
        status = _macos_secitem_delete_query(account)
    except SecretStoreError:
        return
    if status not in (_ERR_SEC_SUCCESS, _ERR_SEC_ITEM_NOT_FOUND):
        return


def _macos_cf() -> tuple[Any, Any]:
    import ctypes

    security = ctypes.CDLL(
        "/System/Library/Frameworks/Security.framework/Security"
    )
    core = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    return security, core


def _macos_cf_str(core: Any, text: str) -> Any:
    import ctypes

    encoded = text.encode("utf-8")
    core.CFStringCreateWithBytes.restype = ctypes.c_void_p
    core.CFStringCreateWithBytes.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_long,
        ctypes.c_uint32,
        ctypes.c_ubyte,
    ]
    ref = core.CFStringCreateWithBytes(
        None,
        encoded,
        len(encoded),
        0x08000100,  # kCFStringEncodingUTF8
        0,
    )
    if not ref:
        raise SecretStoreError("macOS Keychain is unavailable")
    return ref


def _macos_cf_data(core: Any, blob: bytes) -> Any:
    import ctypes

    core.CFDataCreate.restype = ctypes.c_void_p
    core.CFDataCreate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_long,
    ]
    ref = core.CFDataCreate(None, blob, len(blob))
    if not ref:
        raise SecretStoreError("macOS Keychain is unavailable")
    return ref


def _macos_cf_mutable_dict(core: Any) -> Any:
    import ctypes

    core.CFDictionaryCreateMutable.restype = ctypes.c_void_p
    core.CFDictionaryCreateMutable.argtypes = [
        ctypes.c_void_p,
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    key_cbs = ctypes.addressof(
        ctypes.c_char.in_dll(core, "kCFTypeDictionaryKeyCallBacks")
    )
    val_cbs = ctypes.addressof(
        ctypes.c_char.in_dll(core, "kCFTypeDictionaryValueCallBacks")
    )
    ref = core.CFDictionaryCreateMutable(None, 0, key_cbs, val_cbs)
    if not ref:
        raise SecretStoreError("macOS Keychain is unavailable")
    return ref


def _macos_cf_set(core: Any, mapping: Any, key: Any, value: Any) -> None:
    core.CFDictionarySetValue.argtypes = [
        __import__("ctypes").c_void_p,
        __import__("ctypes").c_void_p,
        __import__("ctypes").c_void_p,
    ]
    core.CFDictionarySetValue(mapping, key, value)


def _macos_cf_release(core: Any, *refs: Any) -> None:
    import ctypes

    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    for ref in refs:
        if ref:
            core.CFRelease(ref)


def _macos_sec_const(lib: Any, name: str) -> Any:
    import ctypes

    return ctypes.c_void_p.in_dll(lib, name)


def _macos_balanced_release(core: Any, query: Any, *created: Any) -> None:
    """Release create-refs then the dict (kCFType retain: create+dict = 2)."""
    _macos_cf_release(core, *created)
    _macos_cf_release(core, query)


def _macos_query_base(
    security: Any, core: Any, account: str
) -> tuple[Any, Any, Any]:
    """Return (query, service, account_cf). Caller must balanced-release."""
    service = _macos_cf_str(core, SERVICE_NAME)
    account_cf = _macos_cf_str(core, account)
    query = _macos_cf_mutable_dict(core)
    _macos_cf_set(
        core,
        query,
        _macos_sec_const(security, "kSecClass"),
        _macos_sec_const(security, "kSecClassGenericPassword"),
    )
    _macos_cf_set(core, query, _macos_sec_const(security, "kSecAttrService"), service)
    _macos_cf_set(core, query, _macos_sec_const(security, "kSecAttrAccount"), account_cf)
    return query, service, account_cf


def _macos_secitem_add(account: str, blob: bytes) -> int:
    import ctypes

    security, core = _macos_cf()
    query = service = account_cf = data = None
    try:
        query, service, account_cf = _macos_query_base(security, core, account)
        data = _macos_cf_data(core, blob)
        _macos_cf_set(core, query, _macos_sec_const(security, "kSecValueData"), data)
        security.SecItemAdd.restype = ctypes.c_int32
        security.SecItemAdd.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        return int(security.SecItemAdd(query, None))
    except (OSError, AttributeError, ValueError) as exc:
        raise SecretStoreError("macOS Keychain is unavailable") from exc
    finally:
        _macos_balanced_release(core, query, data, account_cf, service)


def _macos_secitem_update(account: str, blob: bytes) -> int:
    import ctypes

    security, core = _macos_cf()
    query = service = account_cf = data = attrs = None
    try:
        query, service, account_cf = _macos_query_base(security, core, account)
        data = _macos_cf_data(core, blob)
        attrs = _macos_cf_mutable_dict(core)
        _macos_cf_set(core, attrs, _macos_sec_const(security, "kSecValueData"), data)
        security.SecItemUpdate.restype = ctypes.c_int32
        security.SecItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        return int(security.SecItemUpdate(query, attrs))
    except (OSError, AttributeError, ValueError) as exc:
        raise SecretStoreError("macOS Keychain is unavailable") from exc
    finally:
        # attrs retained data; query retained service/account.
        _macos_cf_release(core, data)
        _macos_cf_release(core, attrs)
        _macos_balanced_release(core, query, account_cf, service)


def _macos_secitem_delete_query(account: str) -> int:
    import ctypes

    security, core = _macos_cf()
    query = service = account_cf = None
    try:
        query, service, account_cf = _macos_query_base(security, core, account)
        security.SecItemDelete.restype = ctypes.c_int32
        security.SecItemDelete.argtypes = [ctypes.c_void_p]
        return int(security.SecItemDelete(query))
    except (OSError, AttributeError, ValueError) as exc:
        raise SecretStoreError("macOS Keychain is unavailable") from exc
    finally:
        _macos_balanced_release(core, query, account_cf, service)


def _macos_secitem_copy(account: str) -> Optional[bytes]:
    import ctypes

    security, core = _macos_cf()
    query = service = account_cf = None
    result = ctypes.c_void_p()
    try:
        query, service, account_cf = _macos_query_base(security, core, account)
        _macos_cf_set(
            core,
            query,
            _macos_sec_const(security, "kSecReturnData"),
            _macos_sec_const(core, "kCFBooleanTrue"),
        )
        _macos_cf_set(
            core,
            query,
            _macos_sec_const(security, "kSecMatchLimit"),
            _macos_sec_const(security, "kSecMatchLimitOne"),
        )
        security.SecItemCopyMatching.restype = ctypes.c_int32
        security.SecItemCopyMatching.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        status = int(security.SecItemCopyMatching(query, ctypes.byref(result)))
        if status == _ERR_SEC_ITEM_NOT_FOUND:
            return None
        if status != _ERR_SEC_SUCCESS or not result.value:
            return None
        core.CFDataGetLength.restype = ctypes.c_long
        core.CFDataGetLength.argtypes = [ctypes.c_void_p]
        core.CFDataGetBytePtr.restype = ctypes.c_void_p
        core.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        length = int(core.CFDataGetLength(result))
        ptr = core.CFDataGetBytePtr(result)
        if not ptr or length <= 0:
            return None
        return ctypes.string_at(ptr, length)
    except (OSError, AttributeError, ValueError) as exc:
        raise SecretStoreError("macOS Keychain is unavailable") from exc
    finally:
        if result.value:
            core.CFRelease(result)
        _macos_balanced_release(core, query, account_cf, service)


# ── Windows Credential Manager ─────────────────────────────────────────────

def _windows_target(account: str) -> str:
    return f"{SERVICE_NAME}/{account}"


def _win_cred_get(target: str) -> Optional[str]:
    if sys.platform != "win32":
        return None
    cred = _win_cred_read(target)
    if cred is None:
        return None
    blob, blob_size = cred
    try:
        return blob[:blob_size].decode("utf-8") or None
    except UnicodeDecodeError:
        return None


def _win_cred_set(target: str, value: str) -> None:
    if sys.platform != "win32":
        raise SecretStoreError("Windows Credential Manager is not available")
    _win_cred_write(target, value.encode("utf-8"))


def _win_cred_delete(target: str) -> None:
    if sys.platform != "win32":
        return
    _win_cred_delete_target(target)


def _win_cred_list() -> list[str]:
    if sys.platform != "win32":
        return []
    prefix = f"{SERVICE_NAME}/"
    names: list[str] = []
    for target in _win_cred_enumerate(prefix):
        if target.startswith(prefix):
            account = target[len(prefix) :]
            if _ACCOUNT_RE.fullmatch(account):
                names.append(account)
    return names


def _win_cred_read(target: str) -> Optional[tuple[bytes, int]]:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    cred_ptr = ctypes.c_void_p()
    if not advapi32.CredReadW(target, 1, 0, ctypes.byref(cred_ptr)):
        return None
    try:
        class _CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.c_void_p),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        cred = ctypes.cast(cred_ptr, ctypes.POINTER(_CREDENTIAL)).contents
        size = int(cred.CredentialBlobSize)
        if not cred.CredentialBlob or size <= 0:
            return None
        blob = ctypes.string_at(cred.CredentialBlob, size)
        return blob, size
    finally:
        advapi32.CredFree(cred_ptr)


def _win_cred_write(target: str, blob: bytes) -> None:
    import ctypes
    from ctypes import wintypes

    class _CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.c_void_p),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    buffer = ctypes.create_string_buffer(blob)
    cred = _CREDENTIAL()
    cred.Type = 1  # CRED_TYPE_GENERIC
    cred.TargetName = target
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(buffer, ctypes.c_void_p)
    # CRED_PERSIST_LOCAL_MACHINE: current user profile (DPAPI). Not machine-wide.
    cred.Persist = 2
    cred.UserName = SERVICE_NAME
    if not advapi32.CredWriteW(ctypes.byref(cred), 0):
        raise SecretStoreError("Windows Credential Manager write failed")


def _win_cred_delete_target(target: str) -> None:
    import ctypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.CredDeleteW(target, 1, 0)


def _win_cred_enumerate(filter_prefix: str) -> list[str]:
    import ctypes
    from ctypes import wintypes

    class _CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.c_void_p),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    count = wintypes.DWORD()
    creds = ctypes.POINTER(ctypes.c_void_p)()
    if not advapi32.CredEnumerateW(
        filter_prefix + "*", 0, ctypes.byref(count), ctypes.byref(creds)
    ):
        return []
    names: list[str] = []
    try:
        for index in range(count.value):
            cred = ctypes.cast(creds[index], ctypes.POINTER(_CREDENTIAL)).contents
            if cred.TargetName:
                names.append(cred.TargetName)
    finally:
        advapi32.CredFree(creds)
    return names
