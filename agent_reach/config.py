# -*- coding: utf-8 -*-
"""Configuration management for Agent Reach.

Non-secret settings live in ~/.agent-reach/config.yaml. Sensitive values
(tokens, cookies, keys) go to the OS secret store. YAML remains migrate-from
and the AGENT_REACH_SECRETS=yaml dual-write escape hatch. Reads never create
files or directories; the private directory is created only on the first write.
"""

import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Optional

import yaml

from agent_reach.secrets import (
    VAULT_ITEMS_KEY,
    SecretStoreError,
    collect_store_accounts,
    get_backend,
    is_never_store_key,
    is_sensitive_key,
    migrate_from_mapping,
    yaml_dual_write_enabled,
)
from agent_reach.utils.paths import (
    PrivatePathError,
    ensure_no_symlink_path,
    home_dir,
    make_private_dir,
    read_small_text_no_follow,
)

_MAX_CONFIG_BYTES = 1024 * 1024


class ConfigError(RuntimeError):
    """Base class for configuration errors safe to show to the user."""


class ConfigReadOnlyError(ConfigError):
    """Raised when code tries to mutate an explicitly read-only config."""


class ConfigSecurityError(ConfigError):
    """Raised when a config path could redirect credential reads or writes."""


def _reject_symlink(path: Path, label: str) -> None:
    try:
        ensure_no_symlink_path(path, label)
    except PrivatePathError as exc:
        raise ConfigSecurityError(str(exc)) from exc


def _atomic_write_yaml(target: Path, data: dict) -> None:
    """Atomically replace ``target`` with owner-only YAML.

    The temporary file lives beside the target so ``os.replace`` remains an
    atomic same-filesystem operation. Existing symlinks are rejected rather
    than followed or silently replaced.
    """
    _reject_symlink(target, "配置文件")
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                data,
                handle,
                default_flow_style=False,
                allow_unicode=True,
            )
            handle.flush()
            os.fsync(handle.fileno())

        # Fail closed if a link appeared while serialization was in progress.
        # A later race is still safe: os.replace replaces a directory entry and
        # never follows the symlink into its target.
        _reject_symlink(target, "配置文件")
        os.replace(tmp_path, target)
        if os.name != "nt":
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)

        # Persist the rename where directory fsync is supported.
        if os.name != "nt" and hasattr(os, "O_DIRECTORY"):
            try:
                dir_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class Config:
    """Manages Agent Reach configuration."""

    CONFIG_DIR = home_dir() / ".agent-reach"
    CONFIG_FILE = CONFIG_DIR / "config.yaml"

    # Feature → required config keys
    FEATURE_REQUIREMENTS = {
        "exa_search": ["exa_api_key"],
        "twitter_xreach": ["twitter_auth_token", "twitter_ct0"],  # legacy key name; used by twitter-cli
        "groq_whisper": ["groq_api_key"],
        "openai_whisper": ["openai_api_key"],
        "github_token": ["github_token"],
    }

    def __init__(
        self,
        config_path: Optional[Path] = None,
        *,
        read_only: bool = False,
    ):
        self.config_path = Path(config_path) if config_path else self.CONFIG_FILE
        self.config_dir = self.config_path.parent
        self.read_only = read_only
        self.data: dict = {}
        self.load()

    def _ensure_dir(self):
        """Create config directory if it doesn't exist."""
        _reject_symlink(self.config_dir, "配置目录")
        make_private_dir(self.config_dir)
        _reject_symlink(self.config_dir, "配置目录")

    def load(self):
        """Load config from YAML file."""
        _reject_symlink(self.config_dir, "配置目录")
        _reject_symlink(self.config_path, "配置文件")
        try:
            payload = read_small_text_no_follow(
                self.config_path,
                max_bytes=_MAX_CONFIG_BYTES,
            )
        except PrivatePathError as exc:
            raise ConfigSecurityError(str(exc)) from exc
        if payload is None:
            self.data = {}
            return

        loaded = yaml.safe_load(payload) or {}
        if not isinstance(loaded, dict):
            raise ConfigError("配置文件顶层必须是对象")
        self.data = loaded

    def save(self):
        """Save config atomically, refusing mutation in read-only mode."""
        if self.read_only:
            raise ConfigReadOnlyError("当前配置是只读的，不能保存")
        self._ensure_dir()
        _atomic_write_yaml(self.config_path, self.data)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value.

        Sensitive keys: OS store, then YAML leftover, then env (uppercase).
        Twitter cookies are never-store: env only.
        Non-secret keys: YAML, then env (uppercase).
        """
        if is_never_store_key(key):
            env_val = os.environ.get(key.upper())
            if env_val:
                return env_val
            return default

        if is_sensitive_key(key):
            try:
                stored = get_backend().get(key)
            except SecretStoreError:
                stored = None
            if stored:
                return stored
            if key in self.data:
                yaml_value = self.data[key]
                if yaml_value not in (None, ""):
                    return yaml_value
            env_val = os.environ.get(key.upper())
            if env_val:
                return env_val
            return default

        if key in self.data:
            return self.data[key]
        env_val = os.environ.get(key.upper())
        if env_val:
            return env_val
        return default

    def set(self, key: str, value: Any):
        """Set a config value and save."""
        if self.read_only:
            raise ConfigReadOnlyError("当前配置是只读的，不能修改")
        if is_never_store_key(key):
            raise ConfigError(
                "Twitter cookies are not stored by Agent Reach; "
                "export TWITTER_AUTH_TOKEN and TWITTER_CT0 in the twitter process"
            )

        missing = object()
        previous = self.data.get(key, missing)
        previous_accounts = list(self.data.get(VAULT_ITEMS_KEY) or [])
        previous_secret = None
        wrote_store = False
        store_this = is_sensitive_key(key) and isinstance(value, str) and bool(value)

        try:
            if store_this:
                backend = get_backend()
                previous_secret = backend.get(key)
                backend.set(key, value)
                wrote_store = True
                self._remember_store_account(key)
                if yaml_dual_write_enabled():
                    self.data[key] = value
                else:
                    self.data.pop(key, None)
            else:
                if is_sensitive_key(key):
                    get_backend().delete(key)
                    self._forget_store_account(key)
                self.data[key] = value
            self.save()
        except SecretStoreError as exc:
            if wrote_store:
                try:
                    backend = get_backend()
                    if previous_secret is None:
                        backend.delete(key)
                    else:
                        backend.set(key, previous_secret)
                except SecretStoreError:
                    pass
            if previous is missing:
                self.data.pop(key, None)
            else:
                self.data[key] = previous
            if previous_accounts:
                self.data[VAULT_ITEMS_KEY] = previous_accounts
            else:
                self.data.pop(VAULT_ITEMS_KEY, None)
            raise ConfigError("OS secret store write failed") from exc
        except BaseException:
            if wrote_store:
                try:
                    backend = get_backend()
                    if previous_secret is None:
                        backend.delete(key)
                    else:
                        backend.set(key, previous_secret)
                except SecretStoreError:
                    pass
            if previous is missing:
                self.data.pop(key, None)
            else:
                self.data[key] = previous
            if previous_accounts:
                self.data[VAULT_ITEMS_KEY] = previous_accounts
            else:
                self.data.pop(VAULT_ITEMS_KEY, None)
            raise

    def delete(self, key: str):
        """Delete a config key and save.

        Never-store Twitter keys may still be scrubbed from leftover YAML.
        """
        if self.read_only:
            raise ConfigReadOnlyError("当前配置是只读的，不能修改")
        missing = object()
        previous = self.data.pop(key, missing)
        previous_accounts = list(self.data.get(VAULT_ITEMS_KEY) or [])
        previous_secret = None
        deleted_store = False
        try:
            if is_sensitive_key(key) and not is_never_store_key(key):
                backend = get_backend()
                previous_secret = backend.get(key)
                backend.delete(key)
                deleted_store = True
                self._forget_store_account(key)
            self.save()
        except BaseException:
            if previous is not missing:
                self.data[key] = previous
            if previous_accounts:
                self.data[VAULT_ITEMS_KEY] = previous_accounts
            else:
                self.data.pop(VAULT_ITEMS_KEY, None)
            if deleted_store and previous_secret is not None:
                try:
                    get_backend().set(key, previous_secret)
                except SecretStoreError:
                    pass
            raise

    def migrate_secrets_to_store(self) -> list[str]:
        """Copy sensitive YAML leftovers into the OS store. Do not delete YAML."""
        if self.read_only:
            raise ConfigReadOnlyError("当前配置是只读的，不能修改")
        try:
            copied = migrate_from_mapping(self.data)
            for name in copied:
                self._remember_store_account(name)
            if copied:
                self.save()
            return copied
        except SecretStoreError as exc:
            raise ConfigError("OS secret store write failed") from exc

    def stored_secret_accounts(self) -> set[str]:
        """Account names we may have written. Names only, never values."""
        return collect_store_accounts(self.data)

    def _remember_store_account(self, key: str) -> None:
        items = [str(item) for item in (self.data.get(VAULT_ITEMS_KEY) or []) if item]
        if key not in items:
            items.append(key)
        self.data[VAULT_ITEMS_KEY] = items

    def _forget_store_account(self, key: str) -> None:
        items = [
            str(item)
            for item in (self.data.get(VAULT_ITEMS_KEY) or [])
            if item and item != key
        ]
        if items:
            self.data[VAULT_ITEMS_KEY] = items
        else:
            self.data.pop(VAULT_ITEMS_KEY, None)

    def is_configured(self, feature: str) -> bool:
        """Check if a feature has all required config."""
        required = self.FEATURE_REQUIREMENTS.get(feature, [])
        return all(self.get(k) for k in required)

    def get_configured_features(self) -> dict:
        """Return status of all optional features."""
        return {
            feature: self.is_configured(feature)
            for feature in self.FEATURE_REQUIREMENTS
        }

    def to_dict(self) -> dict:
        """Return config as dict (masks sensitive values)."""
        masked = {}
        for k, v in self.data.items():
            if k == VAULT_ITEMS_KEY:
                masked[k] = list(v) if isinstance(v, list) else v
            elif is_sensitive_key(k):
                masked[k] = "[REDACTED]" if v else None
            else:
                masked[k] = v
        for account in self.data.get(VAULT_ITEMS_KEY) or []:
            if not isinstance(account, str) or account in masked:
                continue
            masked[account] = "[REDACTED]"
        return masked
