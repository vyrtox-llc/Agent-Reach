# -*- coding: utf-8 -*-
"""OS secret store + Config migration (Phase 3 / F11.5)."""

from __future__ import annotations

from argparse import Namespace

import pytest
import yaml

from agent_reach import cli
from agent_reach.config import Config, ConfigError
from agent_reach.secrets import (
    SERVICE_NAME,
    MemoryBackend,
    get_backend,
    is_never_store_key,
    is_sensitive_key,
    migrate_from_mapping,
    set_backend,
)


@pytest.fixture
def tmp_config(tmp_path):
    """Config with a temporary path (MemoryBackend from isolated_home)."""
    return Config(config_path=tmp_path / "config.yaml")


def test_yaml_leftover_secret_keys_names_only():
    from agent_reach.secrets import yaml_leftover_secret_keys

    names = yaml_leftover_secret_keys(
        {
            "github_token": "secret-value",
            "prefer_backend": "opencli",
            "vault_items": ["github_token"],
            "twitter_auth_token": "leftover",
            "empty_key": "",
        }
    )
    assert names == ["github_token", "twitter_auth_token"]
    assert "secret-value" not in names
    assert "leftover" not in names


def test_doctor_warns_on_yaml_leftover_secrets_without_leaking(
    isolated_home, monkeypatch
):
    import re

    import agent_reach.doctor as doctor_mod

    config_dir = isolated_home / ".agent-reach"
    config_dir.mkdir(parents=True)
    (config_dir / "config.yaml").write_text(
        "github_token: leftover-secret-value\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(Config, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(Config, "CONFIG_FILE", config_dir / "config.yaml")

    report = doctor_mod.format_report({})
    plain = re.sub(r"\[[^\]]*\]", "", report)
    assert "明文密钥残留" in plain
    assert "github_token" in plain
    assert "migrate-secrets" in plain
    assert "leftover-secret-value" not in plain


def test_memory_backend_round_trip():
    backend = MemoryBackend()
    backend.set("github_token", "ghp-secret")
    assert backend.get("github_token") == "ghp-secret"
    assert backend.list_accounts() == ["github_token"]
    backend.delete("github_token")
    assert backend.get("github_token") is None
    assert backend.list_accounts() == []


def test_sensitive_markers_match_product_contract():
    assert is_sensitive_key("github_token")
    assert is_sensitive_key("groq_api_key")
    assert is_sensitive_key("proxy")
    assert is_sensitive_key("xueqiu_cookie")
    assert is_never_store_key("twitter_auth_token")
    assert is_never_store_key("twitter_ct0")
    assert not is_sensitive_key("backend_override")
    assert not is_sensitive_key("vault_items")


def test_config_sensitive_write_goes_to_store_not_yaml(tmp_config):
    secret = "ghp-never-in-yaml"
    tmp_config.set("github_token", secret)

    assert tmp_config.get("github_token") == secret
    assert "github_token" not in tmp_config.data
    assert "github_token" in (tmp_config.data.get("vault_items") or [])
    raw = tmp_config.config_path.read_text(encoding="utf-8")
    assert secret not in raw
    assert "github_token:" not in raw


def test_config_read_order_store_then_yaml_then_env(tmp_config, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    tmp_config.data["github_token"] = "from-yaml"
    assert tmp_config.get("github_token") == "from-yaml"

    get_backend().set("github_token", "from-store")
    assert tmp_config.get("github_token") == "from-store"


def test_yaml_dual_write_only_when_env_set(tmp_config, monkeypatch):
    monkeypatch.setenv("AGENT_REACH_SECRETS", "yaml")
    secret = "dual-write-secret"
    tmp_config.set("groq_api_key", secret)

    assert tmp_config.data.get("groq_api_key") == secret
    assert get_backend().get("groq_api_key") == secret


def test_migrate_copies_without_deleting_yaml_or_logging(tmp_config, capsys):
    leftover = "legacy-yaml-token"
    tmp_config.data["openai_api_key"] = leftover
    tmp_config.save()

    copied = tmp_config.migrate_secrets_to_store()

    assert "openai_api_key" in copied
    assert get_backend().get("openai_api_key") == leftover
    assert tmp_config.data.get("openai_api_key") == leftover
    out = capsys.readouterr()
    assert leftover not in out.out
    assert leftover not in out.err


def test_migrate_skips_twitter_never_store(tmp_config):
    tmp_config.data["twitter_auth_token"] = "should-not-migrate"
    tmp_config.data["twitter_ct0"] = "should-not-migrate-ct0"
    tmp_config.save()

    copied = migrate_from_mapping(tmp_config.data)

    assert copied == []
    assert get_backend().get("twitter_auth_token") is None
    assert get_backend().get("twitter_ct0") is None


def test_config_refuses_twitter_persist(tmp_config):
    with pytest.raises(ConfigError, match="not stored"):
        tmp_config.set("twitter_auth_token", "nope")
    assert get_backend().get("twitter_auth_token") is None
    assert "twitter_auth_token" not in tmp_config.data


def test_to_dict_redacts_store_backed_and_yaml_leftovers(tmp_config):
    tmp_config.set("github_token", "store-secret")
    tmp_config.data["xhs_cookie"] = "yaml-leftover-secret"
    masked = tmp_config.to_dict()

    dumped = str(masked)
    assert masked["github_token"] == "[REDACTED]"
    assert masked["xhs_cookie"] == "[REDACTED]"
    assert "store-secret" not in dumped
    assert "yaml-leftover-secret" not in dumped


def test_configure_twitter_does_not_persist(monkeypatch, capsys):
    import shutil

    import agent_reach.config as config_module

    class RecordingConfig:
        def __init__(self):
            self.data = {}
            self.sets = []

        def get(self, key, default=None):
            return self.data.get(key, default)

        def set(self, key, value):
            self.sets.append((key, value))
            self.data[key] = value

    config = RecordingConfig()
    monkeypatch.setattr(config_module, "Config", lambda: config)
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    cli._cmd_configure(
        Namespace(
            from_browser=None,
            key="twitter-cookies",
            value=["auth-value", "ct0-value"],
            sync_legacy_twitter=False,
            read_stdin=False,
        )
    )

    assert config.sets == []
    assert "twitter_auth_token" not in config.data
    assert "twitter_ct0" not in config.data
    output = capsys.readouterr().out
    assert "不会写入" in output
    assert "TWITTER_AUTH_TOKEN" in output
    assert "auth-value" not in output
    assert "ct0-value" not in output


@pytest.mark.parametrize("sync_legacy", [False, True])
def test_twitter_legacy_sync_still_opt_in_without_ar_persist(
    monkeypatch, capsys, sync_legacy
):
    import shutil

    import agent_reach.config as config_module
    import agent_reach.cookie_extract as cookie_extract

    calls = []

    class C:
        def get(self, key, default=None):
            return default

        def set(self, key, value):
            raise AssertionError("twitter cookies must not call config.set")

    monkeypatch.setattr(config_module, "Config", C)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        cookie_extract,
        "_sync_xfetch_session",
        lambda auth, ct0: calls.append(("xfetch", auth, ct0)) or True,
    )
    monkeypatch.setattr(
        cookie_extract,
        "_sync_bird_env",
        lambda auth, ct0: calls.append(("bird", auth, ct0)) or True,
    )

    cli._cmd_configure(
        Namespace(
            from_browser=None,
            key="twitter-cookies",
            value=["auth-value", "ct0-value"],
            sync_legacy_twitter=sync_legacy,
            read_stdin=False,
        )
    )

    assert bool(calls) is sync_legacy
    output = capsys.readouterr().out
    assert ("Legacy copies written" in output) is sync_legacy


def test_uninstall_deletes_store_items(isolated_home, monkeypatch, capsys):
    backend = get_backend()
    backend.set("github_token", "to-delete")
    config = Config()
    config.set("github_token", "to-delete")

    cli._cmd_uninstall(Namespace(dry_run=False, keep_config=False))

    assert backend.get("github_token") is None
    assert not (isolated_home / ".agent-reach").exists()
    out = capsys.readouterr().out
    assert SERVICE_NAME in out
    assert "to-delete" not in out


def test_uninstall_keep_config_keeps_store(isolated_home, capsys):
    backend = get_backend()
    Config().set("groq_api_key", "keep-me")
    assert (isolated_home / ".agent-reach" / "config.yaml").exists()

    cli._cmd_uninstall(Namespace(dry_run=False, keep_config=True))

    assert backend.get("groq_api_key") == "keep-me"
    assert (isolated_home / ".agent-reach" / "config.yaml").exists()
    out = capsys.readouterr().out
    assert "--keep-config" in out
    assert "keep-me" not in out


def test_migrate_secrets_cli_does_not_print_values(tmp_config, monkeypatch, capsys):
    import agent_reach.config as config_module

    secret = "cli-migrate-secret"
    tmp_config.data["github_token"] = secret
    tmp_config.save()
    monkeypatch.setattr(config_module, "Config", lambda: tmp_config)

    cli._cmd_migrate_secrets()

    out = capsys.readouterr()
    assert "github_token" in out.out
    assert secret not in out.out
    assert secret not in out.err
    assert get_backend().get("github_token") == secret


def test_0600_still_applies_with_store_backed_writes(tmp_path):
    import stat
    import sys

    config_file = tmp_path / "secure_config.yaml"
    config = Config(config_path=config_file)
    config.set("github_token", "perm-secret")

    if sys.platform != "win32":
        mode = config_file.stat().st_mode
        assert not (mode & stat.S_IRGRP)
        assert not (mode & stat.S_IROTH)
    payload = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert "github_token" not in payload
    assert "github_token" in payload.get("vault_items", [])
