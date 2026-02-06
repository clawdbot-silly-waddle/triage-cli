"""Tests for configuration management."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from triage.config import ConfigError, get_api_key, load_config_file


class TestConfigLoading:
    """Test configuration loading."""

    def test_load_missing_config(self, tmp_path):
        """Test loading non-existent config returns empty dict."""
        config_path = tmp_path / "nonexistent.toml"
        result = load_config_file(config_path)
        assert result == {}

    def test_load_valid_config(self, tmp_path):
        """Test loading valid config file."""
        config_path = tmp_path / "config.toml"
        config_path.write_text('api_key = "test-key-123"\n')
        result = load_config_file(config_path)
        assert result == {"api_key": "test-key-123"}


class TestAPIKeyResolution:
    """Test API key resolution priority."""

    def test_env_var_priority(self, tmp_path, monkeypatch):
        """Test that env var takes priority over config file."""
        config_path = tmp_path / "config.toml"
        config_path.write_text('api_key = "config-key"\n')

        monkeypatch.setenv("TRIAGE_API_KEY", "env-key")

        with patch("triage.config.DEFAULT_CONFIG_PATH", config_path):
            result = get_api_key()
            assert result == "env-key"

    def test_config_file_fallback(self, tmp_path, monkeypatch):
        """Test that config file is used when env var is not set."""
        config_path = tmp_path / "config.toml"
        config_path.write_text('api_key = "config-key"\n')

        monkeypatch.delenv("TRIAGE_API_KEY", raising=False)

        with patch("triage.config.DEFAULT_CONFIG_PATH", config_path):
            result = get_api_key()
            assert result == "config-key"

    def test_missing_api_key(self, tmp_path, monkeypatch):
        """Test that ConfigError is raised when no API key is found."""
        config_path = tmp_path / "config.toml"
        config_path.write_text("")

        monkeypatch.delenv("TRIAGE_API_KEY", raising=False)

        with patch("triage.config.DEFAULT_CONFIG_PATH", config_path):
            with pytest.raises(ConfigError, match="No API key found"):
                get_api_key()

    def test_config_error_has_help_text(self, tmp_path, monkeypatch):
        """Test that ConfigError includes helpful instructions."""
        config_path = tmp_path / "config.toml"
        config_path.write_text("")

        monkeypatch.delenv("TRIAGE_API_KEY", raising=False)

        with patch("triage.config.DEFAULT_CONFIG_PATH", config_path):
            with pytest.raises(ConfigError) as exc_info:
                get_api_key()

            error_message = str(exc_info.value)
            assert "TRIAGE_API_KEY" in error_message
            assert "config.toml" in error_message
