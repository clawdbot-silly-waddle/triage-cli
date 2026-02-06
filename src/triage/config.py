"""Configuration management for Triage CLI."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import toml

if TYPE_CHECKING:
    from typing import Any

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "triage"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"
ENV_VAR_NAME = "TRIAGE_API_KEY"


class ConfigError(Exception):
    """Raised when configuration is invalid or missing."""

    def __init__(self, message: str, help_text: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.help_text = help_text

    def __str__(self) -> str:
        if self.help_text:
            return f"{self.message}\n\n{self.help_text}"
        return self.message


def get_config_path() -> Path:
    """Get the path to the config file."""
    return DEFAULT_CONFIG_PATH


def load_config_file(config_path: Path | None = None) -> dict[str, Any]:
    """Load configuration from the config file.

    Args:
        config_path: Optional path to config file. Defaults to ~/.config/triage/config.toml

    Returns:
        Dictionary containing configuration values
    """
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return toml.load(f)
    except (toml.TomlDecodeError, OSError):
        return {}


def get_api_key() -> str:
    """Get API key from environment or config file.

    Priority:
        1. Environment variable TRIAGE_API_KEY
        2. Config file ~/.config/triage/config.toml

    Returns:
        The API key string

    Raises:
        ConfigError: If no API key is found
    """
    # Check environment variable first
    env_key = os.environ.get(ENV_VAR_NAME)
    if env_key:
        return env_key

    # Check config file
    config = load_config_file()
    if "api_key" in config and config["api_key"]:
        return config["api_key"]

    # No API key found
    raise ConfigError(
        "No API key found.",
        help_text=(
            "Please configure your API key using one of these methods:\n"
            f"1. Set environment variable: export {ENV_VAR_NAME}=your-api-key\n"
            f"2. Create config file at {DEFAULT_CONFIG_PATH}:\n"
            '   api_key = "your-api-key"'
        ),
    )


def ensure_config_dir() -> None:
    """Ensure the config directory exists."""
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_config(api_key: str, config_path: Path | None = None) -> None:
    """Save API key to config file.

    Args:
        api_key: The API key to save
        config_path: Optional path to config file
    """
    path = config_path or DEFAULT_CONFIG_PATH
    ensure_config_dir()
    config = {"api_key": api_key}
    with open(path, "w", encoding="utf-8") as f:
        toml.dump(config, f)
