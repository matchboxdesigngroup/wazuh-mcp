"""Tests for CLI entry point and settings overrides."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp.__main__ import main, parse_args, settings_from


def test_settings_from_normalises_http_path():
    args = parse_args(["--path", "mcp/"])
    settings = settings_from(args)
    assert settings.http_path == "/mcp"


def test_settings_from_rejects_invalid_port():
    args = parse_args(["--port", "70000"])
    with pytest.raises(ValidationError, match="bind_port"):
        settings_from(args)


def test_main_returns_2_on_invalid_port(capsys):
    code = main(["--transport", "http", "--port", "70000"])
    assert code == 2
    captured = capsys.readouterr()
    assert "bind_port" in captured.err.lower() or "port" in captured.err.lower()
    assert "wazuh-mcp:" in captured.err
