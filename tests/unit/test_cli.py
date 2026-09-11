"""Unit tests for Mobile Sentinel CLI interface."""

import json
from click.testing import CliRunner
from sentinel.cli.main import cli
from sentinel import __version__, __app_name__


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Mobile Sentinel" in result.output
    assert "doctor" in result.output
    assert "scan" in result.output
    assert "version" in result.output


def test_cli_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_version_command() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output
    assert "Flutter / Android APK" in result.output


def test_cli_doctor_command() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    # Should execute and display environment report
    assert "MOBILE SENTINEL - ENVIRONMENT DOCTOR" in result.output
    assert "Python" in result.output


def test_cli_doctor_json_command() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--json-output"])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    assert "tools" in data
    assert "python" in data["tools"]
    assert "ready_for_scan" in data


def test_cli_scan_stub() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "dummy.apk"])
    assert result.exit_code == 0
    assert "Scan engine invoked for: dummy.apk" in result.output
