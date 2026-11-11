"""Unit tests: scans must not report "clean" when a check could not run."""

import asyncio
import subprocess
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

from src.core.exceptions import IaCScanError
from src.main import app
from src.scanners.aws_cloud.scanner import AWSCloudScanner
from src.scanners.iac.scanner import IaCScanner

SERVICES = ["s3", "ec2", "rds", "lambda", "vpc", "cloudtrail"]


class _AccessDeniedClient:
    """Stub AWS client: every API call raises AccessDenied."""

    def __init__(self, *args, **kwargs):
        pass

    def get_account_id(self) -> str:
        return "123456789012"

    def get_client(self, service, region=None):
        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "StubOperation"
        )

        def _raise(*args, **kwargs):
            raise error

        client = SimpleNamespace()
        client.exceptions = SimpleNamespace(
            ClientError=ClientError,
            NoSuchPublicAccessBlockConfiguration=type("NoSuch", (Exception,), {}),
        )
        client.get_paginator = _raise
        for name in (
            "list_buckets",
            "describe_security_groups",
            "describe_volumes",
            "describe_db_instances",
            "list_functions",
            "describe_vpcs",
            "describe_trails",
        ):
            setattr(client, name, _raise)
        return client


class TestCloudScanErrors:
    """AccessDenied on every call must be reported, not hidden."""

    def test_access_denied_is_recorded_per_service(self, monkeypatch):
        """Scan result should list the checks that could not run."""
        monkeypatch.setattr("src.scanners.aws_cloud.scanner.AWSClient", _AccessDeniedClient)
        scanner = AWSCloudScanner(regions=["us-east-1"], services=SERVICES, show_progress=False)

        result = asyncio.run(scanner.scan())

        assert result["total_findings"] == 0
        errors = result["metadata"]["scan_errors"]
        assert {e["service"] for e in errors} == set(SERVICES)
        assert all(e["error_code"] == "AccessDenied" for e in errors)
        assert {e["region"] for e in errors if e["service"] == "ec2"} == {"us-east-1"}

    def test_cli_exits_non_zero_and_does_not_say_clean(self, monkeypatch):
        """CLI should exit non-zero and not print 'No issues found!'."""
        monkeypatch.setattr("src.scanners.aws_cloud.scanner.AWSClient", _AccessDeniedClient)

        result = CliRunner().invoke(
            app, ["cloud", "scan", "-s", ",".join(SERVICES), "-r", "us-east-1"]
        )

        assert result.exit_code != 0
        assert "No issues found!" not in result.output
        assert "AccessDenied" in result.output


class TestIaCCheckovFailure:
    """Checkov producing no output with a non-zero exit must not look like a clean scan."""

    def test_checkov_crash_without_stdout_raises(self, monkeypatch, tmp_path):
        """Exit code 2 with only stderr should raise IaCScanError."""
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: subprocess.CompletedProcess(a, 2, stdout="", stderr="bad checks dir"),
        )

        with pytest.raises(IaCScanError):
            asyncio.run(IaCScanner(framework="terraform").scan(str(tmp_path)))
