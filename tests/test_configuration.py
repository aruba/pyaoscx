# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""Offline unit tests for CLI configuration upload."""

import base64

from unittest.mock import MagicMock

import pytest

import json

from pyaoscx.configuration import Configuration
from pyaoscx.exceptions.config_upload_error import ConfigUploadError
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.verification_error import VerificationError

CLI = "hostname sw1\nvlan 10\n    name TEST\n"


def make_session(status_code=200, text='{"state":"success"}'):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    session.request.return_value = resp
    return session


@pytest.fixture
def cli_file(tmp_path):
    path = tmp_path / "running.cli"
    path.write_text(CLI)
    return str(path)


@pytest.mark.parametrize(
    "kwargs, operation",
    [({}, "replace"), ({"operation": "merge"}, "merge")],
)
def test_upload_cli(cli_file, kwargs, operation):
    s = make_session()
    assert Configuration(s).upload_switch_config(
        config_name="running-config", config_cli=cli_file, **kwargs
    )
    s.request.assert_called_once_with(
        "PUT",
        "configs/running-config",
        params={"operation": operation},
        data=base64.b64encode(CLI.encode()).decode(),
        headers={"Content-Type": "text/plain"},
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"config_name": "checkpoint1"},
        {"operation": "append"},
        {"config_file": "/tmp/x.json"},
        {"remote_file_tftp_path": "tftp://1.1.1.1/x", "vrf": "mgmt"},
    ],
)
def test_upload_cli_invalid(cli_file, kwargs):
    s = make_session()
    kwargs.setdefault("config_name", "running-config")
    with pytest.raises(VerificationError):
        Configuration(s).upload_switch_config(config_cli=cli_file, **kwargs)
    s.request.assert_not_called()


def test_upload_cli_switch_errors(cli_file):
    errors = [
        {
            "line": 34,
            "context": ["configure terminal", "interface 1/1/2"],
            "command": "    vlan acess 10",
            "message": "Invalid input: acess",
        },
        {
            "line": 97,
            "context": ["configure terminal"],
            "command": "router osf 1",
            "message": "Invalid input: osf",
        },
    ]
    s = make_session(text=json.dumps({"state": "failure", "errors": errors}))
    with pytest.raises(ConfigUploadError) as exc:
        Configuration(s).upload_switch_config_cli_from_local(
            cli_file, operation="merge"
        )
    assert exc.value.errors == errors
    assert exc.value.operation == "merge"
    assert str(exc.value) == (
        "CONFIGURATION UPLOAD ERROR: "
        "line 34 (interface 1/1/2): 'vlan acess 10': Invalid input: acess; "
        "line 97: 'router osf 1': Invalid input: osf"
    )


@pytest.mark.parametrize(
    "status_code, unsupported",
    [(400, True), (404, True), (405, True), (415, True), (500, False)],
)
def test_upload_cli_refused(cli_file, status_code, unsupported):
    s = make_session(status_code=status_code, text="Unsupported Media Type")
    with pytest.raises(GenericOperationError) as exc:
        Configuration(s).upload_switch_config_cli_from_local(cli_file)
    assert not isinstance(exc.value, ConfigUploadError)
    assert exc.value.response_code == status_code
    assert "Unsupported Media Type" in exc.value.message
    assert ("probably not supported" in exc.value.message) is unsupported
