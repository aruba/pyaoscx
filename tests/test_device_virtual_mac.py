# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for pyaoscx.device.Device.set_virtual_mac.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from pyaoscx.device import Device


def make_device(config):
    """Build a Device without contacting a switch."""
    device = Device.__new__(Device)
    session = MagicMock()
    session.api = SimpleNamespace(
        default_selector="configuration", default_depth=0
    )
    get_response = MagicMock(status_code=200, text=json.dumps(config))
    put_response = MagicMock(status_code=200, text="")
    session.request.side_effect = lambda verb, *a, **k: (
        get_response if verb == "GET" else put_response
    )
    device.session = session
    return device, session


def put_payload(session):
    puts = [c for c in session.request.call_args_list if c.args[0] == "PUT"]
    return json.loads(puts[0].kwargs["data"]) if puts else None


def test_set_virtual_mac():
    device, session = make_device({"other_config": {}})
    assert device.set_virtual_mac("02:00:00:00:00:AA") is True
    assert put_payload(session)["virtual_mac"] == "02:00:00:00:00:aa"


def test_set_virtual_mac_is_idempotent():
    device, session = make_device({"virtual_mac": "02:00:00:00:00:aa"})
    assert device.set_virtual_mac("02:00:00:00:00:AA") is False
    assert put_payload(session) is None


def test_remove_virtual_mac():
    device, session = make_device({"virtual_mac": "02:00:00:00:00:aa"})
    assert device.set_virtual_mac(None) is True
    assert "virtual_mac" not in put_payload(session)


def test_remove_absent_virtual_mac_is_noop():
    device, session = make_device({})
    assert device.set_virtual_mac(None) is False
