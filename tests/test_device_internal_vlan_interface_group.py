# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the internal VLAN range and interface group support of
pyaoscx.device.Device.
"""

import json
from unittest.mock import MagicMock

import pytest

from pyaoscx.device import Device
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.unsupported_capability_error import (
    UnsupportedCapabilityError,
)


def make_device(get_responses):
    """
    Build a Device without contacting a switch. get_responses maps the
    beginning of a GET URI to (status_code, body).
    """
    session = MagicMock()
    session.connected = True

    def request(verb, uri, *args, **kwargs):
        if verb == "GET":
            for prefix, (code, body) in get_responses.items():
                if uri.startswith(prefix):
                    text = body if isinstance(body, str) else json.dumps(body)
                    return MagicMock(status_code=code, text=text)
            raise AssertionError("unexpected GET " + uri)
        return MagicMock(status_code=204 if verb == "PATCH" else 200, text="")

    session.request.side_effect = request
    device = Device.__new__(Device)
    device.session = session
    return device


def writes(device, verb):
    calls = [
        c for c in device.session.request.call_args_list if c.args[0] == verb
    ]
    return [(c.args[1], json.loads(c.kwargs["data"])) for c in calls]


def range_device(data, code=200):
    return make_device({"system?attributes=internal": (code, data)})


def test_get_internal_vlan_range():
    device = range_device(
        {"internal_vlan_range_base": 3000, "internal_vlan_range_size": 1000}
    )
    assert device.get_internal_vlan_range() == (3000, 3999)


def test_get_internal_vlan_range_not_configured():
    assert range_device({}).get_internal_vlan_range() is None


def test_set_internal_vlan_range():
    device = range_device({})
    assert device.set_internal_vlan_range(3000, 3499) is True
    assert writes(device, "PATCH") == [
        (
            "system",
            {
                "internal_vlan_range_base": 3000,
                "internal_vlan_range_size": 500,
            },
        )
    ]


def test_set_internal_vlan_range_is_idempotent():
    device = range_device(
        {"internal_vlan_range_base": 3000, "internal_vlan_range_size": 1000}
    )
    assert device.set_internal_vlan_range(3000, 3999) is False
    assert writes(device, "PATCH") == []


@pytest.mark.parametrize("start,end", [(1, 10), (10, 4095), (20, 10)])
def test_set_internal_vlan_range_invalid(start, end):
    device = range_device({})
    with pytest.raises(ParameterError):
        device.set_internal_vlan_range(start, end)
    assert device.session.request.call_count == 0


def test_internal_vlan_range_unsupported_platform():
    device = range_device(
        "attribute: internal_vlan_range_base, not found for resource: System",
        code=400,
    )
    with pytest.raises(UnsupportedCapabilityError):
        device.set_internal_vlan_range(3000, 3999)
    assert writes(device, "PATCH") == []


def delete_device(interfaces):
    return make_device(
        {
            "system?attributes=internal": (
                200,
                {
                    "internal_vlan_range_base": 3000,
                    "internal_vlan_range_size": 1000,
                },
            ),
            "system/interfaces?": (200, interfaces),
        }
    )


def test_delete_internal_vlan_range():
    device = delete_device(
        {
            "loopback0": {"type": "loopback", "routing": True},
            "1/1/1": {"type": "system", "routing": False},
            "vlan10": {"type": "vlan", "routing": True},
        }
    )
    assert device.delete_internal_vlan_range() is True
    assert writes(device, "PATCH") == [
        (
            "system",
            {
                "internal_vlan_range_base": None,
                "internal_vlan_range_size": None,
            },
        )
    ]


def test_delete_absent_internal_vlan_range_is_noop():
    device = range_device(
        {"internal_vlan_range_base": 0, "internal_vlan_range_size": 0}
    )
    assert device.delete_internal_vlan_range() is False
    assert writes(device, "PATCH") == []


def test_delete_internal_vlan_range_refused_with_routed_ports():
    device = delete_device(
        {
            "1/1/23": {"type": "system", "routing": True},
            "lag1": {"type": "lag", "routing": True},
        }
    )
    with pytest.raises(ParameterError, match="1/1/23, lag1"):
        device.delete_internal_vlan_range()
    assert writes(device, "PATCH") == []


SUBSYSTEMS = {
    "chassis,1": {"interface_group_info": {}},
    "line_card,1/1": {
        "interface_group_speed": {"2": "50g"},
        "interface_group_applied_speed": {"1": "25g", "2": "50g"},
        "interface_group_default_speed": {"1": "25g", "2": "25g"},
        "interface_group_info": {
            "1": {"10g": "1000,10000", "25g": "25000"},
            "2": {"25g": "100,1000,10000,25000", "50g": "50000"},
        },
    },
}
LINE_CARD_CONFIG = {
    "admin_state": "up",
    "interface_group_speed": {"2": "50g"},
}


def group_device(subsystems=None):
    return make_device(
        {
            "system/subsystems?": (200, subsystems or SUBSYSTEMS),
            "system/subsystems/line_card,1%2F": (200, LINE_CARD_CONFIG),
        }
    )


def test_get_interface_groups():
    groups = group_device().get_interface_groups()
    assert list(groups) == ["line_card,1/1"]
    assert groups["line_card,1/1"]["1"] == {
        "speed": None,
        "applied_speed": "25g",
        "default_speed": "25g",
        "speeds": {"10g": "1000,10000", "25g": "25000"},
    }
    assert groups["line_card,1/1"]["2"]["speed"] == "50g"


def test_set_interface_group_speed_keeps_other_config():
    device = group_device()
    assert device.set_interface_group_speed(1, "10g") is True
    assert writes(device, "PUT") == [
        (
            "system/subsystems/line_card,1%2F1",
            {
                "admin_state": "up",
                "interface_group_speed": {"1": "10g", "2": "50g"},
            },
        )
    ]


def test_set_interface_group_speed_default_removes_group():
    device = group_device()
    assert device.set_interface_group_speed("2", None) is True
    _, body = writes(device, "PUT")[0]
    assert body["interface_group_speed"] == {}


def test_set_interface_group_speed_is_idempotent():
    device = group_device()
    assert device.set_interface_group_speed(2, "50g") is False
    assert device.set_interface_group_speed(1, None) is False
    assert writes(device, "PUT") == []


def test_set_interface_group_speed_invalid_speed():
    device = group_device()
    with pytest.raises(ParameterError):
        device.set_interface_group_speed(1, "50g")
    assert writes(device, "PUT") == []


def test_set_interface_group_speed_unknown_group():
    with pytest.raises(ParameterError):
        group_device().set_interface_group_speed(9, "25g")


def test_set_interface_group_speed_needs_line_module_when_ambiguous():
    subsystems = dict(SUBSYSTEMS)
    subsystems["line_card,1/3"] = SUBSYSTEMS["line_card,1/1"]
    device = group_device(subsystems)
    with pytest.raises(ParameterError):
        device.set_interface_group_speed(1, "10g")
    assert device.set_interface_group_speed(1, "10g", line_module="1/3")
    uri, _ = writes(device, "PUT")[0]
    assert uri == "system/subsystems/line_card,1%2F3"
