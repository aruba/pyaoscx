# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for Group Based Policy support: Device.set_gbp_enable and
the GbpRole class.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from pyaoscx.device import Device
from pyaoscx.gbp_role import GbpRole


def make_session(get_data):
    session = MagicMock()
    session.connected = True
    session.api = SimpleNamespace(
        default_selector="configuration",
        default_depth=1,
        valid_selectors=["configuration", "writable", "status"],
        configurable_selectors=["configuration", "writable"],
        valid_depth=lambda depth: True,
    )
    get_response = MagicMock(status_code=200, text=json.dumps(get_data))
    responses = {
        "GET": get_response,
        "POST": MagicMock(status_code=201, text=""),
    }
    session.request.side_effect = lambda verb, *a, **k: responses.get(
        verb, MagicMock(status_code=200, text="")
    )
    return session


def written(session, verb):
    calls = [c for c in session.request.call_args_list if c.args[0] == verb]
    return [(c.args[1], json.loads(c.kwargs["data"])) for c in calls]


def make_device(config):
    device = Device.__new__(Device)
    device.session = make_session(config)
    return device


def test_enable_gbp():
    device = make_device({"GBP_enable": False, "hostname": "sw1"})
    assert device.set_gbp_enable(True) is True
    _, body = written(device.session, "PUT")[0]
    assert body == {"GBP_enable": True, "hostname": "sw1"}


def test_enable_gbp_is_idempotent():
    device = make_device({"GBP_enable": True})
    assert device.set_gbp_enable(True) is False
    assert written(device.session, "PUT") == []


def test_disable_gbp_sends_false():
    device = make_device({"GBP_enable": True})
    assert device.set_gbp_enable(False) is True
    _, body = written(device.session, "PUT")[0]
    assert body["GBP_enable"] is False


def test_disable_gbp_when_attribute_absent_is_noop():
    device = make_device({})
    assert device.set_gbp_enable(False) is False


def test_gbp_role_create_posts_name_and_id():
    session = make_session(
        {"gbp_role_name": "fabric_user1", "gbp_role_id": 1010}
    )
    role = GbpRole(session, "fabric_user1", gbp_role_id=1010)
    assert role.create() is True
    uri, body = written(session, "POST")[0]
    assert uri == "system/gbp_role_name_id_maps"
    assert body == {"gbp_role_name": "fabric_user1", "gbp_role_id": 1010}


def test_gbp_role_get_ignores_read_only_origin():
    session = make_session(
        {"gbp_role_name": "r1", "gbp_role_id": 400, "origin": "config"}
    )
    role = GbpRole(session, "r1")
    role.get()
    assert role.config_attrs == ["gbp_role_id"]
    assert role.update() is False
    assert written(session, "PUT") == []


def test_gbp_role_update_puts_new_id():
    session = make_session(
        {"gbp_role_name": "r1", "gbp_role_id": 400, "origin": "config"}
    )
    role = GbpRole(session, "r1")
    role.get()
    role.gbp_role_id = 401
    assert role.update() is True
    assert written(session, "PUT") == [
        ("system/gbp_role_name_id_maps/r1", {"gbp_role_id": 401})
    ]


def test_gbp_role_from_uri():
    name, role = GbpRole.from_uri(
        MagicMock(), "/rest/v10.16/system/gbp_role_name_id_maps/fabric_user1"
    )
    assert name == "fabric_user1"
    assert role.path == "system/gbp_role_name_id_maps/fabric_user1"
