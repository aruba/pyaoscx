# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the AaaServerGroup, RadiusServer and TacacsServer
pyaoscx resource modules. The pyaoscx Session is mocked, so no switch is
required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.aaa_server_group import AaaServerGroup
from pyaoscx.radius_server import RadiusServer
from pyaoscx.tacacs_server import TacacsServer


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


def fake_vrf(name):
    obj = MagicMock()
    obj.name = name
    obj.get_uri.return_value = "/rest/v10.16/system/vrfs/{0}".format(name)
    return obj


def make_session(get_body=None):
    session = MagicMock()
    api = session.api
    api.default_depth = 1
    api.default_selector = "writable"
    api.valid_depths = [0, 1, 2, 3, 4]
    api.valid_selectors = [
        "configuration",
        "writable",
        "status",
        "statistics",
    ]
    api.configurable_selectors = ["writable"]
    api.valid_depth = lambda depth: True
    api.compound_index_separator = ","
    api.get_uri_from_data.side_effect = lambda data: list(data.values())
    session.resource_prefix = "/rest/v10.16/"
    session.proxy = None

    calls = []

    def request(method, path, params=None, data=None):
        body = json.loads(data) if data else None
        calls.append({"method": method, "path": path, "data": body})
        if method == "GET":
            return make_response(get_body if get_body is not None else {})
        if method == "POST":
            return make_response({}, 201)
        if method in ("PUT", "DELETE"):
            return make_response({}, 204)
        return make_response({}, 200)

    session.request.side_effect = request
    session.calls = calls
    return session


# --------------------------------------------------------------------------
# AaaServerGroup
# --------------------------------------------------------------------------
def test_group_path():
    session = make_session()
    group = AaaServerGroup(session, "grp1")
    assert group.path == "system/aaa_server_groups/grp1"
    assert group.group_name == "grp1"


def test_group_create_sends_name_and_attrs():
    session = make_session()
    group = AaaServerGroup(session, "grp1", group_type="radius")
    group.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/aaa_server_groups"
    assert post["data"]["group_name"] == "grp1"
    assert post["data"]["group_type"] == "radius"


def test_group_update_idempotent():
    session = make_session(get_body={"group_type": "tacacs"})
    group = AaaServerGroup(session, "grp1")
    group.get(selector="writable")
    assert group.update() is False
    assert not [c for c in session.calls if c["method"] == "PUT"]


def test_group_update_changed_uses_put():
    session = make_session(get_body={"group_type": "tacacs"})
    group = AaaServerGroup(session, "grp1")
    group.get(selector="writable")
    group.group_type = "radius"
    assert group.update() is True
    puts = [c for c in session.calls if c["method"] == "PUT"]
    assert len(puts) == 1
    assert puts[0]["data"] == {"group_type": "radius"}


def test_group_delete():
    session = make_session()
    group = AaaServerGroup(session, "grp1")
    group.delete()
    assert [c for c in session.calls if c["method"] == "DELETE"]


def test_group_get_all():
    body = {"grp1": "/rest/v10.16/system/aaa_server_groups/grp1"}
    session = make_session(get_body=body)
    result = AaaServerGroup.get_all(session)
    assert "grp1" in result


# --------------------------------------------------------------------------
# RadiusServer
# --------------------------------------------------------------------------
def test_radius_path_compound_index():
    session = make_session()
    server = RadiusServer(
        session, fake_vrf("default"), "192.0.2.50", 1812, "udp"
    )
    assert server.base_uri == "system/vrfs/default/radius_servers"
    assert server.path == (
        "system/vrfs/default/radius_servers/192.0.2.50,1812,udp"
    )


def test_radius_create_sends_index_vrf_and_attrs():
    session = make_session()
    server = RadiusServer(
        session,
        fake_vrf("default"),
        "192.0.2.50",
        1812,
        "udp",
        timeout=10,
        server_group={"/rest/v10.16/system/aaa_server_groups/g": 1},
    )
    server.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/vrfs/default/radius_servers"
    assert post["data"]["address"] == "192.0.2.50"
    assert post["data"]["port"] == 1812
    assert post["data"]["port_type"] == "udp"
    assert post["data"]["vrf"] == "/rest/v10.16/system/vrfs/default"
    assert post["data"]["timeout"] == 10
    assert post["data"]["server_group"] == {
        "/rest/v10.16/system/aaa_server_groups/g": 1
    }


def test_radius_update_idempotent():
    session = make_session(get_body={"timeout": 5})
    server = RadiusServer(
        session, fake_vrf("default"), "192.0.2.50", 1812, "udp"
    )
    server.get(selector="writable")
    assert server.update() is False
    assert not [c for c in session.calls if c["method"] == "PUT"]


def test_radius_update_changed_uses_put():
    session = make_session(get_body={"timeout": 5})
    server = RadiusServer(
        session, fake_vrf("default"), "192.0.2.50", 1812, "udp"
    )
    server.get(selector="writable")
    server.timeout = 20
    assert server.update() is True
    puts = [c for c in session.calls if c["method"] == "PUT"]
    assert len(puts) == 1
    assert puts[0]["data"] == {"timeout": 20}


def test_radius_get_pops_indices():
    body = {"timeout": 5, "address": "192.0.2.50", "vrf": "x"}
    session = make_session(get_body=body)
    server = RadiusServer(
        session, fake_vrf("default"), "192.0.2.50", 1812, "udp"
    )
    server.get(selector="writable")
    assert "address" not in server.config_attrs
    assert "vrf" not in server.config_attrs
    assert "timeout" in server.config_attrs


def test_radius_get_all():
    body = {
        "192.0.2.50,1812,udp": (
            "/rest/v10.16/system/vrfs/default/radius_servers/"
            "192.0.2.50,1812,udp"
        )
    }
    session = make_session(get_body=body)
    result = RadiusServer.get_all(session, fake_vrf("default"))
    assert "192.0.2.50,1812,udp" in result


# --------------------------------------------------------------------------
# TacacsServer
# --------------------------------------------------------------------------
def test_tacacs_path_compound_index():
    session = make_session()
    server = TacacsServer(session, fake_vrf("default"), "192.0.2.60", 49)
    assert server.base_uri == "system/vrfs/default/tacacs_servers"
    assert server.path == ("system/vrfs/default/tacacs_servers/192.0.2.60,49")


def test_tacacs_create_sends_index_vrf_and_attrs():
    session = make_session()
    server = TacacsServer(
        session,
        fake_vrf("default"),
        "192.0.2.60",
        49,
        default_group_priority=1,
        group=["/rest/v10.16/system/aaa_server_groups/g"],
        timeout=10,
    )
    server.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/vrfs/default/tacacs_servers"
    assert post["data"]["address"] == "192.0.2.60"
    assert post["data"]["tcp_port"] == 49
    assert post["data"]["vrf"] == "/rest/v10.16/system/vrfs/default"
    assert post["data"]["group"] == ["/rest/v10.16/system/aaa_server_groups/g"]
    assert post["data"]["default_group_priority"] == 1


def test_tacacs_update_idempotent():
    session = make_session(get_body={"timeout": 5})
    server = TacacsServer(session, fake_vrf("default"), "192.0.2.60", 49)
    server.get(selector="writable")
    assert server.update() is False
    assert not [c for c in session.calls if c["method"] == "PUT"]


def test_tacacs_delete():
    session = make_session()
    server = TacacsServer(session, fake_vrf("default"), "192.0.2.60", 49)
    server.delete()
    assert [c for c in session.calls if c["method"] == "DELETE"]


def test_tacacs_get_all():
    body = {
        "192.0.2.60,49": (
            "/rest/v10.16/system/vrfs/default/tacacs_servers/192.0.2.60,49"
        )
    }
    session = make_session(get_body=body)
    result = TacacsServer.get_all(session, fake_vrf("default"))
    assert "192.0.2.60,49" in result
