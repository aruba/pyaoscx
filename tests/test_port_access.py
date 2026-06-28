# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the CaptivePortalProfile, PortAccessRole and
PortAccessVlanGroup pyaoscx resource modules. The pyaoscx Session is mocked,
so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.captive_portal_profile import CaptivePortalProfile
from pyaoscx.port_access_role import PortAccessRole
from pyaoscx.port_access_vlan_group import PortAccessVlanGroup


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


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
# CaptivePortalProfile
# --------------------------------------------------------------------------
def test_cpp_path():
    session = make_session()
    cpp = CaptivePortalProfile(session, "cp1")
    assert cpp.path == "system/captive_portal_profiles/cp1"
    assert cpp.name == "cp1"


def test_cpp_create_sends_name_and_attrs():
    session = make_session()
    cpp = CaptivePortalProfile(
        session, "cp1", url="https://cp.example.com/login"
    )
    cpp.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/captive_portal_profiles"
    assert post["data"]["name"] == "cp1"
    assert post["data"]["url"] == "https://cp.example.com/login"


def test_cpp_update_idempotent():
    session = make_session(get_body={"url": "https://x", "url_hash_key": None})
    cpp = CaptivePortalProfile(session, "cp1")
    cpp.get(selector="writable")
    assert cpp.update() is False
    assert not [c for c in session.calls if c["method"] == "PUT"]


def test_cpp_update_changed_uses_put():
    session = make_session(get_body={"url": "https://x", "url_hash_key": None})
    cpp = CaptivePortalProfile(session, "cp1")
    cpp.get(selector="writable")
    cpp.url = "https://y"
    assert cpp.update() is True
    puts = [c for c in session.calls if c["method"] == "PUT"]
    assert len(puts) == 1
    assert puts[0]["data"]["url"] == "https://y"


def test_cpp_delete():
    session = make_session()
    cpp = CaptivePortalProfile(session, "cp1")
    cpp.delete()
    assert [c for c in session.calls if c["method"] == "DELETE"]


def test_cpp_get_all():
    body = {"cp1": "/rest/v10.16/system/captive_portal_profiles/cp1"}
    session = make_session(get_body=body)
    result = CaptivePortalProfile.get_all(session)
    assert "cp1" in result


def test_cpp_from_uri():
    session = make_session()
    uri = "/rest/v10.16/system/captive_portal_profiles/cp1"
    name, obj = CaptivePortalProfile.from_uri(session, uri)
    assert name == "cp1"
    assert isinstance(obj, CaptivePortalProfile)


# --------------------------------------------------------------------------
# PortAccessVlanGroup
# --------------------------------------------------------------------------
def test_vg_path():
    session = make_session()
    vg = PortAccessVlanGroup(session, "vg1")
    assert vg.path == "system/port_access_vlan_groups/vg1"


def test_vg_create_sends_name_and_vlans():
    session = make_session()
    vg = PortAccessVlanGroup(session, "vg1", vlans=[10, 20])
    vg.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/port_access_vlan_groups"
    assert post["data"]["name"] == "vg1"
    assert post["data"]["vlans"] == [10, 20]


def test_vg_update_idempotent():
    session = make_session(get_body={"vlans": [10, 20]})
    vg = PortAccessVlanGroup(session, "vg1")
    vg.get(selector="writable")
    assert vg.update() is False


def test_vg_update_changed_uses_put():
    session = make_session(get_body={"vlans": [10]})
    vg = PortAccessVlanGroup(session, "vg1")
    vg.get(selector="writable")
    vg.vlans = [10, 20]
    assert vg.update() is True
    puts = [c for c in session.calls if c["method"] == "PUT"]
    assert puts[0]["data"]["vlans"] == [10, 20]


def test_vg_delete():
    session = make_session()
    vg = PortAccessVlanGroup(session, "vg1")
    vg.delete()
    assert [c for c in session.calls if c["method"] == "DELETE"]


# --------------------------------------------------------------------------
# PortAccessRole
# --------------------------------------------------------------------------
def test_role_path():
    session = make_session()
    role = PortAccessRole(session, "role1")
    assert role.path == "system/port_access_roles/role1"


def test_role_create_sends_name_and_attrs():
    session = make_session()
    role = PortAccessRole(
        session, "role1", description="r", vlan_mode="access", vlan_tag=10
    )
    role.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/port_access_roles"
    assert post["data"]["name"] == "role1"
    assert post["data"]["vlan_mode"] == "access"
    assert post["data"]["vlan_tag"] == 10


def test_role_update_idempotent():
    session = make_session(
        get_body={"description": "r", "vlan_mode": "access", "vlan_tag": 10}
    )
    role = PortAccessRole(session, "role1")
    role.get(selector="writable")
    assert role.update() is False


def test_role_update_changed_uses_put():
    session = make_session(
        get_body={"description": "r", "vlan_mode": "access", "vlan_tag": 10}
    )
    role = PortAccessRole(session, "role1")
    role.get(selector="writable")
    role.description = "changed"
    assert role.update() is True
    puts = [c for c in session.calls if c["method"] == "PUT"]
    assert puts[0]["data"]["description"] == "changed"


def test_role_captive_portal_reference_roundtrip():
    uri = "/rest/v10.16/system/captive_portal_profiles/cp1"
    session = make_session(
        get_body={"captive_portal_profile": {"cp1": uri}, "vlan_mode": None}
    )
    role = PortAccessRole(session, "role1")
    role.get(selector="writable")
    # unchanged reference -> idempotent
    assert role.update() is False


def test_role_delete():
    session = make_session()
    role = PortAccessRole(session, "role1")
    role.delete()
    assert [c for c in session.calls if c["method"] == "DELETE"]


def test_role_get_all():
    body = {"role1": "/rest/v10.16/system/port_access_roles/role1"}
    session = make_session(get_body=body)
    result = PortAccessRole.get_all(session)
    assert "role1" in result
