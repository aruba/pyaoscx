# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the SNMP family pyaoscx resource modules (Snmpv3User,
SnmpCommunity, SnmpView, SnmpViewEntry, SnmpTrap). The pyaoscx Session is
mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.snmpv3_user import Snmpv3User
from pyaoscx.snmp_community import SnmpCommunity
from pyaoscx.snmp_view import SnmpView
from pyaoscx.snmp_view_entry import SnmpViewEntry
from pyaoscx.snmp_trap import SnmpTrap


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
    api.valid_selectors = ["configuration", "writable", "status"]
    api.configurable_selectors = ["writable"]
    api.compound_index_separator = ","
    api.valid_depth = lambda depth: True
    api.get_uri_from_data.side_effect = lambda data: list(data.values())
    session.resource_prefix = "/rest/v10.16/"
    session.proxy = None
    calls = []

    def request(method, path, params=None, data=None):
        calls.append(
            {
                "method": method,
                "path": path,
                "data": json.loads(data) if data else None,
            }
        )
        if method == "GET":
            return make_response(get_body if get_body is not None else {})
        if method == "POST":
            return make_response({}, 201)
        return make_response({}, 204)

    session.request.side_effect = request
    session.calls = calls
    return session


def make_vrf(name="default"):
    vrf = MagicMock()
    vrf.name = name
    vrf.get_uri.return_value = "/rest/v10.16/system/vrfs/" + name
    return vrf


def test_user_create():
    s = make_session()
    Snmpv3User(s, "alice", access_level="ro").create()
    post = [c for c in s.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/snmpv3_users"
    assert post["data"]["user_name"] == "alice"


def test_user_path_delete():
    s = make_session()
    u = Snmpv3User(s, "alice")
    assert u.path == "system/snmpv3_users/alice"
    u.delete()
    assert [c for c in s.calls if c["method"] == "DELETE"]


def test_community_create():
    s = make_session()
    SnmpCommunity(s, "anstest").create()
    post = [c for c in s.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/snmp_community_attributes"
    assert post["data"]["name"] == "anstest"


def test_view_create():
    s = make_session()
    SnmpView(s, "v1").create()
    post = [c for c in s.calls if c["method"] == "POST"][0]
    assert post["data"]["name"] == "v1"


def test_view_entry_path():
    s = make_session()
    v = SnmpView(s, "v1")
    e = SnmpViewEntry(s, "u1", v, oid_tree="1.3.6.1", type="included")
    assert e.base_uri == "system/snmp_views/v1/snmp_view_entry"
    e.create()
    post = [c for c in s.calls if c["method"] == "POST"][0]
    assert post["data"]["oid_tree"] == "1.3.6.1"
    assert e.update() is False


def test_trap_compound_index():
    s = make_session()
    vrf = make_vrf()
    t = SnmpTrap(
        s, vrf, "198.51.100.5", 162, "trap", "v2c", community_name="public"
    )
    assert t.path == (
        "system/snmp_traps/default,198.51.100.5,162,trap,v2c"
    )
    t.create()
    post = [c for c in s.calls if c["method"] == "POST"][0]
    assert post["data"]["vrf"] == "/rest/v10.16/system/vrfs/default"
    assert post["data"]["receiver_address"] == "198.51.100.5"
    assert t.update() is False
