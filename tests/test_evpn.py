# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the Evpn and EvpnVlan pyaoscx resource modules.

The pyaoscx Session is mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.evpn import Evpn
from pyaoscx.evpn_vlan import EvpnVlan


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
    api.configurable_selectors = ["configuration", "writable"]
    api.valid_depth = lambda depth: True
    session.resource_prefix = "/rest/v10.09/"

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
# Evpn (singleton)
# --------------------------------------------------------------------------
def test_evpn_path():
    session = make_session()
    evpn = Evpn(session)
    assert evpn.path == "system/evpn"
    assert evpn.base_uri == "system/evpn"


def test_evpn_get_populates_config_attrs():
    body = {
        "arp_suppression_enable": True,
        "mac_move_count": 5,
        "mac_move_timer": 180,
        "nd_suppression_enable": False,
        "redistribute": {"local-mac": False},
    }
    session = make_session(get_body=body)
    evpn = Evpn(session)
    evpn.get(selector="writable")
    assert evpn.materialized is True
    assert set(evpn.config_attrs) == set(body.keys())
    assert evpn.mac_move_timer == 180


def test_evpn_update_idempotent():
    body = {"mac_move_timer": 180}
    session = make_session(get_body=body)
    evpn = Evpn(session)
    evpn.get(selector="writable")
    assert evpn.update() is False
    evpn.mac_move_timer = 181
    assert evpn.update() is True


def test_evpn_from_uri():
    session = make_session()
    evpn = Evpn.from_uri(session, "system/evpn")
    assert isinstance(evpn, Evpn)


# --------------------------------------------------------------------------
# EvpnVlan (child, indexed by vlan)
# --------------------------------------------------------------------------
def test_evpn_vlan_path():
    session = make_session()
    ev = EvpnVlan(session, 204)
    assert ev.path == "system/evpn/evpn_vlans/204"
    assert ev.vlan == "204"


def test_evpn_vlan_from_uri():
    session = make_session()
    vlan_id, ev = EvpnVlan.from_uri(
        session, "/rest/v10.09/system/evpn/evpn_vlans/204"
    )
    assert vlan_id == "204"
    assert ev.vlan == "204"


def test_evpn_vlan_create_sends_vlan_uri():
    get_body = {
        "rd": "65000:3999",
        "export_route_targets": ["65000:3999"],
        "import_route_targets": ["65000:3999"],
        "vlan": "3999",
    }
    session = make_session(get_body=get_body)
    ev = EvpnVlan(session, 3999, rd="65000:3999")
    ev.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["data"]["vlan"] == "/rest/v10.09/system/vlans/3999"
    assert post["data"]["rd"] == "65000:3999"


def test_evpn_vlan_update_excludes_index():
    body = {
        "rd": "65000:3999",
        "export_route_targets": ["65000:3999"],
        "import_route_targets": ["65000:3999"],
    }
    session = make_session(get_body=body)
    ev = EvpnVlan(session, 3999)
    ev.get(selector="writable")
    assert "vlan" not in ev.config_attrs
    assert ev.update() is False
    ev.rd = "65000:3998"
    assert ev.update() is True


def test_evpn_vlan_get_all():
    body = {
        "204": "/rest/v10.09/system/evpn/evpn_vlans/204",
        "205": "/rest/v10.09/system/evpn/evpn_vlans/205",
    }
    session = make_session(get_body=body)
    collection = EvpnVlan.get_all(session)
    assert set(collection.keys()) == {"204", "205"}
    assert all(isinstance(v, EvpnVlan) for v in collection.values())
