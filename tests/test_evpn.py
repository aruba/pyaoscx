# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the dynamic VXLAN tunnel bridging mode of
pyaoscx.evpn.Evpn.
"""

import json

import pytest

from pyaoscx.evpn import Evpn
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self.text = json.dumps(data or {})


class FakeApi:
    default_selector = "configuration"
    valid_selectors = ["configuration", "status", "statistics", "writable"]
    configurable_selectors = ["configuration", "writable"]
    default_depth = 1

    def valid_depth(self, depth):
        return True


class FakeSession:
    def __init__(self, get_data):
        self.api = FakeApi()
        self.connected = True
        self.get_data = get_data
        self.requests = []
        self.write_response = FakeResponse(200)

    def request(self, method, uri, params=None, data=None):
        self.requests.append((method, uri, data))
        if method == "GET":
            return FakeResponse(200, self.get_data)
        return self.write_response


EVPN_GET = {
    "arp_suppression_enable": True,
    "mac_move_count": 5,
    "mac_move_timer": 180,
    "redistribute": {"local-mac": False, "local-svi": False},
}


def make_evpn(get_data):
    session = FakeSession(get_data)
    evpn = Evpn(session)
    evpn.get(selector="writable")
    return session, evpn


def writes(session):
    return [(m, json.loads(d)) for m, _, d in session.requests if m != "GET"]


def test_changed_mode_patched_before_put():
    data = dict(EVPN_GET, dyn_vxlan_tunnel_bridging_mode="no-bridging")
    session, evpn = make_evpn(data)
    evpn.set_dyn_vxlan_tunnel_bridging_mode("ibgp-ebgp")
    assert evpn.update() is True
    (patch_m, patch_body), (put_m, put_body) = writes(session)
    assert (patch_m, put_m) == ("PATCH", "PUT")
    assert patch_body == {"dyn_vxlan_tunnel_bridging_mode": "ibgp-ebgp"}
    assert put_body == dict(data, dyn_vxlan_tunnel_bridging_mode="ibgp-ebgp")


def test_unchanged_mode_not_sent():
    data = dict(EVPN_GET, dyn_vxlan_tunnel_bridging_mode="ibgp-ebgp")
    session, evpn = make_evpn(data)
    evpn.set_dyn_vxlan_tunnel_bridging_mode("ibgp-ebgp")
    assert evpn.update() is False
    evpn.mac_move_timer = 181
    assert evpn.update() is True
    assert [m for m, _ in writes(session)] == ["PUT"]


def test_invalid_mode_rejected():
    _, evpn = make_evpn(dict(EVPN_GET))
    with pytest.raises(ParameterError):
        evpn.set_dyn_vxlan_tunnel_bridging_mode("deny")


@pytest.mark.parametrize(
    "text",
    [
        # Answer of a 6300 (FL.10.19) that does not support the attribute
        "cannot modify the attribute: dyn_vxlan_tunnel_bridging_mode, "
        "reason: Non-configurable column",
        "invalid attribute: dyn_vxlan_tunnel_bridging_mode",
    ],
)
def test_unsupported_mode_rejected_by_switch(text):
    session, evpn = make_evpn(dict(EVPN_GET))
    session.write_response = FakeResponse(400)
    session.write_response.text = text
    evpn.set_dyn_vxlan_tunnel_bridging_mode("ibgp-ebgp")
    with pytest.raises(GenericOperationError) as exc:
        evpn.update()
    assert exc.value.response_code == 400
    assert "probably not supported" in exc.value.message
    # Nothing is applied when the mode is rejected
    assert [m for m, _ in writes(session)] == ["PATCH"]
