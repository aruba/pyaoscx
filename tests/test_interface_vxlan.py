# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the inter-VXLAN bridging mode of
pyaoscx.interface.Interface.
"""

import json

import pytest

from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.interface import Interface


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

    def get_module_class(self, session, name):
        return object

    def get_uri_from_data(self, data):
        return []


class FakeSession:
    def __init__(self, get_data):
        self.api = FakeApi()
        self.get_data = get_data
        self.requests = []

    def request(self, method, uri, params=None, data=None):
        self.requests.append((method, uri, data))
        if method == "GET":
            return FakeResponse(200, self.get_data)
        return FakeResponse(200)


def make_vxlan(get_data):
    session = FakeSession(get_data)
    session.connected = True
    iface = Interface(session, "vxlan1")
    iface.get()
    return session, iface


VXLAN_GET = {
    "name": "vxlan1",
    "type": "vxlan",
    "admin": "up",
    "options": {"local_ip": "10.0.0.1", "vxlan_dest_udp_port": "4789"},
}


def put_bodies(session):
    return [json.loads(d) for m, _, d in session.requests if m == "PUT"]


def test_mode_added_to_put_when_not_configured():
    session, iface = make_vxlan(dict(VXLAN_GET))
    iface.set_inter_vxlan_bridging_mode("static-all")
    assert iface.apply() is True
    assert put_bodies(session)[-1]["inter_vxlan_bridging_mode"] == "static-all"


def test_change_already_configured_mode():
    data = dict(VXLAN_GET, inter_vxlan_bridging_mode="deny")
    session, iface = make_vxlan(data)
    iface.set_inter_vxlan_bridging_mode("static-evpn")
    assert iface.config_attrs.count("inter_vxlan_bridging_mode") == 1
    assert iface.apply() is True
    put = put_bodies(session)[-1]
    assert put["inter_vxlan_bridging_mode"] == "static-evpn"


def test_invalid_mode_rejected():
    _, iface = make_vxlan(dict(VXLAN_GET))
    with pytest.raises(ParameterError):
        iface.set_inter_vxlan_bridging_mode("allow")


def test_non_vxlan_interface_rejected():
    session = FakeSession({"name": "1/1/1", "type": "system"})
    session.connected = True
    iface = Interface(session, "1/1/1")
    iface.get()
    with pytest.raises(ParameterError):
        iface.set_inter_vxlan_bridging_mode("deny")
