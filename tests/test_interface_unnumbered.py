# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the IP unnumbered support of
pyaoscx.interface.Interface.
"""

import json

from types import SimpleNamespace

import pytest

from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.interface import Interface

PREFIX = "/rest/v10.09/"
LO0_URI = PREFIX + "system/interfaces/loopback0"


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self.text = json.dumps(data if data is not None else {})


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
    resource_prefix = PREFIX
    connected = True

    def __init__(self, objects):
        self.api = FakeApi()
        # Maps an URI suffix to the data returned by GET
        self.objects = objects
        self.requests = []

    def request(self, method, uri, params=None, data=None):
        self.requests.append((method, uri, data))
        if method == "GET":
            for suffix, obj in self.objects.items():
                if uri.endswith(suffix):
                    return FakeResponse(200, obj)
            if "/ip6_addresses" in uri:
                return FakeResponse(200, {})
            return FakeResponse(404, {"error": "not found"})
        return FakeResponse(200 if method != "PATCH" else 204)


def routed_port(**extra):
    data = {
        "name": "1/1/25",
        "type": "system",
        "routing": True,
        "vrf": None,
        "ip4_address": None,
        "unnumbered": {},
    }
    data.update(extra)
    return data


def make_iface(port_data, name="1/1/25", **objects):
    objects.setdefault(
        "interfaces/loopback0",
        {"name": "loopback0", "type": "loopback", "vrf": None},
    )
    objects["interfaces/1%2F1%2F25"] = port_data
    session = FakeSession(objects)
    iface = Interface(session, name)
    iface.get()
    return session, iface


def sent(session, method):
    return [json.loads(d) for m, _, d in session.requests if m == method]


def test_set_lender_sends_patch_and_put():
    session, iface = make_iface(routed_port())
    iface.set_ip_unnumbered("loopback0")
    assert iface.apply() is True
    expected = {"ipv4_address_owner_interface": LO0_URI}
    assert sent(session, "PATCH")[-1] == {"unnumbered": expected}
    assert sent(session, "PUT")[-1]["unnumbered"] == expected
    assert iface.ip_unnumbered == "loopback0"


def test_same_lender_sends_no_patch():
    data = routed_port(unnumbered={"ipv4_address_owner_interface": LO0_URI})
    session, iface = make_iface(data)
    assert iface.ip_unnumbered == "loopback0"
    iface.set_ip_unnumbered("loopback0")
    iface.apply()
    assert not sent(session, "PATCH")
    assert sent(session, "PUT")[-1]["unnumbered"] == data["unnumbered"]


def test_remove_lender_with_put_only():
    data = routed_port(unnumbered={"ipv4_address_owner_interface": LO0_URI})
    session, iface = make_iface(data)
    iface.set_ip_unnumbered(None)
    assert iface.apply() is True
    assert not sent(session, "PATCH")
    assert sent(session, "PUT")[-1]["unnumbered"] == {}
    assert iface.ip_unnumbered is None


@pytest.mark.parametrize("lender", ["vlan190", "1/1/27"])
def test_non_loopback_lender_rejected(lender):
    _, iface = make_iface(routed_port())
    with pytest.raises(ParameterError):
        iface.set_ip_unnumbered(lender)


def test_missing_lender_rejected():
    _, iface = make_iface(routed_port())
    with pytest.raises(ParameterError, match="does not exist"):
        iface.set_ip_unnumbered("loopback99")


def test_lender_in_other_vrf_rejected():
    session, iface = make_iface(routed_port())
    lender = Interface(session, "loopback0")
    lender.materialized = True
    lender.vrf = SimpleNamespace(name="red")
    with pytest.raises(ParameterError, match="same VRF"):
        iface.set_ip_unnumbered(lender)


def test_non_routed_port_rejected():
    _, iface = make_iface(routed_port(routing=False))
    with pytest.raises(ParameterError, match="routed"):
        iface.set_ip_unnumbered("loopback0")
