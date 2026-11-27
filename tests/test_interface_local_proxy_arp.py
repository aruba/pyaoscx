# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the local proxy ARP exclusions of
pyaoscx.interface.Interface.
"""

import json

from types import SimpleNamespace

import pytest

from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.unsupported_capability_error import (
    UnsupportedCapabilityError,
)
from pyaoscx.interface import Interface

PREFIX = "/rest/v10.09/"
ATTR = "local_proxy_arp_ip_exemption"


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


def make_svi(**extra):
    data = {"vrf": None, ATTR: []}
    data.update(extra)
    requests = []

    def request(method, uri, params=None, data=None):
        requests.append((method, uri, data))
        if method == "GET":
            if "/ip6_addresses" in uri:
                return SimpleNamespace(status_code=200, text="{}")
            return SimpleNamespace(status_code=200, text=json.dumps(body))
        return SimpleNamespace(status_code=200, text="{}")

    body = data
    session = SimpleNamespace(
        api=FakeApi(),
        connected=True,
        resource_prefix=PREFIX,
        request=request,
    )
    iface = Interface(session, "vlan190")
    iface.get()
    return requests, iface


def test_set_replaces_the_list_and_is_sent_in_the_put():
    requests, iface = make_svi()
    assert iface.set_local_proxy_arp_ip_exemption(["10.1.1.2", "10.1.1.1"])
    assert iface.local_proxy_arp_ip_exemption == ["10.1.1.1", "10.1.1.2"]
    assert iface.apply() is True
    method, uri, data = requests[-1]
    assert (method, uri.rsplit("/", 1)[-1]) == ("PUT", "vlan190")
    assert json.loads(data)[ATTR] == ["10.1.1.1", "10.1.1.2"]


def test_same_set_in_another_order_is_not_a_change():
    requests, iface = make_svi(**{ATTR: ["10.1.1.1", "10.1.1.2"]})
    assert not iface.set_local_proxy_arp_ip_exemption(
        ["10.1.1.2", "10.1.1.1", "10.1.1.2"]
    )
    assert iface.apply() is False
    assert all(request[0] == "GET" for request in requests)


def test_empty_list_clears_the_exclusions():
    requests, iface = make_svi(**{ATTR: ["10.1.1.1"]})
    assert iface.set_local_proxy_arp_ip_exemption([])
    assert iface.apply() is True
    assert json.loads(requests[-1][2])[ATTR] == []


@pytest.mark.parametrize("address", ["fd00::1", "10.1.1.300", "not-an-ip"])
def test_wrong_addresses_are_refused(address):
    _, iface = make_svi()
    with pytest.raises(ParameterError):
        iface.set_local_proxy_arp_ip_exemption([address])


def test_more_than_256_addresses_are_refused():
    _, iface = make_svi()
    addresses = ["10.2.{0}.{1}".format(i // 256, i % 256) for i in range(257)]
    with pytest.raises(ParameterError):
        iface.set_local_proxy_arp_ip_exemption(addresses)


def test_firmware_without_the_attribute_is_refused():
    _, iface = make_svi()
    iface.config_attrs.remove(ATTR)
    with pytest.raises(UnsupportedCapabilityError):
        iface.set_local_proxy_arp_ip_exemption(["10.1.1.1"])
