# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the ARP and ND suppression settings of
pyaoscx.evpn_vlan.EvpnVlan and pyaoscx.evpn.Evpn.
"""

import json

import pytest

from pyaoscx.evpn import Evpn
from pyaoscx.evpn_vlan import EvpnVlan
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.unsupported_capability_error import (
    UnsupportedCapabilityError,
)


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
    resource_prefix = "/rest/v10.16/"

    def __init__(self, get_data):
        self.api = FakeApi()
        self.connected = True
        self.get_data = get_data
        self.requests = []

    def request(self, method, uri, params=None, data=None):
        self.requests.append((method, uri, data))
        if method == "GET":
            return FakeResponse(200, self.get_data)
        return FakeResponse(201 if method == "POST" else 200)


VLAN_GET = {
    "arp_suppression_config": None,
    "arp_suppression_extended_config": None,
    "arp_suppression_extended_ip_exemption": [],
    "arp_suppression_ip_exemption": ["10.1.1.2", "10.1.1.1"],
    "nd_suppression_config": None,
    "nd_suppression_extended_config": None,
    "nd_suppression_extended_ip_exemption": [],
    "nd_suppression_ip_exemption": [],
    "rd": "auto",
}


def make_vlan(get_data=None):
    session = FakeSession(VLAN_GET if get_data is None else get_data)
    evpn_vlan = EvpnVlan(session, 190)
    evpn_vlan.get(selector="writable")
    return session, evpn_vlan


def writes(session):
    return [(m, json.loads(d)) for m, _, d in session.requests if m != "GET"]


def test_set_suppression_puts_the_override():
    session, evpn_vlan = make_vlan()
    assert evpn_vlan.set_suppression("arp", "enable") is True
    assert evpn_vlan.update() is True
    ((method, body),) = writes(session)
    assert method == "PUT"
    assert body == dict(VLAN_GET, arp_suppression_config="enable")


def test_set_suppression_idempotent_and_reset():
    data = dict(VLAN_GET, nd_suppression_extended_config="disable")
    session, evpn_vlan = make_vlan(data)
    assert evpn_vlan.set_suppression("nd_extended", "disable") is False
    assert evpn_vlan.update() is False
    assert writes(session) == []
    assert evpn_vlan.set_suppression("nd_extended", None) is True
    assert evpn_vlan.update() is True
    assert writes(session)[0][1]["nd_suppression_extended_config"] is None


def test_set_suppression_rejects_invalid_values():
    _, evpn_vlan = make_vlan()
    with pytest.raises(ParameterError):
        evpn_vlan.set_suppression("arp", "on")
    with pytest.raises(ParameterError):
        evpn_vlan.set_suppression("dhcp", "enable")


def test_plain_and_extended_cannot_be_enabled_together():
    session, evpn_vlan = make_vlan()
    evpn_vlan.set_suppression("arp", "enable")
    evpn_vlan.set_suppression("arp_extended", "enable")
    with pytest.raises(ParameterError):
        evpn_vlan.update()
    assert writes(session) == []


def test_migration_to_extended_in_one_update():
    data = dict(VLAN_GET, arp_suppression_config="enable")
    session, evpn_vlan = make_vlan(data)
    evpn_vlan.set_suppression("arp", "disable")
    evpn_vlan.set_suppression("arp_extended", "enable")
    assert evpn_vlan.update() is True
    body = writes(session)[0][1]
    assert body["arp_suppression_config"] == "disable"
    assert body["arp_suppression_extended_config"] == "enable"


def test_ip_exemption_ignores_order_and_duplicates():
    session, evpn_vlan = make_vlan()
    assert (
        evpn_vlan.set_suppression_ip_exemption(
            "arp", ["10.1.1.1", "10.1.1.2", "10.1.1.1"]
        )
        is False
    )
    assert evpn_vlan.update() is False
    assert writes(session) == []


def test_ip_exemption_replaces_the_list():
    session, evpn_vlan = make_vlan()
    assert evpn_vlan.set_suppression_ip_exemption("arp", ["10.1.1.9"]) is True
    assert evpn_vlan.update() is True
    assert writes(session)[0][1]["arp_suppression_ip_exemption"] == [
        "10.1.1.9"
    ]
    assert evpn_vlan.set_suppression_ip_exemption("arp", []) is True
    assert evpn_vlan.arp_suppression_ip_exemption == []


def test_nd_exemption_is_normalized_and_compared_by_value():
    data = dict(VLAN_GET, nd_suppression_ip_exemption=["FD00::2"])
    _, evpn_vlan = make_vlan(data)
    assert evpn_vlan.set_suppression_ip_exemption("nd", ["fd00::2"]) is False
    assert evpn_vlan.set_suppression_ip_exemption("nd", ["FD00::0:1"]) is True
    assert evpn_vlan.nd_suppression_ip_exemption == ["fd00::1"]


@pytest.mark.parametrize(
    "feature, address",
    [
        ("arp", "fd00::1"),
        ("arp_extended", "fd00::1"),
        ("nd", "10.1.1.1"),
        ("nd_extended", "10.1.1.1"),
        ("arp", "10.1.1.256"),
    ],
)
def test_ip_exemption_rejects_wrong_addresses(feature, address):
    _, evpn_vlan = make_vlan()
    with pytest.raises(ParameterError):
        evpn_vlan.set_suppression_ip_exemption(feature, [address])


def test_ip_exemption_limit():
    _, evpn_vlan = make_vlan()
    addresses = ["10.0.{0}.{1}".format(i // 250, i % 250) for i in range(257)]
    with pytest.raises(ParameterError):
        evpn_vlan.set_suppression_ip_exemption("arp", addresses)
    evpn_vlan.set_suppression_ip_exemption("arp", addresses[:256])


def test_firmware_without_the_attributes_is_refused():
    _, evpn_vlan = make_vlan({"rd": "auto"})
    with pytest.raises(UnsupportedCapabilityError):
        evpn_vlan.set_suppression("arp", "enable")
    with pytest.raises(UnsupportedCapabilityError):
        evpn_vlan.set_suppression_ip_exemption("arp", ["10.1.1.1"])


def test_create_posts_the_suppression_settings():
    session = FakeSession(VLAN_GET)
    evpn_vlan = EvpnVlan(session, 190, rd="auto")
    evpn_vlan.set_suppression("nd", "enable")
    evpn_vlan.set_suppression_ip_exemption("nd", ["fd00::1"])
    assert evpn_vlan.create() is True
    method, body = writes(session)[0]
    assert method == "POST"
    assert body["nd_suppression_config"] == "enable"
    assert body["nd_suppression_ip_exemption"] == ["fd00::1"]
    assert body["vlan"] == "/rest/v10.16/system/vlans/190"


EVPN_GET = {
    "arp_suppression_enable": True,
    "arp_suppression_extended_enable": False,
    "nd_suppression_enable": False,
    "nd_suppression_extended_enable": False,
}


def make_evpn():
    session = FakeSession(EVPN_GET)
    evpn = Evpn(session)
    evpn.get(selector="writable")
    return session, evpn


def test_global_extended_requires_the_plain_version_disabled():
    session, evpn = make_evpn()
    evpn.arp_suppression_extended_enable = True
    with pytest.raises(ParameterError):
        evpn.update()
    assert writes(session) == []


def test_global_migration_to_extended():
    session, evpn = make_evpn()
    evpn.arp_suppression_enable = False
    evpn.arp_suppression_extended_enable = True
    assert evpn.update() is True
    assert writes(session)[0][1] == dict(
        EVPN_GET,
        arp_suppression_enable=False,
        arp_suppression_extended_enable=True,
    )


def test_global_unrelated_update_is_not_blocked():
    data = dict(
        EVPN_GET, arp_suppression_extended_enable=True, mac_move_count=5
    )
    session = FakeSession(data)
    evpn = Evpn(session)
    evpn.get(selector="writable")
    evpn.mac_move_count = 6
    assert evpn.update() is True


def test_check_suppression_can_be_called_before_update():
    session, evpn_vlan = make_vlan()
    evpn_vlan.check_suppression()
    evpn_vlan.set_suppression("nd", "enable")
    evpn_vlan.set_suppression("nd_extended", "enable")
    with pytest.raises(ParameterError):
        evpn_vlan.check_suppression()
    assert writes(session) == []
