# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for pyaoscx.ipv6.Ipv6.get_all.
"""

import json

from types import SimpleNamespace

from pyaoscx.ipv6 import Ipv6

PREFIX = "/rest/v10.16/"
INT_URI = PREFIX + "system/interfaces/1%2F1%2F1"


class FakeResponse:
    def __init__(self, data):
        self.status_code = 200
        self.text = json.dumps(data)


class FakeSession:
    resource_prefix = PREFIX
    connected = True

    def __init__(self, collection):
        self.collection = collection
        self.requests = []
        self.api = SimpleNamespace(
            default_selector="configuration",
            valid_selectors=["configuration", "writable"],
            configurable_selectors=["configuration", "writable"],
            default_depth=1,
            valid_depth=lambda depth: True,
        )

    def request(self, method, uri, params=None, data=None):
        self.requests.append(uri)
        if uri.endswith("/ip6_addresses"):
            return FakeResponse(self.collection)
        return FakeResponse({"address": "2001:db8::1/64", "type": "global"})


def parent():
    return SimpleNamespace(
        base_uri=PREFIX + "system/interfaces",
        percents_name="1%2F1%2F1",
        name="1/1/1",
    )


def test_get_all_ignores_interface_returned_for_empty_collection():
    # 6200 ML.10.16 returns the interface itself instead of {}
    session = FakeSession(
        {
            "name": "1/1/1",
            "admin": None,
            "ip6_addresses": {},
            "dhcpv6_ip6_addresses": INT_URI
            + "/ip6_addresses/dhcpv6_ip6_addresses",
            "stp_config": {"admin_edge_port_enable": False},
        }
    )

    assert Ipv6.get_all(session, parent()) == {}
    assert len(session.requests) == 1


def test_get_all_reads_ipv6_addresses():
    key = "2001%3Adb8%3A%3A1%2F64"
    session = FakeSession({key: INT_URI + "/ip6_addresses/" + key})

    result = Ipv6.get_all(session, parent())

    assert list(result) == [key]
