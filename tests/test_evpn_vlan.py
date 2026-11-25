# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for pyaoscx.evpn_vlan.EvpnVlan and the registration of the
Evpn and EvpnVlan classes in the pyaoscx API.
"""

from unittest.mock import MagicMock

from pyaoscx.rest.v10_09.api import v10_09
from pyaoscx.evpn import Evpn
from pyaoscx.evpn_vlan import EvpnVlan


def make_session():
    session = MagicMock()
    session.resource_prefix = "/rest/v10.15/"
    return session


def test_index_and_path():
    evpn_vlan = EvpnVlan(make_session(), 190)
    assert evpn_vlan.base_uri == "system/evpn/evpn_vlans"
    assert evpn_vlan.path == "system/evpn/evpn_vlans/190"
    assert EvpnVlan.indices == ["vlan"]


def test_from_uri():
    vlan, evpn_vlan = EvpnVlan.from_uri(
        make_session(), "/rest/v10.15/system/evpn/evpn_vlans/190"
    )
    assert vlan == 190
    assert isinstance(evpn_vlan, EvpnVlan)


def test_create_posts_vlan_reference_and_attributes():
    evpn_vlan = EvpnVlan(
        make_session(), 190, rd="auto", import_route_targets=["auto"]
    )
    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    evpn_vlan._post_data = fake_post
    assert evpn_vlan.create() is True
    assert captured == {
        "vlan": "/rest/v10.15/system/vlans/190",
        "rd": "auto",
        "import_route_targets": ["auto"],
    }


def test_classes_are_registered():
    api = v10_09()
    session = make_session()
    assert api.get_module_class(session, "Evpn") is Evpn
    assert api.get_module_class(session, "EvpnVlan") is EvpnVlan
