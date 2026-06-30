# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for pyaoscx.evpn_vlan_aware_bundle.EvpnVlanAwareBundle.

The class manages EVPN VLAN-aware bundles under
system/evpn/evpn_vlan_aware_bundles, indexed by the bundle name. These tests
cover the index/path construction, the from_uri parser and the create payload
(only the bundle name is configurable at creation time).
"""

from unittest.mock import MagicMock

from pyaoscx.evpn_vlan_aware_bundle import EvpnVlanAwareBundle


def make_bundle(name="tenant-blue"):
    session = MagicMock()
    return EvpnVlanAwareBundle(session, name)


def test_index_and_path():
    bundle = make_bundle("tenant-blue")
    assert bundle.bundle_name == "tenant-blue"
    assert bundle.base_uri == "system/evpn/evpn_vlan_aware_bundles"
    assert bundle.path == (
        "system/evpn/evpn_vlan_aware_bundles/tenant-blue"
    )
    assert EvpnVlanAwareBundle.indices == ["bundle_name"]


def test_from_uri():
    session = MagicMock()
    uri = "/rest/latest/system/evpn/evpn_vlan_aware_bundles/tenant-red"
    name, bundle = EvpnVlanAwareBundle.from_uri(session, uri)
    assert name == "tenant-red"
    assert isinstance(bundle, EvpnVlanAwareBundle)
    assert bundle.bundle_name == "tenant-red"


def test_create_posts_only_bundle_name():
    bundle = make_bundle("tenant-blue")
    # Decorate around _post_data to capture the payload.
    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    bundle._post_data = fake_post
    assert bundle.create() is True
    assert captured == {"bundle_name": "tenant-blue"}
