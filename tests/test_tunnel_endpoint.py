# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for pyaoscx.tunnel_endpoint.TunnelEndpoint.

A Tunnel Endpoint (TEP) is indexed by (vrf, origin, destination) and can flood
several VNIs at once through its ``network_id`` map. These tests cover the
serialization of ``network_id`` (single VNI, list of VNIs, or an existing
{vni_key: uri} map) and the fact that ``get`` keeps the full map instead of
collapsing it to a single VNI.
"""

from pyaoscx.tunnel_endpoint import TunnelEndpoint


class FakeVni:
    def __init__(self, key, uri):
        self.key = key
        self.uri = uri


class FakeVrf:
    def __init__(self, name="default"):
        self.name = name

    def get_info_format(self):
        return {"vrfs": "/rest/latest/system/vrfs/" + self.name}


class FakeInterface:
    percents_name = "vxlan1"

    def get_info_format(self):
        return {"interfaces": "/rest/latest/system/interfaces/vxlan1"}


class FakeApi:
    def get_index(self, vni):
        return {vni.key: vni.uri}

    def get_module(self, session, module, name):
        return FakeVrf(name)


class FakeSession:
    def __init__(self):
        self.api = FakeApi()


def make_tep(network_id):
    return TunnelEndpoint(
        FakeSession(),
        FakeInterface(),
        network_id,
        "9.9.9.9",
        origin="static",
        vrf=FakeVrf("default"),
    )


def test_payload_single_vni():
    tep = make_tep(FakeVni("vxlan_vni,206", "u206"))
    assert tep._network_id_payload() == {"vxlan_vni,206": "u206"}


def test_payload_list_of_vnis():
    tep = make_tep(
        [FakeVni("vxlan_vni,206", "u206"), FakeVni("vxlan_vni,207", "u207")]
    )
    assert tep._network_id_payload() == {
        "vxlan_vni,206": "u206",
        "vxlan_vni,207": "u207",
    }


def test_payload_existing_map_returned_as_copy():
    original = {"vxlan_vni,206": "u206"}
    tep = make_tep(original)
    payload = tep._network_id_payload()
    assert payload == original
    assert payload is not original


def test_get_preserves_network_id_map():
    tep = make_tep(FakeVni("vxlan_vni,206", "u206"))
    expected = {"vxlan_vni,206": "u206", "vxlan_vni,207": "u207"}

    def fake_copy(depth, selector, indices):
        tep.network_id = dict(expected)

    tep._get_and_copy_data = fake_copy
    tep.get()
    assert tep.network_id == expected


def test_get_defaults_to_empty_map_when_absent():
    tep = make_tep(FakeVni("vxlan_vni,206", "u206"))

    def fake_copy(depth, selector, indices):
        tep.network_id = None

    tep._get_and_copy_data = fake_copy
    tep.get()
    assert tep.network_id == {}
