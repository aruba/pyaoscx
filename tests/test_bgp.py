# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the BGP Router / BGP Neighbor address family handling.

These tests do not require a live switch. They mock the HTTP layer and the
get()/apply() calls to verify the request bodies built by the classes and the
PyaoscxFactory helpers.
"""

import json
from types import SimpleNamespace

import pytest

from pyaoscx.bgp_neighbor import BgpNeighbor
from pyaoscx.bgp_router import BgpRouter
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.verification_error import VerificationError
from pyaoscx.pyaoscx_factory import PyaoscxFactory

MODULES = {"BgpRouter": BgpRouter, "BgpNeighbor": BgpNeighbor}


def make_session(requests=None):
    def request(method, uri, data=None, **kwargs):
        if requests is not None:
            requests.append((method, uri, json.loads(data) if data else None))
        return SimpleNamespace(
            status_code={"POST": 201, "DELETE": 204}.get(method, 200),
            text="{}",
        )

    api = SimpleNamespace(
        default_selector="writable",
        default_depth=1,
        get_module=lambda session, name, *args, **kwargs: MODULES[name](
            session, *args, **kwargs
        ),
    )
    return SimpleNamespace(connected=True, api=api, request=request)


def make_router(session, asn=65000):
    vrf = SimpleNamespace(
        name="default",
        materialized=True,
        update_bgp_routers=lambda router: None,
    )
    router = BgpRouter(session, asn, parent_vrf=vrf)
    router.materialized = True
    return router


@pytest.fixture
def neighbor_calls(monkeypatch):
    """Mock BgpNeighbor.get()/apply(); `existing` simulates switch data."""
    state = {"existing": None, "applied": []}

    def fake_get(self, *args, **kwargs):
        if state["existing"] is None:
            raise GenericOperationError("Not found", 404)
        for key, val in state["existing"].items():
            setattr(self, key, val)
        self.materialized = True
        return True

    def fake_apply(self):
        state["applied"].append(self)
        return True

    monkeypatch.setattr(BgpNeighbor, "get", fake_get)
    monkeypatch.setattr(BgpNeighbor, "apply", fake_apply)
    return state


def test_create_bgp_neighbors_sends_per_af_dicts(neighbor_calls):
    router = make_router(make_session())

    nbr = router.create_bgp_neighbors(
        "10.0.0.1",
        family_type="l2vpn-evpn",
        activate=True,
        send_community=True,
    )

    assert neighbor_calls["applied"] == [nbr]
    assert nbr.activate == {
        "ipv4-unicast": False,
        "ipv6-unicast": False,
        "l2vpn-evpn": True,
    }
    assert nbr.send_community == {
        "ipv4-unicast": "none",
        "ipv6-unicast": "none",
        "l2vpn-evpn": "both",
    }


def test_create_bgp_neighbors_merges_existing_af(neighbor_calls):
    neighbor_calls["existing"] = {
        "activate": {"ipv4-unicast": True, "l2vpn-evpn": False},
        "send_community": {"ipv4-unicast": "standard", "l2vpn-evpn": "none"},
    }
    router = make_router(make_session())

    nbr = router.create_bgp_neighbors(
        "10.0.0.1",
        family_type="l2vpn-evpn",
        activate=True,
        send_community="extended",
    )

    assert nbr.activate == {"ipv4-unicast": True, "l2vpn-evpn": True}
    assert nbr.send_community == {
        "ipv4-unicast": "standard",
        "l2vpn-evpn": "extended",
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"family_type": "vpnv4", "activate": True},
        {"family_type": "l2vpn-evpn", "inbound_soft_reconfiguration": True},
        {"activate": True},
    ],
)
def test_create_bgp_neighbors_invalid_family(neighbor_calls, kwargs):
    router = make_router(make_session())
    with pytest.raises(VerificationError):
        router.create_bgp_neighbors("10.0.0.1", **kwargs)


def test_neighbor_update_without_local_interface():
    requests = []
    session = make_session(requests)
    nbr = BgpNeighbor(
        session, "10.0.0.1", parent_bgp_router=make_router(session)
    )
    nbr.remote_as = 65000
    nbr.config_attrs = ["remote_as"]

    assert nbr.update() is True
    assert requests[-1][0] == "PUT"
    assert requests[-1][2] == {"remote_as": 65000}


def test_neighbor_registered_once_and_deleted_with_one_request():
    requests = []
    session = make_session(requests)
    router = make_router(session)
    first = BgpNeighbor(session, "10.0.0.1", parent_bgp_router=router)
    other = BgpNeighbor(session, "10.0.0.2", parent_bgp_router=router)
    again = BgpNeighbor(session, "10.0.0.1", parent_bgp_router=router)

    assert list(router.bgp_neighbors) == [again, other]
    assert first not in router.bgp_neighbors

    again.delete()
    assert [r[:2] for r in requests] == [
        (
            "DELETE",
            "system/vrfs/default/bgp_routers/65000/bgp_neighbors/10.0.0.1",
        )
    ]
    assert list(router.bgp_neighbors) == [other]


def test_neighbor_update_strips_create_only_attrs():
    requests = []
    session = make_session(requests)
    nbr = BgpNeighbor(
        session, "spine-RR", parent_bgp_router=make_router(session)
    )
    nbr.is_peer_group = True
    nbr.remote_as = 65001
    nbr.config_attrs = ["is_peer_group", "remote_as"]
    nbr._BgpNeighbor__original_attributes = {
        "is_peer_group": True,
        "remote_as": 65000,
    }

    assert nbr.update() is True
    assert requests[-1][2] == {"remote_as": 65001}

    requests.clear()
    assert nbr.update() is False
    assert not requests


def test_neighbor_create_skips_empty_local_interface(monkeypatch):
    requests = []
    session = make_session(requests)
    monkeypatch.setattr(BgpNeighbor, "get", lambda self, *a, **k: True)
    nbr = BgpNeighbor(
        session,
        "spine-RR",
        parent_bgp_router=make_router(session),
        is_peer_group=True,
        local_interface="",
    )

    assert nbr.create() is True
    method, _, body = requests[-1]
    assert method == "POST"
    assert body == {
        "ip_or_ifname_or_group_name": "spine-RR",
        "is_peer_group": True,
    }


def test_factory_bgp_neighbor_with_family_type(neighbor_calls):
    neighbor_calls["existing"] = {
        "activate": {"ipv4-unicast": True, "l2vpn-evpn": True},
    }
    session = make_session()
    factory = PyaoscxFactory(session)
    factory.session = session
    router = make_router(session)

    nbr = factory.bgp_neighbor(
        router._BgpRouter__parent_vrf,
        router,
        "10.0.0.1",
        family_type="ipv6-unicast",
    )

    assert nbr.activate == {
        "ipv4-unicast": True,
        "l2vpn-evpn": True,
        "ipv6-unicast": True,
    }


def test_factory_bgp_router_vrf(monkeypatch):
    session = make_session()
    factory = PyaoscxFactory(session)
    factory.session = session
    existing = {"redistribute": {"ipv6-unicast": ["connected"]}}

    def fake_get(self, *args, **kwargs):
        self.__dict__.update(existing)
        return True

    monkeypatch.setattr(BgpRouter, "get", fake_get)
    monkeypatch.setattr(BgpRouter, "apply", lambda self: True)
    vrf = make_router(session)._BgpRouter__parent_vrf

    router = factory.bgp_router_vrf(
        vrf, 65000, "ipv4-unicast", route_types=["connected", "static"]
    )
    assert router.redistribute == {
        "ipv4-unicast": ["connected", "static"],
        "ipv6-unicast": ["connected"],
    }

    with pytest.raises(VerificationError):
        factory.bgp_router_vrf(vrf, 65000, "l2vpn-evpn")


def test_create_bgp_neighbors_ebgp_hop_count(neighbor_calls):
    router = make_router(make_session())

    nbr = router.create_bgp_neighbors(
        "10.0.0.1", remote_as=65000, ebgp_hop_count=255
    )
    assert nbr.ebgp_hop_count == 255
    assert "ebgp_hop_count" in nbr.config_attrs

    neighbor_calls["existing"] = {"ebgp_hop_count": 255}
    nbr = router.create_bgp_neighbors("10.0.0.1", ebgp_hop_count=1)
    assert nbr.ebgp_hop_count == 1


@pytest.mark.parametrize("value", [0, 256, True, "5"])
def test_create_bgp_neighbors_invalid_ebgp_hop_count(neighbor_calls, value):
    router = make_router(make_session())
    with pytest.raises(VerificationError):
        router.create_bgp_neighbors("10.0.0.1", ebgp_hop_count=value)
    assert not neighbor_calls["applied"]


def test_nest_compound_keys():
    from pyaoscx.utils.util import nest_compound_keys

    data = {
        "route_maps": {"ipv4-unicast,in": "A", "ipv4-unicast,out": "B"},
        "redistribute_route_map": {"ipv6-unicast": {"static": "C"}},
        "activate": {"ipv4-unicast": True},
        "other": None,
    }
    nest_compound_keys(
        data, ("route_maps", "redistribute_route_map", "other", "missing")
    )
    assert data == {
        "route_maps": {"ipv4-unicast": {"in": "A", "out": "B"}},
        "redistribute_route_map": {"ipv6-unicast": {"static": "C"}},
        "activate": {"ipv4-unicast": True},
        "other": None,
    }


def test_router_put_sends_nested_redistribute_route_map(monkeypatch):
    requests = []
    session = make_session(requests)
    session.api.configurable_selectors = ["writable"]
    rm = "/rest/v10.09/system/route_maps/RM"
    router = make_router(session)
    monkeypatch.setattr(
        router,
        "_get_data",
        lambda depth, selector: {
            "redistribute": {"ipv4-unicast": ["static"]},
            "redistribute_route_map": {"ipv4-unicast,connected": rm},
        },
    )
    monkeypatch.setattr(BgpNeighbor, "get_all", lambda *a: {})
    monkeypatch.setattr(
        "pyaoscx.bgp_router.AggregateAddress.get_all", lambda *a: {}
    )
    router.get()
    assert router.redistribute_route_map == {"ipv4-unicast": {"connected": rm}}

    assert router.update() is False
    router.redistribute = {"ipv4-unicast": []}
    assert router.update() is True
    assert requests[-1][2]["redistribute_route_map"] == {
        "ipv4-unicast": {"connected": rm}
    }


def test_unnumbered_neighbor_name_is_encoded_in_uris():
    requests = []
    session = make_session(requests)
    session.resource_prefix = "/rest/v10.09/"
    router = make_router(session)
    nbr = BgpNeighbor(session, "1/1/3", parent_bgp_router=router)
    nbr.remote_as = 65000
    nbr.config_attrs = ["remote_as"]

    nbr.update()
    nbr.delete()
    path = "system/vrfs/default/bgp_routers/65000/bgp_neighbors/1%2F1%2F3"
    assert [r[:2] for r in requests] == [("PUT", path), ("DELETE", path)]

    name, from_uri = BgpNeighbor.from_uri(
        session, router, "/rest/v10.09/" + path
    )
    assert name == from_uri.ip_or_ifname_or_group_name == "1/1/3"


@pytest.mark.parametrize(
    "index, family, prefix",
    [
        ("ipv4-unicast,10.2.0.0%2F16", "ipv4-unicast", "10.2.0.0/16"),
        (
            "ipv6-unicast,2001%3Adb8%3A%3A%2F32",
            "ipv6-unicast",
            "2001:db8::/32",
        ),
    ],
)
def test_aggregate_address_from_uri(index, family, prefix):
    from pyaoscx.aggregate_address import AggregateAddress

    router = make_router(make_session())
    uri = "/rest/v10.09/system/vrfs/default/bgp_routers/65000/"
    key, agg = AggregateAddress.from_uri(
        make_session(), router, uri + "aggregate_addresses/" + index
    )
    assert (agg.address_family, agg.ip_prefix) == (family, prefix)
    assert key == "{0},{1}".format(family, prefix)


def test_aggregate_address_registered_once_and_deleted_once():
    from pyaoscx.aggregate_address import AggregateAddress

    requests = []
    session = make_session(requests)
    session.api.compound_index_separator = ","
    router = make_router(session)
    first = AggregateAddress(session, "ipv4-unicast", "10.0.0.0/8", router)
    other = AggregateAddress(session, "ipv6-unicast", "2001:db8::/32", router)
    again = AggregateAddress(session, "ipv4-unicast", "10.0.0.0/8", router)
    assert list(router.aggregate_addresses) == [again, other]
    assert first not in router.aggregate_addresses

    again.delete()
    assert [r[:2] for r in requests] == [
        (
            "DELETE",
            "system/vrfs/default/bgp_routers/65000/aggregate_addresses/"
            "ipv4-unicast,10.0.0.0%2F8",
        )
    ]
    assert list(router.aggregate_addresses) == [other]
