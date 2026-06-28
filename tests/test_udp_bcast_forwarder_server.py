# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the UdpBcastForwarderServer module.

These tests do not require a live switch. They mock the HTTP layer
(session.request) and verify the request bodies and URIs produced by the
class, including the compound-index handling.
"""

import json

from types import SimpleNamespace

import pytest

import pyaoscx.utils.util as utils

from pyaoscx.udp_bcast_forwarder_server import UdpBcastForwarderServer


class FakeResponse:
    def __init__(self, status_code=200, text="{}"):
        self.status_code = status_code
        self.text = text


def make_session(get_text="{}"):
    calls = []

    def request(method, uri, params=None, data=None):
        calls.append(
            SimpleNamespace(method=method, uri=uri, params=params, data=data)
        )
        if method == "GET":
            return FakeResponse(200, get_text)
        return FakeResponse(201, "")

    api = SimpleNamespace(
        compound_index_separator=",",
        default_depth=1,
        default_selector="writable",
        valid_depths=[0, 1, 2, 3],
        valid_selectors=["writable", "configuration", "status"],
        configurable_selectors=["writable", "configuration"],
        valid_depth=lambda d: True,
        get_index=lambda obj: "idx",
    )
    session = SimpleNamespace(
        connected=True,
        api=api,
        request=request,
        calls=calls,
        resource_prefix="/rest/v10.09/",
    )
    return session


def make_vrf(name="default"):
    return SimpleNamespace(
        name=name,
        get_info_format=lambda: "/rest/v10.09/system/vrfs/" + name,
    )


def make_port(name="1/1/1"):
    percents = name.replace("/", "%2F")
    return SimpleNamespace(
        name=name,
        percents_name=percents,
        get_info_format=(lambda: "/rest/v10.09/system/interfaces/" + percents),
    )


def test_registry_resolution():
    from pyaoscx.rest.v10_09.api import v10_09

    api = v10_09()
    assert (
        api.get_module_class(None, "UdpBcastForwarderServer")
        is UdpBcastForwarderServer
    )


def test_index_uri():
    session = make_session()
    fwd = UdpBcastForwarderServer(session, make_vrf(), make_port(), 53)
    assert fwd._index_uri() == (
        "system/udp_bcast_forwarder_servers/default,1%2F1%2F1,53"
    )
    assert UdpBcastForwarderServer.indices == [
        "dest_vrf",
        "src_port",
        "udp_dport",
    ]


def test_create_body(monkeypatch):
    monkeypatch.setattr(utils, "_response_ok", lambda *a, **k: True)
    session = make_session()
    fwd = UdpBcastForwarderServer(
        session,
        make_vrf(),
        make_port(),
        53,
        ipv4_ucast_server=["10.0.0.1"],
    )
    assert fwd.create() is True
    post = [c for c in session.calls if c.method == "POST"][0]
    body = json.loads(post.data)
    assert post.uri == "system/udp_bcast_forwarder_servers"
    assert body["dest_vrf"] == "/rest/v10.09/system/vrfs/default"
    assert body["src_port"] == ("/rest/v10.09/system/interfaces/1%2F1%2F1")
    assert body["udp_dport"] == 53
    assert body["ipv4_ucast_server"] == ["10.0.0.1"]


def test_update_no_change(monkeypatch):
    monkeypatch.setattr(utils, "_response_ok", lambda *a, **k: True)
    session = make_session()
    fwd = UdpBcastForwarderServer(
        session,
        make_vrf(),
        make_port(),
        53,
        ipv4_ucast_server=["10.0.0.1"],
    )
    # Simulate a materialized object whose data equals the desired data.
    fwd.materialized = True
    fwd._UdpBcastForwarderServer__original_attributes = {
        "ipv4_ucast_server": ["10.0.0.1"]
    }
    assert fwd.update() is False
    assert not [c for c in session.calls if c.method == "PUT"]


def test_update_change(monkeypatch):
    monkeypatch.setattr(utils, "_response_ok", lambda *a, **k: True)
    session = make_session()
    fwd = UdpBcastForwarderServer(
        session,
        make_vrf(),
        make_port(),
        53,
        ipv4_ucast_server=["10.0.0.1", "10.0.0.2"],
    )
    fwd.materialized = True
    fwd._UdpBcastForwarderServer__original_attributes = {
        "ipv4_ucast_server": ["10.0.0.1"]
    }
    assert fwd.update() is True
    put = [c for c in session.calls if c.method == "PUT"][0]
    assert put.uri == (
        "system/udp_bcast_forwarder_servers/default,1%2F1%2F1,53"
    )
    assert json.loads(put.data)["ipv4_ucast_server"] == [
        "10.0.0.1",
        "10.0.0.2",
    ]


def test_delete(monkeypatch):
    monkeypatch.setattr(utils, "_response_ok", lambda *a, **k: True)
    session = make_session()
    fwd = UdpBcastForwarderServer(session, make_vrf(), make_port(), 53)
    fwd.delete()
    delete = [c for c in session.calls if c.method == "DELETE"][0]
    assert delete.uri == (
        "system/udp_bcast_forwarder_servers/default,1%2F1%2F1,53"
    )


def test_from_uri():
    session = make_session()
    # get_module is needed by from_uri to build Vrf and Interface objects.
    session.api.get_module = lambda sess, mod, idx: SimpleNamespace(name=idx)
    uri = (
        "/rest/v10.09/system/udp_bcast_forwarder_servers/"
        "default,1%2F1%2F1,53"
    )
    indices, fwd = UdpBcastForwarderServer.from_uri(session, uri)
    assert indices == "default,1%2F1%2F1,53"
    assert isinstance(fwd, UdpBcastForwarderServer)
    assert fwd.udp_dport == "53"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
