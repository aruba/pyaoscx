# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the DhcpRelay module.

These tests do not require a live switch. They focus on the compound-index
parsing in ``from_uri`` / ``get_all``: the two indices (vrf and port) are
joined in the URI by the compound index separator (a comma), and the port
name is percent-encoded, e.g. ``dhcp_relays/default,1%2F1%2F3``.
"""

import json

from types import SimpleNamespace

from pyaoscx.dhcp_relay import DhcpRelay


def make_session():
    """Session whose get_module records calls and returns named stubs."""
    calls = []

    def get_module(session, module, index, **kwargs):
        calls.append(SimpleNamespace(module=module, index=index))
        return SimpleNamespace(name=index)

    def get_uri_from_data(data):
        return list(data.values())

    api = SimpleNamespace(
        compound_index_separator=",",
        get_module=get_module,
        get_uri_from_data=get_uri_from_data,
    )
    session = SimpleNamespace(api=api, calls=calls)
    return session


def test_from_uri_parses_comma_separated_index():
    session = make_session()
    uri = "/rest/v10.09/system/dhcp_relays/default,1%2F1%2F3"

    indices, relay = DhcpRelay.from_uri(session, uri)

    # The index string keeps the vrf and the percent-encoded port name.
    assert indices == "default,1%2F1%2F3"
    assert isinstance(relay, DhcpRelay)
    # The port index is everything after the first comma (not split on "/").
    modules = {c.module: c.index for c in session.calls}
    assert modules["Vrf"] == "default"
    assert modules["Interface"] == "1%2F1%2F3"


def test_from_uri_vrf_with_underscores():
    session = make_session()
    uri = "/rest/v10.09/system/dhcp_relays/mgmt_vrf,vlan204"

    indices, relay = DhcpRelay.from_uri(session, uri)

    assert indices == "mgmt_vrf,vlan204"
    modules = {c.module: c.index for c in session.calls}
    assert modules["Vrf"] == "mgmt_vrf"
    assert modules["Interface"] == "vlan204"


def test_get_all_builds_dict_keyed_by_indices():
    session = make_session()

    def request(method, uri, params=None, data=None):
        body = {
            "default,1%2F1%2F3": (
                "/rest/v10.09/system/dhcp_relays/default,1%2F1%2F3"
            ),
            "default,vlan204": (
                "/rest/v10.09/system/dhcp_relays/default,vlan204"
            ),
        }
        return SimpleNamespace(status_code=200, text=json.dumps(body))

    session.request = request

    result = DhcpRelay.get_all(session)

    assert set(result.keys()) == {"default,1%2F1%2F3", "default,vlan204"}
    for relay in result.values():
        assert isinstance(relay, DhcpRelay)
