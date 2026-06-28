# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the RouteMap and RouteMapEntry modules.

These tests do not require a live switch. They mock the HTTP layer
(_post_data / _put_data) and verify the request bodies and URIs produced by
the classes, including the index immutability rules.
"""

from types import SimpleNamespace

import pytest

from pyaoscx.route_map import RouteMap
from pyaoscx.route_map_entry import RouteMapEntry


def make_session():
    api = SimpleNamespace(
        default_selector="writable",
        default_depth=1,
        default_facts_depth=2,
        compound_index_separator=",",
    )
    return SimpleNamespace(connected=True, api=api)


def test_registry_resolution():
    session = make_session()
    from pyaoscx.rest.v10_09.api import v10_09

    api = v10_09()
    assert api.get_module_class(session, "RouteMap") is RouteMap
    assert api.get_module_class(session, "RouteMapEntry") is RouteMapEntry


def test_route_map_uris():
    session = make_session()
    rmap = RouteMap(session, "RM1")
    assert rmap.name == "RM1"
    assert rmap.path == "system/route_maps/RM1"
    assert rmap.base_uri == "system/route_maps"
    assert RouteMap.indices == ["name"]


def test_route_map_create_body():
    session = make_session()
    rmap = RouteMap(session, "RM1")

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    rmap._post_data = fake_post
    assert rmap.create() is True
    assert captured["name"] == "RM1"


def test_route_map_update_strips_name():
    session = make_session()
    rmap = RouteMap(session, "RM1", description="x")

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    rmap._put_data = fake_put
    assert rmap.update() is True
    assert "name" not in captured
    assert captured["description"] == "x"


def test_route_map_entry_uris():
    session = make_session()
    parent = RouteMap(session, "RM1")
    entry = RouteMapEntry(session, 10, parent, action="permit")
    assert entry.preference == 10
    assert entry.path == "system/route_maps/RM1/route_map_entries/10"
    assert entry.base_uri == "system/route_maps/RM1/route_map_entries"
    assert RouteMapEntry.indices == ["preference"]


def test_route_map_entry_create_body():
    session = make_session()
    parent = RouteMap(session, "RM1")
    entry = RouteMapEntry(
        session,
        10,
        parent,
        action="permit",
        match={"source_protocol": "bgp"},
        set={"local_preference": 200},
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    entry._post_data = fake_post
    assert entry.create() is True
    assert captured["preference"] == 10
    assert captured["action"] == "permit"
    assert captured["match"] == {"source_protocol": "bgp"}
    assert captured["set"] == {"local_preference": 200}


def test_route_map_entry_update_strips_index():
    session = make_session()
    parent = RouteMap(session, "RM1")
    entry = RouteMapEntry(session, 10, parent, action="deny")

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    entry._put_data = fake_put
    assert entry.update() is True
    assert "preference" not in captured
    assert captured["action"] == "deny"


def test_route_map_entry_from_uri():
    session = make_session()
    uri = "/rest/v10.09/system/route_maps/RM1/route_map_entries/20"
    preference, entry = RouteMapEntry.from_uri(session, uri)
    assert preference == "20"
    assert isinstance(entry, RouteMapEntry)
    assert entry.preference == "20"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
