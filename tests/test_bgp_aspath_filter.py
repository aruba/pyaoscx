# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the BgpAspathFilter and BgpAspathFilterEntry modules.

These tests do not require a live switch. They mock the HTTP layer
(_post_data / _put_data) and verify the request bodies and URIs produced by
the classes, including the index immutability rules.
"""

from types import SimpleNamespace

import pytest

from pyaoscx.bgp_aspath_filter import BgpAspathFilter
from pyaoscx.bgp_aspath_filter_entry import BgpAspathFilterEntry


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
    assert api.get_module_class(session, "BgpAspathFilter") is BgpAspathFilter
    assert (
        api.get_module_class(session, "BgpAspathFilterEntry")
        is BgpAspathFilterEntry
    )


def test_filter_uris():
    session = make_session()
    flt = BgpAspathFilter(session, "F1")
    assert flt.name == "F1"
    assert flt.path == "system/bgp_aspath_filters/F1"
    assert flt.base_uri == "system/bgp_aspath_filters"
    assert BgpAspathFilter.indices == ["name"]


def test_filter_create_body():
    session = make_session()
    flt = BgpAspathFilter(session, "F1", description="x")

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    flt._post_data = fake_post
    assert flt.create() is True
    assert captured["name"] == "F1"
    assert captured["description"] == "x"


def test_filter_update_strips_name():
    session = make_session()
    flt = BgpAspathFilter(session, "F1", description="x")

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    flt._put_data = fake_put
    assert flt.update() is True
    assert "name" not in captured
    assert captured["description"] == "x"


def test_entry_uris():
    session = make_session()
    parent = BgpAspathFilter(session, "F1")
    entry = BgpAspathFilterEntry(session, 10, parent, action="permit")
    assert entry.preference == 10
    assert entry.path == (
        "system/bgp_aspath_filters/F1/bgp_aspath_filter_entries/10"
    )
    assert entry.base_uri == (
        "system/bgp_aspath_filters/F1/bgp_aspath_filter_entries"
    )
    assert BgpAspathFilterEntry.indices == ["preference"]


def test_entry_create_body():
    session = make_session()
    parent = BgpAspathFilter(session, "F1")
    entry = BgpAspathFilterEntry(
        session, 10, parent, action="permit", regex="^65000_"
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    entry._post_data = fake_post
    assert entry.create() is True
    assert captured["preference"] == 10
    assert captured["action"] == "permit"
    assert captured["regex"] == "^65000_"


def test_entry_update_strips_index():
    session = make_session()
    parent = BgpAspathFilter(session, "F1")
    entry = BgpAspathFilterEntry(session, 10, parent, action="deny")

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    entry._put_data = fake_put
    assert entry.update() is True
    assert "preference" not in captured
    assert captured["action"] == "deny"


def test_entry_from_uri():
    session = make_session()
    uri = (
        "/rest/v10.09/system/bgp_aspath_filters/F1/"
        "bgp_aspath_filter_entries/20"
    )
    preference, entry = BgpAspathFilterEntry.from_uri(session, uri)
    assert preference == "20"
    assert isinstance(entry, BgpAspathFilterEntry)
    assert entry.preference == "20"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
