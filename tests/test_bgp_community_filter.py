# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the BgpCommunityFilter and BgpCommunityFilterEntry
modules.

These tests do not require a live switch. They mock the HTTP layer
(_post_data / _put_data) and verify the request bodies and URIs produced by
the classes, including the index immutability rules.
"""

from types import SimpleNamespace

import pytest

from pyaoscx.bgp_community_filter import BgpCommunityFilter
from pyaoscx.bgp_community_filter_entry import BgpCommunityFilterEntry


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
    assert (
        api.get_module_class(session, "BgpCommunityFilter")
        is BgpCommunityFilter
    )
    assert (
        api.get_module_class(session, "BgpCommunityFilterEntry")
        is BgpCommunityFilterEntry
    )


def test_filter_uris():
    session = make_session()
    flt = BgpCommunityFilter(session, "C1")
    assert flt.name == "C1"
    assert flt.path == "system/bgp_community_filters/C1"
    assert flt.base_uri == "system/bgp_community_filters"
    assert BgpCommunityFilter.indices == ["name"]


def test_filter_create_body():
    session = make_session()
    flt = BgpCommunityFilter(
        session, "C1", type="community-list", description="x"
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    flt._post_data = fake_post
    assert flt.create() is True
    assert captured["name"] == "C1"
    assert captured["type"] == "community-list"
    assert captured["description"] == "x"


def test_filter_update_strips_name():
    session = make_session()
    flt = BgpCommunityFilter(
        session, "C1", type="community-list", description="x"
    )

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    flt._put_data = fake_put
    assert flt.update() is True
    assert "name" not in captured
    assert captured["type"] == "community-list"
    assert captured["description"] == "x"


def test_entry_uris():
    session = make_session()
    parent = BgpCommunityFilter(session, "C1")
    entry = BgpCommunityFilterEntry(session, 10, parent, action="permit")
    assert entry.preference == 10
    assert entry.path == (
        "system/bgp_community_filters/C1/bgp_community_filter_entries/10"
    )
    assert entry.base_uri == (
        "system/bgp_community_filters/C1/bgp_community_filter_entries"
    )
    assert BgpCommunityFilterEntry.indices == ["preference"]


def test_entry_create_body():
    session = make_session()
    parent = BgpCommunityFilter(session, "C1")
    entry = BgpCommunityFilterEntry(
        session, 10, parent, action="permit", match_string="65000:1"
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    entry._post_data = fake_post
    assert entry.create() is True
    assert captured["preference"] == 10
    assert captured["action"] == "permit"
    assert captured["match_string"] == "65000:1"


def test_entry_update_strips_index():
    session = make_session()
    parent = BgpCommunityFilter(session, "C1")
    entry = BgpCommunityFilterEntry(session, 10, parent, action="deny")

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
        "/rest/v10.09/system/bgp_community_filters/C1/"
        "bgp_community_filter_entries/20"
    )
    preference, entry = BgpCommunityFilterEntry.from_uri(session, uri)
    assert preference == "20"
    assert isinstance(entry, BgpCommunityFilterEntry)
    assert entry.preference == "20"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
