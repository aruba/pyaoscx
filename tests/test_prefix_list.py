# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the PrefixList and PrefixListEntry modules.

These tests do not require a live switch. They mock the HTTP layer
(_post_data / _put_data / _send_data) and verify the request bodies and
URIs produced by the classes, including the immutability rules for the
index attributes (name / preference) and the address family.
"""

from types import SimpleNamespace

import pytest

from pyaoscx.prefix_list import PrefixList
from pyaoscx.prefix_list_entry import PrefixListEntry


def make_session():
    """Build a minimal mocked session accepted by @connected."""
    api = SimpleNamespace(
        default_selector="writable",
        default_depth=1,
        default_facts_depth=2,
        compound_index_separator=",",
    )
    return SimpleNamespace(connected=True, api=api)


# --------------------------------------------------------------------------
# Registry resolution
# --------------------------------------------------------------------------
def test_registry_resolution():
    session = make_session()
    from pyaoscx.rest.v10_09.api import v10_09

    api = v10_09()
    cls = api.get_module_class(session, "PrefixList")
    assert cls is PrefixList
    cls_entry = api.get_module_class(session, "PrefixListEntry")
    assert cls_entry is PrefixListEntry


# --------------------------------------------------------------------------
# PrefixList
# --------------------------------------------------------------------------
def test_prefix_list_uris():
    session = make_session()
    plist = PrefixList(session, "MY_LIST")
    assert plist.name == "MY_LIST"
    assert plist.path == "system/prefix_lists/MY_LIST"
    assert plist.base_uri == "system/prefix_lists"
    assert PrefixList.indices == ["name"]


def test_prefix_list_create_body():
    session = make_session()
    plist = PrefixList(
        session,
        "MY_LIST",
        address_family="ipv4",
        description="lab",
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    plist._post_data = fake_post
    assert plist.create() is True
    # The index must be explicitly added to the POST body.
    assert captured["name"] == "MY_LIST"
    assert captured["address_family"] == "ipv4"
    assert captured["description"] == "lab"


def test_prefix_list_update_strips_immutable():
    session = make_session()
    plist = PrefixList(
        session,
        "MY_LIST",
        address_family="ipv4",
        description="changed",
    )

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    plist._put_data = fake_put
    assert plist.update() is True
    # name (index) and address_family (immutable) must never be in PUT body.
    assert "name" not in captured
    assert "address_family" not in captured
    assert captured["description"] == "changed"


def test_prefix_list_from_uri():
    session = make_session()
    name, plist = PrefixList.from_uri(
        session, "/rest/v10.09/system/prefix_lists/MY_LIST"
    )
    assert name == "MY_LIST"
    assert isinstance(plist, PrefixList)
    assert plist.name == "MY_LIST"


# --------------------------------------------------------------------------
# PrefixListEntry
# --------------------------------------------------------------------------
def test_prefix_list_entry_uris():
    session = make_session()
    parent = PrefixList(session, "MY_LIST")
    entry = PrefixListEntry(session, 10, parent, action="permit")
    assert entry.preference == 10
    assert entry.path == ("system/prefix_lists/MY_LIST/prefix_list_entries/10")
    assert entry.base_uri == (
        "system/prefix_lists/MY_LIST/prefix_list_entries"
    )
    assert PrefixListEntry.indices == ["preference"]


def test_prefix_list_entry_create_body():
    session = make_session()
    parent = PrefixList(session, "MY_LIST")
    entry = PrefixListEntry(
        session,
        10,
        parent,
        action="permit",
        prefix="10.0.0.0/8",
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    entry._post_data = fake_post
    assert entry.create() is True
    assert captured["preference"] == 10
    assert captured["action"] == "permit"
    assert captured["prefix"] == "10.0.0.0/8"


def test_prefix_list_entry_update_strips_index():
    session = make_session()
    parent = PrefixList(session, "MY_LIST")
    entry = PrefixListEntry(
        session,
        10,
        parent,
        action="deny",
    )

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    entry._put_data = fake_put
    assert entry.update() is True
    assert "preference" not in captured
    assert captured["action"] == "deny"


def test_prefix_list_entry_from_uri():
    session = make_session()
    uri = "/rest/v10.09/system/prefix_lists/MY_LIST/" "prefix_list_entries/20"
    preference, entry = PrefixListEntry.from_uri(session, uri)
    assert preference == "20"
    assert isinstance(entry, PrefixListEntry)
    assert entry.preference == "20"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
