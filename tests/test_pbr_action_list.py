# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the PbrActionList and PbrActionListEntry modules.

These tests do not require a live switch. They mock the HTTP layer
(_post_data / _put_data) and verify the request bodies and URIs produced by
the classes, including the index immutability rules.
"""

from types import SimpleNamespace

import pytest

from pyaoscx.pbr_action_list import PbrActionList
from pyaoscx.pbr_action_list_entry import PbrActionListEntry


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
    assert api.get_module_class(session, "PbrActionList") is PbrActionList
    assert (
        api.get_module_class(session, "PbrActionListEntry")
        is PbrActionListEntry
    )


def test_action_list_uris():
    session = make_session()
    pal = PbrActionList(session, "PBR1")
    assert pal.name == "PBR1"
    assert pal.path == "system/pbr_action_lists/PBR1"
    assert pal.base_uri == "system/pbr_action_lists"
    assert PbrActionList.indices == ["name"]


def test_action_list_create_body():
    session = make_session()
    pal = PbrActionList(
        session, "PBR1", vsx_sync=["all_attributes_and_dependents"]
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    pal._post_data = fake_post
    assert pal.create() is True
    assert captured["name"] == "PBR1"
    assert captured["vsx_sync"] == ["all_attributes_and_dependents"]


def test_action_list_update_strips_name():
    session = make_session()
    pal = PbrActionList(session, "PBR1", vsx_sync=[])

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    pal._put_data = fake_put
    assert pal.update() is True
    assert "name" not in captured
    assert captured["vsx_sync"] == []


def test_entry_uris():
    session = make_session()
    parent = PbrActionList(session, "PBR1")
    entry = PbrActionListEntry(session, 10, parent, type="blackhole")
    assert entry.sequence_number == 10
    assert entry.path == ("system/pbr_action_lists/PBR1/cfg_entries/10")
    assert entry.base_uri == ("system/pbr_action_lists/PBR1/cfg_entries")
    assert PbrActionListEntry.indices == ["sequence_number"]


def test_entry_create_body_nexthop():
    session = make_session()
    parent = PbrActionList(session, "PBR1")
    entry = PbrActionListEntry(
        session, 10, parent, type="nexthop", ip="10.0.0.1"
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    entry._post_data = fake_post
    assert entry.create() is True
    assert captured["sequence_number"] == 10
    assert captured["type"] == "nexthop"
    assert captured["ip"] == "10.0.0.1"


def test_entry_create_body_interface():
    session = make_session()
    parent = PbrActionList(session, "PBR1")
    uri = "/rest/v10.09/system/interfaces/1%2F1%2F1"
    entry = PbrActionListEntry(
        session, 20, parent, type="interface", interface=uri
    )

    captured = {}

    def fake_post(data):
        captured.update(data)
        return True

    entry._post_data = fake_post
    assert entry.create() is True
    assert captured["sequence_number"] == 20
    assert captured["type"] == "interface"
    assert captured["interface"] == uri


def test_entry_update_strips_index():
    session = make_session()
    parent = PbrActionList(session, "PBR1")
    entry = PbrActionListEntry(session, 10, parent, type="blackhole")

    captured = {}

    def fake_put(data):
        captured.clear()
        captured.update(data)
        return True

    entry._put_data = fake_put
    assert entry.update() is True
    assert "sequence_number" not in captured
    assert captured["type"] == "blackhole"


def test_entry_from_uri():
    session = make_session()
    uri = "/rest/v10.09/system/pbr_action_lists/PBR1/cfg_entries/30"
    sequence_number, entry = PbrActionListEntry.from_uri(session, uri)
    assert sequence_number == "30"
    assert isinstance(entry, PbrActionListEntry)
    assert entry.sequence_number == "30"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
