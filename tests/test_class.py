# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the Class and ClassEntry pyaoscx resource modules. The
pyaoscx Session is mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from importlib import import_module

from pyaoscx.class_entry import ClassEntry

Class = getattr(import_module("pyaoscx.class"), "Class")


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


def make_session(get_body=None):
    session = MagicMock()
    api = session.api
    api.default_depth = 1
    api.default_selector = "writable"
    api.valid_depths = [0, 1, 2, 3, 4]
    api.valid_selectors = [
        "configuration",
        "writable",
        "status",
        "statistics",
    ]
    api.configurable_selectors = ["writable"]
    api.compound_index_separator = ","
    api.valid_depth = lambda depth: True
    api.get_uri_from_data.side_effect = lambda data: list(data.values())
    session.resource_prefix = "/rest/v10.16/"
    session.proxy = None

    calls = []

    def request(method, path, params=None, data=None):
        body = json.loads(data) if data else None
        calls.append({"method": method, "path": path, "data": body})
        if method == "GET":
            return make_response(get_body if get_body is not None else {})
        if method == "POST":
            return make_response({}, 201)
        if method in ("PUT", "DELETE"):
            return make_response({}, 204)
        return make_response({}, 200)

    session.request.side_effect = request
    session.calls = calls
    return session


# --------------------------------------------------------------------------
# Class
# --------------------------------------------------------------------------
def test_class_path():
    session = make_session()
    traffic_class = Class(session, "web", type="ipv4")
    assert traffic_class.path == "system/classes/web,ipv4"
    assert traffic_class.index == "web,ipv4"
    assert traffic_class.name == "web"
    assert traffic_class.type == "ipv4"


def test_class_create_sends_name_and_type():
    session = make_session()
    traffic_class = Class(session, "web", type="ipv4")
    traffic_class.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/classes"
    assert post["data"]["name"] == "web"
    assert post["data"]["type"] == "ipv4"


def test_class_delete():
    session = make_session()
    traffic_class = Class(session, "web", type="ipv4")
    traffic_class.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert deletes and deletes[0]["path"] == "system/classes/web,ipv4"


def test_class_get_all():
    session = make_session(
        get_body={"web,ipv4": "/rest/v10.16/system/classes/web,ipv4"}
    )
    classes = Class.get_all(session)
    assert "web,ipv4" in classes
    assert classes["web,ipv4"].name == "web"
    assert classes["web,ipv4"].type == "ipv4"


# --------------------------------------------------------------------------
# ClassEntry
# --------------------------------------------------------------------------
def make_parent(session):
    return Class(session, "web", type="ipv4")


def test_entry_path():
    session = make_session()
    parent = make_parent(session)
    entry = ClassEntry(session, 10, parent)
    assert entry.path == "system/classes/web,ipv4/cfg_entries/10"
    assert entry.base_uri == "system/classes/web,ipv4/cfg_entries"
    assert entry.sequence_number == 10


def test_entry_create_sends_sequence_number_and_attrs():
    session = make_session()
    parent = make_parent(session)
    entry = ClassEntry(
        session, 10, parent, type="match", protocol=6, dst_ip="10.0.0.0/24"
    )
    entry.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/classes/web,ipv4/cfg_entries"
    assert post["data"]["sequence_number"] == 10
    assert post["data"]["type"] == "match"
    assert post["data"]["protocol"] == 6
    assert post["data"]["dst_ip"] == "10.0.0.0/24"


def test_entry_get_configuration_selector():
    session = make_session(get_body={"type": "match", "protocol": 6})
    parent = make_parent(session)
    entry = ClassEntry(session, 10, parent)
    entry.get(selector="configuration")
    assert entry.type == "match"
    assert entry.protocol == 6


def test_entry_get_all():
    session = make_session(
        get_body={"10": "/rest/v10.16/system/classes/web,ipv4/cfg_entries/10"}
    )
    parent = make_parent(session)
    entries = ClassEntry.get_all(session, parent)
    assert "10" in entries
    assert entries["10"].sequence_number == "10"


def test_entry_delete():
    session = make_session()
    parent = make_parent(session)
    entry = ClassEntry(session, 10, parent)
    entry.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert deletes[0]["path"] == "system/classes/web,ipv4/cfg_entries/10"
