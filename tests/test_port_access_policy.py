# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the Port Access policy family resource modules
(PortAccessGbp/Abp/Policy containers, their entries and action sets). The
pyaoscx Session is mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.port_access_gbp import (
    PortAccessGbp,
    PortAccessGbpActionSet,
    PortAccessGbpEntry,
)
from pyaoscx.port_access_abp import (
    PortAccessAbp,
    PortAccessAbpActionSet,
)
from pyaoscx.port_access_policy import (
    PortAccessPolicy,
    PortAccessPolicyActionSet,
)


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
# Container
# --------------------------------------------------------------------------
def test_container_path():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    assert gbp.path == "system/port_access_gbps/g1"
    assert gbp.name == "g1"


def test_container_create_sends_name():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    gbp.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/port_access_gbps"
    assert post["data"]["name"] == "g1"


def test_container_delete():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    gbp.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert deletes[0]["path"] == "system/port_access_gbps/g1"


def test_container_get_all():
    session = make_session(
        get_body={"g1": "/rest/v10.16/system/port_access_gbps/g1"}
    )
    containers = PortAccessGbp.get_all(session)
    assert "g1" in containers
    assert containers["g1"].name == "g1"


def test_container_base_uris():
    session = make_session()
    assert PortAccessAbp(session, "a").path == "system/port_access_abps/a"
    assert (
        PortAccessPolicy(session, "p").path == "system/port_access_policies/p"
    )


# --------------------------------------------------------------------------
# Entry
# --------------------------------------------------------------------------
def test_entry_path():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    entry = PortAccessGbpEntry(session, 10, gbp)
    assert entry.path == "system/port_access_gbps/g1/cfg_entries/10"
    assert entry.base_uri == "system/port_access_gbps/g1/cfg_entries"
    assert entry.sequence_number == 10


def test_entry_create_sends_class_and_comment():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    entry = PortAccessGbpEntry(
        session,
        10,
        gbp,
        **{
            "class": "/rest/v10.16/system/classes/c1,gbp-ipv4",
            "comment": "x",
        }
    )
    entry.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/port_access_gbps/g1/cfg_entries"
    assert post["data"]["sequence_number"] == 10
    assert post["data"]["class"] == "/rest/v10.16/system/classes/c1,gbp-ipv4"
    assert post["data"]["comment"] == "x"


def test_entry_get_all():
    session = make_session(
        get_body={
            "10": ("/rest/v10.16/system/port_access_gbps/g1/cfg_entries/10")
        }
    )
    gbp = PortAccessGbp(session, "g1")
    entries = PortAccessGbpEntry.get_all(session, gbp)
    assert "10" in entries
    assert entries["10"].sequence_number == "10"


def test_entry_delete():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    entry = PortAccessGbpEntry(session, 10, gbp)
    entry.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert deletes[0]["path"] == "system/port_access_gbps/g1/cfg_entries/10"


# --------------------------------------------------------------------------
# Action set
# --------------------------------------------------------------------------
def test_action_set_path():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    entry = PortAccessGbpEntry(session, 10, gbp)
    action = PortAccessGbpActionSet(session, entry)
    assert action.path == (
        "system/port_access_gbps/g1/cfg_entries/10/gbp_action_set"
    )


def test_action_set_create_sends_fields():
    session = make_session()
    gbp = PortAccessGbp(session, "g1")
    entry = PortAccessGbpEntry(session, 10, gbp)
    action = PortAccessGbpActionSet(session, entry, drop=True)
    action.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == (
        "system/port_access_gbps/g1/cfg_entries/10/gbp_action_set"
    )
    assert post["data"]["drop"] is True


def test_action_set_update_idempotent():
    session = make_session(get_body={"drop": True})
    gbp = PortAccessGbp(session, "g1")
    entry = PortAccessGbpEntry(session, 10, gbp)
    action = PortAccessGbpActionSet(session, entry)
    action.get()
    action.drop = True
    action.config_attrs = ["drop"]
    assert action.update() is False


def test_action_set_keys_per_family():
    assert PortAccessGbpActionSet.action_key == "gbp_action_set"
    assert PortAccessAbpActionSet.action_key == "abp_action_set"
    assert PortAccessPolicyActionSet.action_key == "policy_action_set"
