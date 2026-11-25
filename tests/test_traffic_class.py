# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for traffic classes (Class, ClassEntry) and port access
roles (PortAccessRole).
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from pyaoscx.class_entry import ClassEntry
from pyaoscx.port_access_role import PortAccessRole
from pyaoscx.traffic_class import Class


def make_session(get_data=None, uri_list=()):
    session = MagicMock()
    session.connected = True
    session.resource_prefix = "/rest/v10.16/"
    session.api = SimpleNamespace(
        default_selector="configuration",
        default_depth=1,
        valid_selectors=["configuration", "writable", "status"],
        configurable_selectors=["configuration", "writable"],
        valid_depth=lambda depth: True,
        get_uri_from_data=lambda data: list(uri_list),
    )
    responses = {
        "GET": MagicMock(status_code=200, text=json.dumps(get_data or {})),
        "POST": MagicMock(status_code=201, text=""),
    }
    session.request.side_effect = lambda verb, *a, **k: responses.get(
        verb, MagicMock(status_code=200, text="")
    )
    return session


def written(session, verb):
    calls = [c for c in session.request.call_args_list if c.args[0] == verb]
    return [(c.args[1], json.loads(c.kwargs["data"])) for c in calls]


def test_class_create_posts_name_and_type():
    session = make_session({"name": "c1", "type": "gbp-ipv4"})
    traffic_class = Class(session, "c1", "gbp-ipv4")
    assert traffic_class.path == "system/classes/c1,gbp-ipv4"
    assert traffic_class.create() is True
    assert written(session, "POST") == [
        ("system/classes", {"name": "c1", "type": "gbp-ipv4"})
    ]


def test_class_update_never_sends_read_only_attributes():
    session = make_session(
        {
            "name": "c1",
            "type": "gbp-ipv4",
            "origin": "configuration",
            "cfg_entries": {"10": "/rest/v10.16/x"},
            "cfg_version": 1,
        }
    )
    traffic_class = Class(session, "c1", "gbp-ipv4")
    traffic_class.get()
    assert traffic_class.config_attrs == ["cfg_version"]
    assert traffic_class.update() is False
    traffic_class.cfg_version = 2
    assert traffic_class.update() is True
    assert written(session, "PUT") == [
        ("system/classes/c1,gbp-ipv4", {"cfg_version": 2})
    ]


def test_class_from_uri_handles_comma_in_name():
    index, traffic_class = Class.from_uri(
        MagicMock(), "/rest/v10.16/system/classes/a,b,gbp-mac"
    )
    assert index == "a,b,gbp-mac"
    assert (traffic_class.name, traffic_class.type) == ("a,b", "gbp-mac")


def test_class_entry_create_under_parent_class():
    session = make_session({"sequence_number": 10, "type": "match"})
    parent = Class(session, "gbp_allow_user1", "gbp-ipv4")
    entry = ClassEntry(
        session, 10, parent, type="match", dst_role="fabric_user1", count=True
    )
    assert entry.create() is True
    uri, body = written(session, "POST")[0]
    assert uri == "system/classes/gbp_allow_user1,gbp-ipv4/cfg_entries"
    assert body == {
        "sequence_number": 10,
        "type": "match",
        "dst_role": "fabric_user1",
        "count": True,
    }


def test_class_entry_update_sends_only_comment():
    session = make_session()
    entry = ClassEntry(session, 10, Class(session, "c1", "ipv4"), comment="x")
    assert entry.update() is True
    assert written(session, "PUT") == [
        ("system/classes/c1,ipv4/cfg_entries/10", {"comment": "x"})
    ]


def test_class_entry_get_all():
    session = make_session(
        uri_list=[
            "/rest/v10.16/system/classes/c1,ipv4/cfg_entries/10",
            "/rest/v10.16/system/classes/c1,ipv4/cfg_entries/20",
        ]
    )
    entries = ClassEntry.get_all(session, Class(session, "c1", "ipv4"))
    assert sorted(entries) == ["10", "20"]
    assert entries["20"].path == "system/classes/c1,ipv4/cfg_entries/20"


def test_port_access_role_create_and_update():
    session = make_session({"auth_mode": "client-mode", "reauth_period": 760})
    role = PortAccessRole(
        session, "fabric_user1", auth_mode="client-mode", reauth_period=760
    )
    assert role.path == "system/port_access_roles/fabric_user1"
    assert role.create() is True
    assert written(session, "POST") == [
        (
            "system/port_access_roles",
            {
                "auth_mode": "client-mode",
                "reauth_period": 760,
                "name": "fabric_user1",
            },
        )
    ]
    role.reauth_period = 800
    assert role.update() is True
    assert written(session, "PUT") == [
        (
            "system/port_access_roles/fabric_user1",
            {"auth_mode": "client-mode", "reauth_period": 800},
        )
    ]
