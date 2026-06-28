# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the Mirror and MirrorEndpoint pyaoscx resource
modules. The pyaoscx Session is mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.mirror import Mirror
from pyaoscx.mirror_endpoint import MirrorEndpoint


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


def fake_port(name):
    port = MagicMock()
    port.name = name
    uri = "/rest/v10.09/system/interfaces/{0}".format(name.replace("/", "%2F"))
    port.get_info_format.return_value = {name: uri}
    return port


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
    api.configurable_selectors = ["configuration", "writable"]
    api.valid_depth = lambda depth: True
    session.resource_prefix = "/rest/v10.09/"

    def get_module(sess, module, index=None, **kwargs):
        if module == "Interface":
            return fake_port(index)
        if module == "Vlan":
            vlan = MagicMock()
            vlan.name = str(index)
            uri = "/rest/v10.09/system/vlans/{0}".format(index)
            vlan.get_info_format.return_value = {str(index): uri}
            return vlan
        raise AssertionError("unexpected module {0}".format(module))

    api.get_module.side_effect = get_module

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
# Mirror
# --------------------------------------------------------------------------
def test_mirror_path():
    session = make_session()
    mirror = Mirror(session, 5)
    assert mirror.path == "system/mirrors/5"
    assert mirror.id == 5


def test_mirror_get_converts_references():
    body = {
        "active": False,
        "session_type": "port",
        "select_src_port": {
            "1/1/27": "/rest/v10.09/system/interfaces/1%2F1%2F27"
        },
        "output_port": {"1/1/28": "/rest/v10.09/system/interfaces/1%2F1%2F28"},
        "select_dst_port": {},
        "select_rx_vlan": {},
        "select_tx_vlan": {},
    }
    session = make_session(get_body=body)
    mirror = Mirror(session, 5)
    mirror.get(selector="writable")
    assert [p.name for p in mirror.select_src_port] == ["1/1/27"]
    assert [p.name for p in mirror.output_port] == ["1/1/28"]
    assert mirror.select_dst_port == []


def test_mirror_create_sends_id_and_refs():
    session = make_session()
    src = fake_port("1/1/27")
    out = fake_port("1/1/28")
    mirror = Mirror(
        session,
        99,
        session_type="port",
        active=False,
        select_src_port=[src],
        output_port=[out],
    )
    mirror.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["data"]["id"] == 99
    assert post["data"]["select_src_port"] == {
        "1/1/27": "/rest/v10.09/system/interfaces/1%2F1%2F27"
    }
    assert post["data"]["output_port"] == {
        "1/1/28": "/rest/v10.09/system/interfaces/1%2F1%2F28"
    }


def test_mirror_update_idempotent():
    body = {
        "active": False,
        "comment": "x",
        "session_type": "port",
        "select_src_port": {
            "1/1/27": "/rest/v10.09/system/interfaces/1%2F1%2F27"
        },
        "output_port": {},
        "select_dst_port": {},
        "select_rx_vlan": {},
        "select_tx_vlan": {},
    }
    session = make_session(get_body=body)
    mirror = Mirror(session, 5)
    mirror.get(selector="writable")
    assert mirror.update() is False
    mirror.comment = "y"
    assert mirror.update() is True


def test_mirror_from_uri():
    session = make_session()
    session_id, mirror = Mirror.from_uri(session, "system/mirrors/7")
    assert session_id == "7"
    assert mirror.id == 7


def test_mirror_get_all():
    body = {"1": "/rest/v10.09/system/mirrors/1"}
    session = make_session(get_body=body)
    collection = Mirror.get_all(session)
    assert set(collection.keys()) == {"1"}
    assert isinstance(collection["1"], Mirror)


# --------------------------------------------------------------------------
# MirrorEndpoint
# --------------------------------------------------------------------------
def test_endpoint_path():
    session = make_session()
    ep = MirrorEndpoint(session, "e1")
    assert ep.path == "system/mirror_endpoints/e1"
    assert ep.name == "e1"


def test_endpoint_get_converts_references():
    body = {
        "admin": "down",
        "comment": None,
        "output_port": {"1/1/27": "/rest/v10.09/system/interfaces/1%2F1%2F27"},
        "tunnel": {},
    }
    session = make_session(get_body=body)
    ep = MirrorEndpoint(session, "e1")
    ep.get(selector="writable")
    assert [p.name for p in ep.output_port] == ["1/1/27"]


def test_endpoint_create_sends_name_and_refs():
    session = make_session()
    out = fake_port("1/1/27")
    ep = MirrorEndpoint(
        session,
        "ansible_ep",
        admin="down",
        output_port=[out],
        tunnel={"id": 100},
    )
    ep.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["data"]["name"] == "ansible_ep"
    assert post["data"]["output_port"] == {
        "1/1/27": "/rest/v10.09/system/interfaces/1%2F1%2F27"
    }
    assert post["data"]["tunnel"] == {"id": 100}


def test_endpoint_update_idempotent():
    body = {
        "admin": "down",
        "comment": "x",
        "output_port": {},
        "tunnel": {},
    }
    session = make_session(get_body=body)
    ep = MirrorEndpoint(session, "e1")
    ep.get(selector="writable")
    assert ep.update() is False
    ep.admin = "up"
    assert ep.update() is True


def test_endpoint_get_all():
    body = {"e1": "/rest/v10.09/system/mirror_endpoints/e1"}
    session = make_session(get_body=body)
    collection = MirrorEndpoint.get_all(session)
    assert set(collection.keys()) == {"e1"}
    assert isinstance(collection["e1"], MirrorEndpoint)
