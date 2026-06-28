# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the IpslaSource, IpslaResponder and IpslaTrackObject
pyaoscx resource modules. The pyaoscx Session is mocked, so no switch is
required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.ipsla_source import IpslaSource
from pyaoscx.ipsla_responder import IpslaResponder
from pyaoscx.ipsla_track_object import IpslaTrackObject


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


def fake_vrf(name):
    obj = MagicMock()
    obj.name = name
    return obj


def fake_source(name):
    obj = MagicMock()
    obj.name = name
    return obj


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

    patch_calls = []

    def patch(uri, verify=False, data=None, proxies=None):
        patch_calls.append({"uri": uri, "data": json.loads(data)})
        return make_response({}, 204)

    session.s.patch.side_effect = patch
    session._build_uri.side_effect = lambda path: "https://x/" + path

    session.calls = calls
    session.patch_calls = patch_calls
    return session


# --------------------------------------------------------------------------
# IpslaSource
# --------------------------------------------------------------------------
def test_source_path():
    session = make_session()
    source = IpslaSource(session, "src1")
    assert source.path == "system/ipsla_sources/src1"
    assert source.name == "src1"


def test_source_create_sends_name_vrf_and_attrs():
    session = make_session()
    source = IpslaSource(
        session,
        "src1",
        vrf=fake_vrf("default"),
        type="icmp_echo",
        frequency=30,
    )
    source.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/ipsla_sources"
    assert post["data"]["name"] == "src1"
    assert post["data"]["type"] == "icmp_echo"
    assert post["data"]["frequency"] == 30
    assert post["data"]["vrf"] == "/rest/v10.16/system/vrfs/default"


def test_source_update_idempotent():
    body = {"frequency": 60, "tos": 0}
    session = make_session(get_body=body)
    source = IpslaSource(session, "src1")
    source.get(selector="writable")
    assert source.update() is False
    assert not session.patch_calls


def test_source_update_changed_uses_patch():
    body = {"frequency": 60, "tos": 0}
    session = make_session(get_body=body)
    source = IpslaSource(session, "src1")
    source.get(selector="writable")
    source.tos = 10
    assert source.update() is True
    assert len(session.patch_calls) == 1
    assert session.patch_calls[0]["data"] == {"tos": 10}


def test_source_get_all():
    body = {"src1": "/rest/v10.16/system/ipsla_sources/src1"}
    session = make_session(get_body=body)
    result = IpslaSource.get_all(session)
    assert "src1" in result


# --------------------------------------------------------------------------
# IpslaResponder
# --------------------------------------------------------------------------
def test_responder_path():
    session = make_session()
    responder = IpslaResponder(session, "resp1")
    assert responder.path == "system/ipsla_responders/resp1"


def test_responder_create_sends_name_vrf_and_attrs():
    session = make_session()
    responder = IpslaResponder(
        session,
        "resp1",
        vrf=fake_vrf("default"),
        type="udp_echo",
        responder_port_number=5000,
    )
    responder.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/ipsla_responders"
    assert post["data"]["name"] == "resp1"
    assert post["data"]["type"] == "udp_echo"
    assert post["data"]["responder_port_number"] == 5000
    assert post["data"]["vrf"] == "/rest/v10.16/system/vrfs/default"


def test_responder_update_is_noop():
    session = make_session(get_body={})
    responder = IpslaResponder(session, "resp1")
    responder.get()
    assert responder.update() is False
    assert not session.patch_calls


def test_responder_get_all():
    body = {"resp1": "/rest/v10.16/system/ipsla_responders/resp1"}
    session = make_session(get_body=body)
    result = IpslaResponder.get_all(session)
    assert "resp1" in result


# --------------------------------------------------------------------------
# IpslaTrackObject
# --------------------------------------------------------------------------
def test_track_path():
    session = make_session()
    track = IpslaTrackObject(session, "trk1")
    assert track.path == "system/ipsla_track_objects/trk1"


def test_track_create_sends_name_and_tracked_sessions():
    session = make_session()
    track = IpslaTrackObject(
        session,
        "trk1",
        tracked_ipsla_session=[fake_source("src1")],
        track_list_operator="or",
        up_delay=5,
    )
    track.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/ipsla_track_objects"
    assert post["data"]["name"] == "trk1"
    assert post["data"]["track_list_operator"] == "or"
    assert post["data"]["tracked_ipsla_session"] == [
        "/rest/v10.16/system/ipsla_sources/src1"
    ]


def test_track_update_idempotent():
    body = {"up_delay": 0, "down_delay": 0, "track_list_operator": "and"}
    session = make_session(get_body=body)
    track = IpslaTrackObject(session, "trk1")
    track.get(selector="writable")
    assert track.update() is False
    assert not session.patch_calls


def test_track_update_changed_uses_patch():
    body = {"up_delay": 0, "down_delay": 0, "track_list_operator": "and"}
    session = make_session(get_body=body)
    track = IpslaTrackObject(session, "trk1")
    track.get(selector="writable")
    track.up_delay = 10
    assert track.update() is True
    assert len(session.patch_calls) == 1
    assert session.patch_calls[0]["data"] == {"up_delay": 10}


def test_track_get_all():
    body = {"trk1": "/rest/v10.16/system/ipsla_track_objects/trk1"}
    session = make_session(get_body=body)
    result = IpslaTrackObject.get_all(session)
    assert "trk1" in result
