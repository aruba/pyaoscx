# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the SFlow and SFlowCollector pyaoscx resource
modules. The pyaoscx Session is mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.sflow import SFlow
from pyaoscx.sflow_collector import SFlowCollector


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


def fake_vrf(name):
    vrf = MagicMock()
    vrf.name = name
    return vrf


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
    api.compound_index_separator = ","
    session.resource_prefix = "/rest/v10.09/"

    def get_module(sess, module, index=None, **kwargs):
        if module == "Vrf":
            return fake_vrf(index)
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
# SFlow
# --------------------------------------------------------------------------
def test_sflow_path():
    session = make_session()
    sflow = SFlow(session, "global")
    assert sflow.path == "system/sflows/global"
    assert sflow.name == "global"


def test_sflow_from_uri():
    session = make_session()
    name, sflow = SFlow.from_uri(session, "/rest/v10.09/system/sflows/global")
    assert name == "global"
    assert sflow.name == "global"
    assert sflow.path == "system/sflows/global"


def test_sflow_create_sends_name_and_attrs():
    session = make_session()
    sflow = SFlow(
        session,
        "ansible-test",
        enabled=False,
        mode="both",
        polling=20,
        sampling=2048,
    )
    sflow.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["path"] == "system/sflows"
    assert post["data"]["name"] == "ansible-test"
    assert post["data"]["mode"] == "both"
    assert post["data"]["polling"] == 20


def test_sflow_update_idempotent():
    body = {
        "enabled": False,
        "mode": "both",
        "polling": 20,
        "sampling": 2048,
    }
    session = make_session(get_body=body)
    sflow = SFlow(session, "ansible-test")
    sflow.get(selector="writable")
    # No change applied, an update must be a no-op (no PUT request made).
    assert sflow.update() is False
    assert not any(c["method"] == "PUT" for c in session.calls)


def test_sflow_update_sends_put_on_change():
    body = {
        "enabled": False,
        "mode": "both",
        "polling": 20,
        "sampling": 2048,
    }
    session = make_session(get_body=body)
    sflow = SFlow(session, "ansible-test")
    sflow.get(selector="writable")
    sflow.polling = 25
    assert sflow.update() is True
    put = next(c for c in session.calls if c["method"] == "PUT")
    assert put["data"]["polling"] == 25


def test_sflow_get_all():
    body = {"global": "/rest/v10.09/system/sflows/global"}
    session = make_session(get_body=body)
    result = SFlow.get_all(session)
    assert list(result.keys()) == ["global"]
    assert result["global"].name == "global"


def test_sflow_delete():
    session = make_session()
    sflow = SFlow(session, "ansible-test")
    sflow.delete()
    delete = next(c for c in session.calls if c["method"] == "DELETE")
    assert delete["path"] == "system/sflows/ansible-test"


# --------------------------------------------------------------------------
# SFlowCollector
# --------------------------------------------------------------------------
def test_collector_path():
    session = make_session()
    parent = SFlow(session, "global")
    vrf = fake_vrf("default")
    collector = SFlowCollector(session, vrf, "10.0.0.50", 6343, parent)
    assert collector.base_uri == "system/sflows/global/collectors"
    assert collector.path == (
        "system/sflows/global/collectors/default,10.0.0.50,6343"
    )


def test_collector_create_sends_uri_ref():
    session = make_session()
    parent = SFlow(session, "global")
    vrf = fake_vrf("default")
    collector = SFlowCollector(session, vrf, "10.0.0.50", 6343, parent)
    collector.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["path"] == "system/sflows/global/collectors"
    assert post["data"]["vrf"] == "/rest/v10.09/system/vrfs/default"
    assert post["data"]["ip_address"] == "10.0.0.50"
    assert post["data"]["udp_port"] == 6343


def test_collector_update_noop():
    session = make_session()
    parent = SFlow(session, "global")
    vrf = fake_vrf("default")
    collector = SFlowCollector(session, vrf, "10.0.0.50", 6343, parent)
    assert collector.update() is False


def test_collector_from_uri():
    session = make_session()
    parent = SFlow(session, "global")
    uri = (
        "/rest/v10.09/system/sflows/global/collectors/"
        "default,10.0.0.50,6343"
    )
    key, collector = SFlowCollector.from_uri(session, uri, parent)
    assert key == "default,10.0.0.50,6343"
    assert collector.vrf.name == "default"
    assert collector.ip_address == "10.0.0.50"
    assert collector.udp_port == 6343


def test_collector_get_all():
    body = {
        "default,10.0.0.50,6343": (
            "/rest/v10.09/system/sflows/global/collectors/"
            "default,10.0.0.50,6343"
        )
    }
    session = make_session(get_body=body)
    parent = SFlow(session, "global")
    result = SFlowCollector.get_all(session, parent)
    assert list(result.keys()) == ["default,10.0.0.50,6343"]


def test_collector_delete():
    session = make_session()
    parent = SFlow(session, "global")
    vrf = fake_vrf("default")
    collector = SFlowCollector(session, vrf, "10.0.0.50", 6343, parent)
    collector.delete()
    delete = next(c for c in session.calls if c["method"] == "DELETE")
    assert delete["path"] == (
        "system/sflows/global/collectors/default,10.0.0.50,6343"
    )
