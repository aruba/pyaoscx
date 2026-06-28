# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the IpfixFlowRecord, IpfixFlowExporter and
IpfixFlowMonitor pyaoscx resource modules. The pyaoscx Session is mocked, so
no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.ipfix_flow_record import IpfixFlowRecord
from pyaoscx.ipfix_flow_exporter import IpfixFlowExporter
from pyaoscx.ipfix_flow_monitor import IpfixFlowMonitor


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


def fake_ref(name, kind):
    obj = MagicMock()
    obj.name = name
    uri = "/rest/v10.13/system/{0}/{1}".format(kind, name)
    obj.get_info_format.return_value = {name: uri}
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
    api.configurable_selectors = ["configuration", "writable"]
    api.valid_depth = lambda depth: True
    session.resource_prefix = "/rest/v10.13/"

    def get_module(sess, module, index=None, **kwargs):
        if module == "IpfixFlowExporter":
            return fake_ref(index, "ipfix_flow_exporters")
        if module == "IpfixFlowRecord":
            return fake_ref(index, "ipfix_flow_records")
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
# IpfixFlowRecord
# --------------------------------------------------------------------------
def test_record_path():
    session = make_session()
    record = IpfixFlowRecord(session, "r1")
    assert record.path == "system/ipfix_flow_records/r1"
    assert record.name == "r1"


def test_record_create_sends_name_and_dicts():
    session = make_session()
    record = IpfixFlowRecord(
        session,
        "r1",
        description="d",
        match={"ipv4_source_address": True},
        collect={"counter_bytes": True},
    )
    record.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["path"] == "system/ipfix_flow_records"
    assert post["data"]["name"] == "r1"
    assert post["data"]["match"] == {"ipv4_source_address": True}
    assert post["data"]["collect"] == {"counter_bytes": True}


def test_record_update_idempotent():
    body = {"description": "d", "match": {"ipv4_version": True}, "collect": {}}
    session = make_session(get_body=body)
    record = IpfixFlowRecord(session, "r1")
    record.get(selector="writable")
    assert record.update() is False
    assert not any(c["method"] == "PUT" for c in session.calls)


def test_record_get_all():
    body = {"app-vis": "/rest/v10.13/system/ipfix_flow_records/app-vis"}
    session = make_session(get_body=body)
    result = IpfixFlowRecord.get_all(session)
    assert list(result.keys()) == ["app-vis"]


# --------------------------------------------------------------------------
# IpfixFlowExporter
# --------------------------------------------------------------------------
def test_exporter_path():
    session = make_session()
    exporter = IpfixFlowExporter(session, "e1")
    assert exporter.path == "system/ipfix_flow_exporters/e1"


def test_exporter_create_sends_name_and_attrs():
    session = make_session()
    exporter = IpfixFlowExporter(
        session,
        "e1",
        description="d",
        destination_type="hostname-or-ip-addr",
        destination_hostname_or_ip_addr={
            "10.0.0.50": "/rest/v10.13/system/vrfs/default"
        },
        template_data_timeout=60,
        transport={"port": 2055, "protocol": "udp"},
    )
    exporter.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["path"] == "system/ipfix_flow_exporters"
    assert post["data"]["name"] == "e1"
    assert post["data"]["destination_type"] == "hostname-or-ip-addr"
    assert post["data"]["transport"] == {"port": 2055, "protocol": "udp"}


def test_exporter_delete():
    session = make_session()
    exporter = IpfixFlowExporter(session, "e1")
    exporter.delete()
    delete = next(c for c in session.calls if c["method"] == "DELETE")
    assert delete["path"] == "system/ipfix_flow_exporters/e1"


# --------------------------------------------------------------------------
# IpfixFlowMonitor
# --------------------------------------------------------------------------
def test_monitor_get_converts_references():
    body = {
        "cache_timeout_active": 60,
        "cache_timeout_inactive": 40,
        "description": "d",
        "exporter": {"e1": "/rest/v10.13/system/ipfix_flow_exporters/e1"},
        "record": {"r1": "/rest/v10.13/system/ipfix_flow_records/r1"},
    }
    session = make_session(get_body=body)
    monitor = IpfixFlowMonitor(session, "m1")
    monitor.get(selector="writable")
    assert [e.name for e in monitor.exporter] == ["e1"]
    assert monitor.record.name == "r1"


def test_monitor_create_sends_refs():
    session = make_session()
    exporter = fake_ref("e1", "ipfix_flow_exporters")
    record = fake_ref("r1", "ipfix_flow_records")
    monitor = IpfixFlowMonitor(
        session,
        "m1",
        cache_timeout_active=60,
        exporter=[exporter],
        record=record,
    )
    monitor.create()
    post = next(c for c in session.calls if c["method"] == "POST")
    assert post["data"]["name"] == "m1"
    assert post["data"]["exporter"] == {
        "e1": "/rest/v10.13/system/ipfix_flow_exporters/e1"
    }
    assert post["data"]["record"] == {
        "r1": "/rest/v10.13/system/ipfix_flow_records/r1"
    }


def test_monitor_update_idempotent():
    body = {
        "cache_timeout_active": 60,
        "description": "d",
        "exporter": {"e1": "/rest/v10.13/system/ipfix_flow_exporters/e1"},
        "record": {"r1": "/rest/v10.13/system/ipfix_flow_records/r1"},
    }
    session = make_session(get_body=body)
    monitor = IpfixFlowMonitor(session, "m1")
    monitor.get(selector="writable")
    assert monitor.update() is False
    assert not any(c["method"] == "PUT" for c in session.calls)


def test_monitor_get_all():
    body = {"app-vis": "/rest/v10.13/system/ipfix_flow_monitors/app-vis"}
    session = make_session(get_body=body)
    result = IpfixFlowMonitor.get_all(session)
    assert list(result.keys()) == ["app-vis"]
