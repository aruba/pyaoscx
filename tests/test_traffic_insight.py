# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the TrafficInsight and TrafficInsightMonitor pyaoscx
resource modules. The pyaoscx Session is mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.traffic_insight import TrafficInsight
from pyaoscx.traffic_insight_monitor import TrafficInsightMonitor


def make_response(body, code=200):
    resp = MagicMock()
    resp.status_code = code
    resp.text = json.dumps(body)
    return resp


def fake_instance(name):
    obj = MagicMock()
    obj.name = name
    uri = "/rest/v10.13/system/traffic_insights/{0}".format(name)
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
    api.compound_index_separator = ","
    session.resource_prefix = "/rest/v10.13/"

    def get_module(sess, module, index=None, **kwargs):
        if module == "TrafficInsight":
            return fake_instance(index)
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
# TrafficInsight
# --------------------------------------------------------------------------
def test_instance_path():
    session = make_session()
    instance = TrafficInsight(session, "ti1")
    assert instance.path == "system/traffic_insights/ti1"
    assert instance.name == "ti1"


def test_instance_create_sends_name_and_attrs():
    session = make_session()
    instance = TrafficInsight(session, "ti1", enable=True, source=["ipfix"])
    instance.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/traffic_insights"
    assert post["data"]["name"] == "ti1"
    assert post["data"]["enable"] is True
    assert post["data"]["source"] == ["ipfix"]


def test_instance_update_idempotent():
    body = {"enable": True, "source": ["ipfix"]}
    session = make_session(get_body=body)
    instance = TrafficInsight(session, "ti1")
    instance.get(selector="writable")
    # No change -> PUT must not be sent.
    assert instance.update() is False
    assert not [c for c in session.calls if c["method"] == "PUT"]


def test_instance_update_changed():
    body = {"enable": True, "source": ["ipfix"]}
    session = make_session(get_body=body)
    instance = TrafficInsight(session, "ti1")
    instance.get(selector="writable")
    instance.enable = False
    assert instance.update() is True
    put = [c for c in session.calls if c["method"] == "PUT"][0]
    assert put["data"]["enable"] is False


def test_instance_get_all():
    body = {"ti1": "/rest/v10.13/system/traffic_insights/ti1"}
    session = make_session(get_body=body)
    result = TrafficInsight.get_all(session)
    assert "ti1" in result
    assert isinstance(result["ti1"], TrafficInsight)


def test_instance_delete():
    session = make_session()
    instance = TrafficInsight(session, "ti1")
    instance.config_attrs = ["enable", "source"]
    instance.delete()
    delete = [c for c in session.calls if c["method"] == "DELETE"][0]
    assert delete["path"] == "system/traffic_insights/ti1"


# --------------------------------------------------------------------------
# TrafficInsightMonitor
# --------------------------------------------------------------------------
def test_monitor_path_compound():
    session = make_session()
    instance = fake_instance("ti1")
    monitor = TrafficInsightMonitor(session, instance, "m1", "topN-flows")
    assert monitor.path == (
        "system/traffic_insight_monitors/ti1,m1,topN-flows"
    )


def test_monitor_create_sends_index_and_attrs():
    session = make_session()
    instance = fake_instance("ti1")
    monitor = TrafficInsightMonitor(
        session,
        instance,
        "m1",
        "topN-flows",
        group_by="appid",
        monitor_n_flows=10,
        running_stats_reset_interval=600,
    )
    monitor.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/traffic_insight_monitors"
    assert post["data"]["monitor_name"] == "m1"
    assert post["data"]["monitor_type"] == "topN-flows"
    assert post["data"]["traffic_insight_instance"] == {
        "ti1": "/rest/v10.13/system/traffic_insights/ti1"
    }
    assert post["data"]["group_by"] == "appid"
    assert post["data"]["monitor_n_flows"] == 10


def test_monitor_from_uri():
    session = make_session()
    uri = "/rest/v10.13/system/traffic_insight_monitors/" "ti1,m1,topN-flows"
    index, monitor = TrafficInsightMonitor.from_uri(session, uri)
    assert index == "ti1,m1,topN-flows"
    assert monitor.monitor_name == "m1"
    assert monitor.monitor_type == "topN-flows"
    assert monitor.traffic_insight_instance.name == "ti1"


def test_monitor_update_changed():
    body = {
        "filter_by_single_value": {},
        "group_by": "appid",
        "monitor_n_flows": 10,
        "running_stats_reset_interval": 600,
    }
    session = make_session(get_body=body)
    instance = fake_instance("ti1")
    monitor = TrafficInsightMonitor(session, instance, "m1", "topN-flows")
    monitor.get(selector="writable")
    monitor.monitor_n_flows = 15
    assert monitor.update() is True
    put = [c for c in session.calls if c["method"] == "PUT"][0]
    assert put["data"]["monitor_n_flows"] == 15


def test_monitor_get_all():
    key = "ti1,m1,topN-flows"
    body = {key: ("/rest/v10.13/system/traffic_insight_monitors/" + key)}
    session = make_session(get_body=body)
    result = TrafficInsightMonitor.get_all(session)
    assert key in result
    assert isinstance(result[key], TrafficInsightMonitor)
