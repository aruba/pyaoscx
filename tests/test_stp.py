# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""Offline unit tests for the Stp pyaoscx resource module."""

import json

from unittest.mock import MagicMock

from pyaoscx.stp import Stp


def make_session():
    session = MagicMock()
    api = session.api
    api.default_depth = 1
    api.default_selector = "writable"
    api.valid_depths = [0, 1, 2, 3, 4]
    api.valid_selectors = ["configuration", "writable", "status"]
    api.configurable_selectors = ["writable"]
    api.valid_depth = lambda depth: True
    session.resource_prefix = "/rest/v10.09/"
    calls = []

    def request(method, path, params=None, data=None):
        calls.append(
            {
                "method": method,
                "path": path,
                "data": json.loads(data) if data else None,
            }
        )
        resp = MagicMock()
        resp.status_code = 201 if method == "POST" else 200
        if method == "DELETE":
            resp.status_code = 204
        resp.text = json.dumps({})
        return resp

    session.request.side_effect = request
    session.calls = calls
    return session


def test_create():
    s = make_session()
    Stp(s, "mstp,0", priority=4, hello_time=2).create()
    post = [c for c in s.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/stp_instances"
    assert post["data"]["instance"] == "mstp,0"


def test_path():
    s = make_session()
    stp = Stp(s, "mstp,0")
    assert stp.path == "system/stp_instances/mstp,0"


def test_delete():
    s = make_session()
    Stp(s, "mstp,0").delete()
    assert [c for c in s.calls if c["method"] == "DELETE"]
