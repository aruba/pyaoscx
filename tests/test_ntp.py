# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the NTP family pyaoscx resource modules (NtpKey and
NtpAssociation). The pyaoscx Session is mocked, so no switch is required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.ntp_key import NtpKey
from pyaoscx.ntp_association import NtpAssociation


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
    session.resource_prefix = "/rest/v10.09/"
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


def make_vrf(name="default"):
    vrf = MagicMock()
    vrf.name = name
    vrf.get_uri.return_value = (
        "/rest/v10.09/system/vrfs/{0}".format(name)
    )
    return vrf


# --------------------------------------------------------------------------
# NtpKey
# --------------------------------------------------------------------------
def test_key_path():
    session = make_session()
    key = NtpKey(session, 1)
    assert key.path == "system/ntp_keys/1"
    assert key.base_uri == "system/ntp_keys"
    assert key.key_id == 1


def test_key_create_sends_key_id():
    session = make_session()
    key = NtpKey(
        session, 1, key_password="secret", key_type="md5", trust_enable=True
    )
    key.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/ntp_keys"
    assert post["data"]["key_id"] == 1
    assert post["data"]["key_type"] == "md5"
    assert post["data"]["trust_enable"] is True


def test_key_delete():
    session = make_session()
    key = NtpKey(session, 1)
    key.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert deletes[0]["path"] == "system/ntp_keys/1"


def test_key_get_all():
    session = make_session(
        get_body={"1": "/rest/v10.09/system/ntp_keys/1"}
    )
    keys = NtpKey.get_all(session)
    assert "1" in keys
    assert keys["1"].key_id == 1


def test_key_get_pops_index():
    session = make_session(get_body={"key_id": 5, "key_type": "sha1"})
    key = NtpKey(session, 5)
    key.get()
    assert key.materialized is True
    assert key.key_type == "sha1"


# --------------------------------------------------------------------------
# NtpAssociation
# --------------------------------------------------------------------------
def test_assoc_path():
    session = make_session()
    vrf = make_vrf()
    assoc = NtpAssociation(session, vrf, "198.51.100.1")
    assert assoc.base_uri == "system/vrfs/default/ntp_associations"
    assert assoc.path == "system/vrfs/default/ntp_associations/198.51.100.1"
    assert assoc.address == "198.51.100.1"


def test_assoc_create_sends_address_and_vrf():
    session = make_session()
    vrf = make_vrf()
    assoc = NtpAssociation(session, vrf, "198.51.100.1", prefer=True)
    assoc.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/vrfs/default/ntp_associations"
    assert post["data"]["address"] == "198.51.100.1"
    assert post["data"]["vrf"] == "/rest/v10.09/system/vrfs/default"
    assert post["data"]["prefer"] is True


def test_assoc_delete():
    session = make_session()
    vrf = make_vrf()
    assoc = NtpAssociation(session, vrf, "198.51.100.1")
    assoc.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert (
        deletes[0]["path"]
        == "system/vrfs/default/ntp_associations/198.51.100.1"
    )


def test_assoc_get_all():
    session = make_session(
        get_body={
            "198.51.100.1": (
                "/rest/v10.09/system/vrfs/default/ntp_associations/"
                "198.51.100.1"
            )
        }
    )
    vrf = make_vrf()
    assocs = NtpAssociation.get_all(session, vrf)
    assert "198.51.100.1" in assocs
    assert assocs["198.51.100.1"].address == "198.51.100.1"


def test_assoc_get_pops_index():
    session = make_session(get_body={"address": "198.51.100.1", "vrf": "x"})
    vrf = make_vrf()
    assoc = NtpAssociation(session, vrf, "198.51.100.1")
    assoc.get()
    assert assoc.materialized is True
    assert not hasattr(assoc, "address_extra")
