# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the MacsecPolicy, MkaPolicy, Keychain and KeychainKey
pyaoscx resource modules. The pyaoscx Session is mocked, so no switch is
required.
"""

import json

from unittest.mock import MagicMock

from pyaoscx.macsec_policy import MacsecPolicy
from pyaoscx.mka_policy import MkaPolicy
from pyaoscx.keychain import Keychain
from pyaoscx.keychain_key import KeychainKey


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
# MacsecPolicy
# --------------------------------------------------------------------------
def test_macsec_path():
    session = make_session()
    mp = MacsecPolicy(session, "mp1")
    assert mp.path == "system/macsec_policies/mp1"
    assert mp.name == "mp1"


def test_macsec_create_sends_name_and_nested():
    session = make_session()
    mp = MacsecPolicy(
        session,
        "mp1",
        secure_mode="should-secure",
        replay_window=100,
        cipher_suites={"gcm_aes_256_enabled": True},
    )
    mp.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/macsec_policies"
    assert post["data"]["name"] == "mp1"
    assert post["data"]["secure_mode"] == "should-secure"
    assert post["data"]["replay_window"] == 100
    assert post["data"]["cipher_suites"] == {"gcm_aes_256_enabled": True}


def test_macsec_update_idempotent():
    session = make_session(
        get_body={"secure_mode": "must-secure", "replay_window": 0}
    )
    mp = MacsecPolicy(session, "mp1")
    mp.get(selector="writable")
    assert mp.update() is False
    assert not [c for c in session.calls if c["method"] == "PUT"]


def test_macsec_update_changes():
    session = make_session(
        get_body={"secure_mode": "must-secure", "replay_window": 0}
    )
    mp = MacsecPolicy(session, "mp1")
    mp.get(selector="writable")
    mp.secure_mode = "should-secure"
    assert mp.update() is True
    put = [c for c in session.calls if c["method"] == "PUT"][0]
    assert put["data"]["secure_mode"] == "should-secure"


def test_macsec_delete():
    session = make_session()
    mp = MacsecPolicy(session, "mp1")
    mp.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert deletes and deletes[0]["path"] == "system/macsec_policies/mp1"


def test_macsec_get_all():
    session = make_session(
        get_body={"mp1": "/rest/v10.16/system/macsec_policies/mp1"}
    )
    result = MacsecPolicy.get_all(session)
    assert "mp1" in result
    assert isinstance(result["mp1"], MacsecPolicy)


# --------------------------------------------------------------------------
# MkaPolicy
# --------------------------------------------------------------------------
def test_mka_path():
    session = make_session()
    mka = MkaPolicy(session, "mka1")
    assert mka.path == "system/mka_policies/mka1"


def test_mka_create_sends_name_and_keychain():
    uri = "/rest/v10.16/system/keychains/kc1"
    session = make_session()
    mka = MkaPolicy(
        session, "mka1", mode="psk", transmit_interval=2, keychain=uri
    )
    mka.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/mka_policies"
    assert post["data"]["name"] == "mka1"
    assert post["data"]["mode"] == "psk"
    assert post["data"]["keychain"] == uri


def test_mka_update_idempotent():
    session = make_session(get_body={"mode": "psk", "transmit_interval": 2})
    mka = MkaPolicy(session, "mka1")
    mka.get(selector="writable")
    assert mka.update() is False


# --------------------------------------------------------------------------
# Keychain
# --------------------------------------------------------------------------
def test_keychain_path():
    session = make_session()
    kc = Keychain(session, "kc1")
    assert kc.path == "system/keychains/kc1"
    assert kc.name == "kc1"


def test_keychain_create_sends_name():
    session = make_session()
    kc = Keychain(session, "kc1")
    kc.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/keychains"
    assert post["data"]["name"] == "kc1"


def test_keychain_get_all():
    session = make_session(
        get_body={"kc1": "/rest/v10.16/system/keychains/kc1"}
    )
    result = Keychain.get_all(session)
    assert "kc1" in result
    assert isinstance(result["kc1"], Keychain)


# --------------------------------------------------------------------------
# KeychainKey
# --------------------------------------------------------------------------
def test_key_path():
    session = make_session()
    kc = Keychain(session, "kc1")
    key = KeychainKey(session, 1, kc)
    assert key.path == "system/keychains/kc1/keys/1"
    assert key.base_uri == "system/keychains/kc1/keys"
    assert key.key_id == 1


def test_key_create_sends_key_id_and_attrs():
    session = make_session()
    kc = Keychain(session, "kc1")
    key = KeychainKey(
        session,
        1,
        kc,
        auth_type="sha256",
        auth_key="S3cretKey123",
        send_start=1577836800,
    )
    key.create()
    post = [c for c in session.calls if c["method"] == "POST"][0]
    assert post["path"] == "system/keychains/kc1/keys"
    assert post["data"]["key_id"] == 1
    assert post["data"]["auth_type"] == "sha256"
    assert post["data"]["auth_key"] == "S3cretKey123"


def test_key_get_all():
    session = make_session(
        get_body={"1": "/rest/v10.16/system/keychains/kc1/keys/1"}
    )
    kc = Keychain(session, "kc1")
    result = KeychainKey.get_all(session, kc)
    assert "1" in result
    assert isinstance(result["1"], KeychainKey)


def test_key_delete():
    session = make_session()
    kc = Keychain(session, "kc1")
    key = KeychainKey(session, 1, kc)
    key.delete()
    deletes = [c for c in session.calls if c["method"] == "DELETE"]
    assert deletes and deletes[0]["path"] == "system/keychains/kc1/keys/1"
