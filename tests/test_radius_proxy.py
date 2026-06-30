# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the RADIUS proxy SDK classes:
RadiusProxyClientGroup and RadiusProxyProfile.
"""

from unittest.mock import MagicMock

from pyaoscx.radius_proxy_client_group import RadiusProxyClientGroup
from pyaoscx.radius_proxy_profile import RadiusProxyProfile


def test_client_group_index_and_create_payload():
    group = RadiusProxyClientGroup(MagicMock(), "nas-grp")
    assert group.base_uri == "system/radius_proxy_client_groups"
    assert group.path.endswith("radius_proxy_client_groups/nas-grp")
    assert RadiusProxyClientGroup.indices == ["group_name"]
    captured = {}
    group._post_data = lambda data: captured.update(data) or True
    assert group.create() is True
    assert captured == {"group_name": "nas-grp"}


def test_profile_index_and_create_payload():
    profile = RadiusProxyProfile(MagicMock(), "radius-proxy")
    assert profile.base_uri == "system/radius_proxy_profiles"
    assert profile.path.endswith("radius_proxy_profiles/radius-proxy")
    captured = {}
    profile._post_data = lambda data: captured.update(data) or True
    assert profile.create() is True
    assert captured == {"profile_name": "radius-proxy"}


def test_from_uri_names():
    session = MagicMock()
    _, group = RadiusProxyClientGroup.from_uri(
        session, "/x/radius_proxy_client_groups/g1"
    )
    assert group.group_name == "g1"
    _, profile = RadiusProxyProfile.from_uri(
        session, "/x/radius_proxy_profiles/p1"
    )
    assert profile.profile_name == "p1"
