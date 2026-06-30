# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the RADIUS dynamic authorization proxy SDK classes:
RadiusDynauthProxyServer, RadiusDynauthProxyClientGroup and
RadiusDynauthProxyProfile.
"""

from unittest.mock import MagicMock

from pyaoscx.radius_dynauth_proxy_server import RadiusDynauthProxyServer
from pyaoscx.radius_dynauth_proxy_client_group import (
    RadiusDynauthProxyClientGroup,
)
from pyaoscx.radius_dynauth_proxy_profile import RadiusDynauthProxyProfile


def make_session():
    session = MagicMock()
    session.api.compound_index_separator = ","
    return session


def test_server_index_and_path():
    server = RadiusDynauthProxyServer(
        make_session(), "default", "192.0.2.30", 3799, "udp"
    )
    assert server.base_uri == "system/vrfs/default/radius_dynauth_proxy_servers"
    assert server.path.endswith(
        "radius_dynauth_proxy_servers/192.0.2.30,3799,udp"
    )
    assert RadiusDynauthProxyServer.indices == [
        "address", "port", "port_type"
    ]


def test_server_from_uri():
    session = make_session()
    uri = (
        "/rest/latest/system/vrfs/default/radius_dynauth_proxy_servers/"
        "192.0.2.30,3799,udp"
    )
    index, server = RadiusDynauthProxyServer.from_uri(session, "default", uri)
    assert index == "192.0.2.30,3799,udp"
    assert server.address == "192.0.2.30"
    assert server.port == "3799"
    assert server.port_type == "udp"


def test_client_group_index_and_create_payload():
    group = RadiusDynauthProxyClientGroup(MagicMock(), "coa-grp")
    assert group.base_uri == "system/radius_dynauth_proxy_client_groups"
    assert group.path.endswith("radius_dynauth_proxy_client_groups/coa-grp")
    captured = {}
    group._post_data = lambda data: captured.update(data) or True
    assert group.create() is True
    assert captured == {"group_name": "coa-grp"}


def test_profile_index_and_create_payload():
    profile = RadiusDynauthProxyProfile(MagicMock(), "coa-proxy")
    assert profile.base_uri == "system/radius_dynauth_proxy_profiles"
    assert profile.path.endswith("radius_dynauth_proxy_profiles/coa-proxy")
    captured = {}
    profile._post_data = lambda data: captured.update(data) or True
    assert profile.create() is True
    assert captured == {"profile_name": "coa-proxy"}


def test_from_uri_names():
    session = MagicMock()
    _, group = RadiusDynauthProxyClientGroup.from_uri(
        session, "/x/radius_dynauth_proxy_client_groups/g1"
    )
    assert group.group_name == "g1"
    _, profile = RadiusDynauthProxyProfile.from_uri(
        session, "/x/radius_dynauth_proxy_profiles/p1"
    )
    assert profile.profile_name == "p1"
