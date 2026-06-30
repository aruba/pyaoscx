# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""Offline unit tests for pyaoscx.radius_config_attribute."""

from unittest.mock import MagicMock

from pyaoscx.radius_config_attribute import RadiusConfigAttribute


def test_index_and_path():
    entry = RadiusConfigAttribute(MagicMock(), "my-grp")
    assert entry.base_uri == "system/radius_config_attributes"
    assert entry.path.endswith("radius_config_attributes/my-grp")
    assert RadiusConfigAttribute.indices == ["server_group"]


def test_create_posts_server_group_uri():
    entry = RadiusConfigAttribute(
        MagicMock(), "my-grp",
        server_group_uri="/rest/latest/system/aaa_server_groups/my-grp,radius",
    )
    captured = {}
    entry._post_data = lambda data: captured.update(data) or True
    assert entry.create() is True
    assert captured["server_group"].endswith("aaa_server_groups/my-grp,radius")


def test_from_uri_name():
    _, entry = RadiusConfigAttribute.from_uri(
        MagicMock(), "/x/radius_config_attributes/my-grp"
    )
    assert entry.server_group == "my-grp"
