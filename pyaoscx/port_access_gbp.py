# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.port_access_policy_common import (
    PortAccessActionSet,
    PortAccessPolicyContainer,
    PortAccessPolicyEntry,
)


class PortAccessGbpActionSet(PortAccessActionSet):
    """
    Action set of a Group Based Policy entry (drop, reflect).
    """

    action_key = "gbp_action_set"


class PortAccessGbpEntry(PortAccessPolicyEntry):
    """
    Entry of a Group Based Policy.
    """

    action_set_class = PortAccessGbpActionSet


class PortAccessGbp(PortAccessPolicyContainer):
    """
    Provide configuration management for Group Based Policies on AOS-CX
        devices.
    """

    base_uri = "system/port_access_gbps"
    resource_uri_name = "port_access_gbps"
    entry_class = PortAccessGbpEntry
