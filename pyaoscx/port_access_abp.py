# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.port_access_policy_common import (
    PortAccessActionSet,
    PortAccessPolicyContainer,
    PortAccessPolicyEntry,
)


class PortAccessAbpActionSet(PortAccessActionSet):
    """
    Action set of an Application Based Policy entry (drop, dscp,
        local_priority, mirror).
    """

    action_key = "abp_action_set"


class PortAccessAbpEntry(PortAccessPolicyEntry):
    """
    Entry of an Application Based Policy.
    """

    action_set_class = PortAccessAbpActionSet


class PortAccessAbp(PortAccessPolicyContainer):
    """
    Provide configuration management for Application Based Policies on AOS-CX
        devices.
    """

    base_uri = "system/port_access_abps"
    resource_uri_name = "port_access_abps"
    entry_class = PortAccessAbpEntry
