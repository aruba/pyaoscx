# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.port_access_policy_common import (
    PortAccessActionSet,
    PortAccessPolicyContainer,
    PortAccessPolicyEntry,
)


class PortAccessPolicyActionSet(PortAccessActionSet):
    """
    Action set of a Port Access Policy entry (drop, reflect, dscp, cir, cbs,
        pcp, ecn, ip_precedence, local_priority, exceed_drop, redirect).
    """

    action_key = "policy_action_set"


class PortAccessPolicyEntryItem(PortAccessPolicyEntry):
    """
    Entry of a Port Access Policy.
    """

    action_set_class = PortAccessPolicyActionSet


class PortAccessPolicy(PortAccessPolicyContainer):
    """
    Provide configuration management for Port Access Policies on AOS-CX
        devices.
    """

    base_uri = "system/port_access_policies"
    resource_uri_name = "port_access_policies"
    entry_class = PortAccessPolicyEntryItem
