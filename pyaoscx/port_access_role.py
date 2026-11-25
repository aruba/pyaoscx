# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.port_access_policy_common import PortAccessPolicyContainer


class PortAccessRole(PortAccessPolicyContainer):
    """
    Provide configuration management for local port access roles on AOS-CX
        devices (port-access role <name> command), stored as
        system/port_access_roles/{name}.
    """

    base_uri = "system/port_access_roles"
    resource_uri_name = "port_access_roles"
