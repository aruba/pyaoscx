# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.port_access_policy_common import PortAccessPolicyEntry


class ClassEntry(PortAccessPolicyEntry):
    """
    Provide configuration management for the entries of a traffic class on
        AOS-CX devices (system/classes/{name},{type}/cfg_entries/{sequence}).

    The parent is a pyaoscx.traffic_class.Class object. Except for comment,
        the attributes of an entry (type, match fields, count) cannot be
        modified with PUT: the entry must be deleted and created again.
    """
