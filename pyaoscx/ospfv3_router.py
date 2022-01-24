# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.ospf_router import OspfRouter


class Ospfv3Router(OspfRouter):
    """
    Provide configuration management for OSPFv3 Routers on AOS-CX devices.
    """

    version = "v3"

    resource_uri_name = "ospfv3_routers"
