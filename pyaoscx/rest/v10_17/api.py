# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from datetime import date

from pyaoscx.rest.v10_09.api import v10_09


class v10_17(v10_09):
    """
    Represents a REST API Version 10.17. First version to expose the
        Container Manager endpoints (system/containers and
        system/container_isolated_networks) on 8325 (GL.10.19).

    Behaviour is identical to 10.09 apart from the version string, so this
    subclasses it rather than repeating the attribute block.
    """

    def __init__(self):
        super().__init__()
        self.release_date = date(2024, 1, 1)
        self.version = "10.17"
