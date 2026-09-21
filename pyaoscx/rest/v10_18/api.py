# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from datetime import date

from pyaoscx.rest.v10_17.api import v10_17


class v10_18(v10_17):
    """
    Represents a REST API Version 10.18. Container Manager endpoints are
        available here on the 6300 family (FL.10.18).
    """

    def __init__(self):
        super().__init__()
        self.release_date = date(2024, 6, 1)
        self.version = "10.18"
