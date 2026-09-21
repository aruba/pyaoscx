# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from datetime import date

from pyaoscx.rest.v10_18.api import v10_18


class v10_19(v10_18):
    """
    Represents a REST API Version 10.19. Newer firmware only — a switch that
        does not implement it answers 404 for every path.
    """

    def __init__(self):
        super().__init__()
        self.release_date = date(2025, 1, 1)
        self.version = "10.19"
