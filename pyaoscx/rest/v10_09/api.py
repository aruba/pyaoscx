# (C) Copyright 2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from datetime import date

from pyaoscx.api import API


class v10_09(API):
    """
    Represents a REST API Version 10.09. It keeps all the information needed
        for the version and methods related to it.
    """

    def __init__(self):
        self.release_date = date(2022, 9, 10)
        self.version = "10.09"
        self.default_selector = "writable"
        self.default_depth = 1
        self.default_facts_depth = 2
        self.default_subsystem_facts_depth = 4
        self.default_data_planes_facts_depth = 6
        self.valid_selectors = [
            "configuration",
            "status",
            "statistics",
            "writable",
        ]
        self.configurable_selectors = ["writable"]
        self.compound_index_separator = ","
        self.valid_depths = [0, 1, 2, 3, 4, 6]

    def _create_ospf_area(self, module_class, session, index_id, **kwargs):
        if "other_config" not in kwargs:
            # If user does not pass value for other_config provide default
            # value, it's needed for correct OSPF Area creation
            kwargs["other_config"] = {
                "stub_default_cost": 1,
                "stub_metric_type": "metric_non_comparable",
            }
        return module_class(session, index_id, **kwargs)
