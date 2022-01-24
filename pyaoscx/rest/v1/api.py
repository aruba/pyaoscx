# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import re

from datetime import date

from pyaoscx.api import API


class v1(API):
    """
    Represents a REST API Version 1. It keeps all the information needed for
        the version and methods related to it.
    """

    def __init__(self):
        self.release_date = date(2017, 1, 1)
        self.version = "1"
        self.default_selector = "configuration"
        self.default_depth = 0
        self.default_facts_depth = 1
        self.default_subsystem_facts_depth = 4
        self.valid_selectors = ["configuration", "status", "statistics"]
        self.configurable_selectors = ["configuration"]
        self.compound_index_separator = "/"
        self.valid_depths = [0, 1, 2, 3]

    def get_index(self, obj):
        """
        Method used to obtain the correct format of the objects information
            which depends on the Current API version.
        :param obj: PyaoscxModule object.
        :return: Resource URI.
        """
        # use object indices
        return obj.get_uri()

    def get_keys(self, response_data, module_name):
        """
        Given a string obtain the keys in it and return them.
        :param response_data: a string of the form:
            "/rest/v1/system/<module>/<key_1>/<key_2>".
        :return name_arr: List of keys.
        """
        # Create regex string
        regex_str = r"(.*)/" + re.escape(module_name) + r"/(?P<ids>.+)"
        # Pattern expected
        ids_pattern = re.compile(regex_str)
        # Match pattern
        indices = ids_pattern.match(response_data).group("ids")
        # Get all indices
        indices = indices.split("/")

        return indices

    def get_uri_from_data(self, data):
        """
        Given a response data, create a list of URI items. In this Version the
            data is a list, string or dict.
        :param data: String, List or Dictionary containing URI items.
        :return uri_list: Return the list of URIs.
        """
        if isinstance(data, list):
            return data
        elif isinstance(data, str):
            return [data]
        elif isinstance(data, dict):
            uri_list = []
            for k, v in data.items():
                item = self.get_uri_from_data(v)
                # if value is a list, then concatenate.
                if isinstance(item, list):
                    uri_list += item
                elif isinstance(item, str):
                    uri_list.append(item)

            return uri_list

    def _create_ospf_area(self, module_class, session, index_id, **kwargs):
        return module_class(session, index_id, **kwargs)
