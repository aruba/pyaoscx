# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class AaaServerGroupPrio(PyaoscxModule):
    """
    Provide configuration management for AAA server group priorities on AOS-CX
        devices. They live under system/aaa_server_group_prios and are indexed
        by session_type. Each entry holds ordered server-group maps for
        accounting, authentication, authorization and radius authorize-only.
    """

    base_uri = "system/aaa_server_group_prios"
    resource_uri_name = "aaa_server_group_prios"

    indices = ["session_type"]

    def __init__(self, session, session_type, uri=None, **kwargs):
        self.session = session
        self.session_type = session_type
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.path = "{0}/{1}".format(self.base_uri, self.session_type)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a server group priority entry
            and fill the object with the incoming attributes.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if selector not in self.session.api.valid_selectors:
            selectors = " ".join(self.session.api.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {0}".format(selectors)
            )

        payload = {"depth": depth, "selector": selector}

        try:
            response = self.session.request("GET", self.path, params=payload)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        for index in self.indices:
            data.pop(index, None)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", self.indices)

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all server group priority entries.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        entries = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            index, entry = cls.from_uri(session, uri)
            entries[index] = entry

        return entries

    @PyaoscxModule.connected
    def apply(self):
        """
        Apply the configured values with a PUT. The entry already exists on
            the switch, so this only ever performs an update.
        """
        modified = self.update()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing entry.
        """
        entry_data = utils.get_attrs(self, self.config_attrs)

        if entry_data == self._original_attributes:
            return False

        try:
            response = self.session.request(
                "PUT", self.path, data=json.dumps(entry_data)
            )
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = entry_data
        return True

    def create(self):
        """
        The entry already exists; configuring it is an update.
        """
        return self.update()

    def delete(self):
        """
        Not supported; entries are permanent.
        """
        pass

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an AaaServerGroupPrio object given a URI.
        """
        index_pattern = re.compile(
            r"(.*)aaa_server_group_prios/(?P<index>.+)"
        )
        index = index_pattern.match(uri).group("index")
        entry = cls(session, index)
        return index, entry

    def __str__(self):
        return "AAA Server Group Prio {0}".format(self.session_type)

    @PyaoscxModule.deprecated
    def get_uri(self):
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix, self.path
            )
        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        return self.session.api.get_index(self)

    @property
    def modified(self):
        return self.__modified
