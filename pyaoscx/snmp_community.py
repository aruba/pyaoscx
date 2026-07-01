# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class SnmpCommunity(PyaoscxModule):
    """
    Provide configuration management for SNMP community attributes on AOS-CX
        devices (system/snmp_community_attributes), indexed by name.
    """

    base_uri = "system/snmp_community_attributes"
    resource_uri_name = "snmp_community_attributes"

    indices = ["name"]

    def __init__(self, session, name, uri=None, **kwargs):
        self.session = session
        self.name = name
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.path = "{0}/{1}".format(self.base_uri, self.name)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        logging.info("Retrieving %s from switch", self)
        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector
        if not self.session.api.valid_depth(depth):
            raise Exception(
                "ERROR: Depth should be {0}".format(
                    self.session.api.valid_depths
                )
            )
        if selector not in self.session.api.valid_selectors:
            raise Exception(
                "ERROR: Selector should be one of {0}".format(
                    " ".join(self.session.api.valid_selectors)
                )
            )
        payload = {"depth": depth, "selector": selector}
        try:
            response = self.session.request("GET", self.path, params=payload)
        except Exception as e:
            raise ResponseError("GET", e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        data.pop("name", None)
        utils.create_attrs(self, data)
        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", ["name"])
        self._original_attributes = data
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        logging.info("Retrieving all %s data from switch", cls.__name__)
        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        communities = {}
        for uri in session.api.get_uri_from_data(data):
            index, comm = cls.from_uri(session, uri)
            communities[index] = comm
        return communities

    @PyaoscxModule.connected
    def apply(self):
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        comm_data = utils.get_attrs(self, self.config_attrs)
        if comm_data == self._original_attributes:
            return False
        try:
            response = self.session.request(
                "PUT", self.path, data=json.dumps(comm_data)
            )
        except Exception as e:
            raise ResponseError("PUT", e)
        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)
        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = comm_data
        return True

    @PyaoscxModule.connected
    def create(self):
        comm_data = utils.get_attrs(self, self.config_attrs)
        comm_data["name"] = self.name
        try:
            response = self.session.request(
                "POST", self.base_uri, data=json.dumps(comm_data)
            )
        except Exception as e:
            raise ResponseError("POST", e)
        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)
        logging.info("SUCCESS: Adding %s", self)
        self.get()
        return True

    @PyaoscxModule.connected
    def delete(self):
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)
        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri):
        index_pattern = re.compile(
            r"(.*)snmp_community_attributes/(?P<index>.+)"
        )
        index = index_pattern.match(uri).group("index")
        return index, cls(session, index)

    def __str__(self):
        return "SnmpCommunity name:{0}".format(self.name)

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
