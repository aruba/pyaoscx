# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class PortAccessAuthConfiguration(PyaoscxModule):
    """
    Provide configuration management for per-method port access authentication
        configurations on an interface. They live under
        system/interfaces/<interface>/port_access_auth_configurations and are
        indexed by authentication_method (e.g. dot1x, mac-auth).
    """

    collection_uri = "system/interfaces"
    object_uri = (
        collection_uri + "/{interface}/port_access_auth_configurations"
    )

    indices = ["authentication_method"]

    def __init__(
        self, session, parent_interface, authentication_method, uri=None,
        **kwargs
    ):
        self.session = session
        if isinstance(parent_interface, str):
            parent_interface = self.session.api.get_module(
                self.session, "Interface", parent_interface
            )
        self._interface = parent_interface
        self.authentication_method = authentication_method
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        pct = parent_interface.percents_name or parent_interface.name.replace(
            "/", "%2F"
        )
        self.base_uri = self.object_uri.format(interface=pct)
        self.path = "{0}/{1}".format(
            self.base_uri, self.authentication_method
        )

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an authentication
            configuration and fill the object with the incoming attributes.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {0}".format(depths))

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
    def get_all(cls, session, parent_interface):
        """
        Perform a GET call to retrieve all configurations for an interface.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        if isinstance(parent_interface, str):
            parent_interface = session.api.get_module(
                session, "Interface", parent_interface
            )
        base_uri = cls.object_uri.format(
            interface=parent_interface.percents_name
            or parent_interface.name.replace("/", "%2F")
        )

        try:
            response = session.request("GET", base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        configs = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            index, config = cls.from_uri(session, parent_interface, uri)
            configs[index] = config

        return configs

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing entry.
        """
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing configuration.
        """
        config_data = utils.get_attrs(self, self.config_attrs)

        if config_data == self._original_attributes:
            return False

        post_data = json.dumps(config_data)

        try:
            response = self.session.request("PUT", self.path, data=post_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = config_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Create the entry with a POST, or update it if it already exists.
        """
        pending = utils.get_attrs(self, self.config_attrs)
        try:
            self.get()
            exists = True
        except GenericOperationError:
            exists = False
        if exists:
            for key, value in pending.items():
                setattr(self, key, value)
                if key not in self.config_attrs:
                    self.config_attrs.append(key)
            return self.update()
        config_data = dict(pending)
        config_data["authentication_method"] = self.authentication_method
        post_data = json.dumps(config_data)
        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
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
        """
        Delete the configuration entry.
        """
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)
        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, parent_interface, uri):
        """
        Create a PortAccessAuthConfiguration object given a URI.
        """
        index_pattern = re.compile(
            r"(.*)port_access_auth_configurations/(?P<index>.+)"
        )
        index = index_pattern.match(uri).group("index")
        config = cls(session, parent_interface, index)
        return index, config

    def __str__(self):
        return "Port Access Auth Configuration {0}".format(
            self.authentication_method
        )

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific entry URI.
        """
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
