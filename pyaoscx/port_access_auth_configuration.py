# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re
from urllib.parse import quote_plus, unquote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class PortAccessAuthConfiguration(PyaoscxModule):
    """
    Provide configuration management for the per interface port access
        authentication settings of AOS-CX devices (aaa authentication
        port-access dot1x authenticator | mac-auth commands of an interface),
        stored as
        system/interfaces/{name}/port_access_auth_configurations/{method}.
    """

    resource_uri_name = "port_access_auth_configurations"

    indices = ["authentication_method"]

    # Attributes returned by the switch that cannot be sent back with PUT.
    read_only_attrs = ["authentication_method", "is_persona"]

    def __init__(
        self,
        session,
        interface,
        authentication_method=None,
        uri=None,
        **kwargs
    ):
        self.session = session
        interface_name = getattr(interface, "name", interface)
        self.interface_name = unquote_plus(interface_name)
        self.authentication_method = authentication_method
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = "system/interfaces/{0}/{1}".format(
            quote_plus(self.interface_name), self.resource_uri_name
        )
        self.path = "{0}/{1}".format(self.base_uri, authentication_method)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve the authentication settings of the
            interface for this method and fill the object with them.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
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
        data.pop("authentication_method", None)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(
                self, data, "config_attrs", self.read_only_attrs
            )

        self._original_attributes = {
            k: v for k, v in data.items() if k in self.config_attrs
        }

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, interface):
        """
        Perform a GET call to retrieve the authentication settings of all the
            methods configured on an interface.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param interface: Interface name or pyaoscx Interface object.
        :return: Dictionary containing the authentication methods as keys and
            the PortAccessAuthConfiguration objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        configs = {}
        collection = cls(session, interface).base_uri
        try:
            response = session.request("GET", collection)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        for method in json.loads(response.text):
            configs[method] = cls(
                session, interface, authentication_method=method
            )

        return configs

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update the authentication
            settings.

        :return: Boolean, True if object was created or modified.
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
        Perform a PUT call to apply changes to existing authentication
            settings.

        :return: True if Object was modified and a PUT request was made.
        """
        config_data = utils.get_attrs(self, self.config_attrs)

        if config_data == self._original_attributes:
            return False

        try:
            response = self.session.request(
                "PUT", self.path, data=json.dumps(config_data)
            )
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
        Perform a POST call to create the authentication settings of the
            interface for this method.

        :return: Boolean, True if the settings were created.
        """
        config_data = utils.get_attrs(self, self.config_attrs)
        config_data["authentication_method"] = self.authentication_method

        try:
            response = self.session.request(
                "POST", self.base_uri, data=json.dumps(config_data)
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
        Perform DELETE call to remove the authentication settings of the
            interface for this method.
        """
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    def __str__(self):
        return "PortAccessAuthConfiguration interface:{0}, method:{1}".format(
            self.interface_name, self.authentication_method
        )

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a PortAccessAuthConfiguration object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param uri: a String with a URI.
        :return: tuple containing both the authentication method and the
            object.
        """
        match = re.match(
            r"(.*)interfaces/(?P<interface>[^/]+)/"
            r"port_access_auth_configurations/(?P<method>[^/]+)$",
            uri,
        )
        method = match.group("method")
        config = cls(
            session, match.group("interface"), authentication_method=method
        )
        return method, config

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific URI of the settings.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix, self.path
            )
        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.

        :return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified
