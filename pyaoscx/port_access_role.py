# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class PortAccessRole(PyaoscxModule):
    """
    Provide configuration management for Port Access Roles on AOS-CX devices.
    """

    base_uri = "system/port_access_roles"
    resource_uri_name = "port_access_roles"

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
        """
        Perform a GET call to retrieve data for a Port Access Role and fill
            the object with the incoming attributes.

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

        if "name" in data:
            data.pop("name")

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", ["name"])

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all Port Access Roles, and create a
            dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing the names as keys and the
            PortAccessRole objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        roles = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            indices, role = cls.from_uri(session, uri)
            roles[indices] = role

        return roles

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Port Access
            Role.

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
        Perform a PUT call to apply changes to an existing Port Access Role.

        :return: True if Object was modified and a PUT request was made.
        """
        role_data = utils.get_attrs(self, self.config_attrs)

        if role_data == self._original_attributes:
            return False

        post_data = json.dumps(role_data)

        try:
            response = self.session.request("PUT", self.path, data=post_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = role_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Port Access Role. Only returns if
            no exception is raised.

        :return: Boolean, True if entry was created.
        """
        role_data = utils.get_attrs(self, self.config_attrs)
        role_data["name"] = self.name

        post_data = json.dumps(role_data)

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
        Perform DELETE call to delete a Port Access Role.
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
    def from_response(cls, session, response_data):
        """
        Create a PortAccessRole object given a response_data.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param response_data: The response must be a dictionary of the form:
            {name: "/rest/v10.xx/system/port_access_roles/name"}
        :return: PortAccessRole object.
        """
        role_arr = session.api.get_keys(response_data, cls.resource_uri_name)
        name = role_arr[0]
        return cls(session, name)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a PortAccessRole object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param uri: a String with a URI.
        :return: tuple containing both the index and the PortAccessRole object.
        """
        index_pattern = re.compile(r"(.*)port_access_roles/(?P<index>.+)")
        name = index_pattern.match(uri).group("index")

        role = cls(session, name)
        return name, role

    def __str__(self):
        return "PortAccessRole name:{0}".format(self.name)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific Port Access Role URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
                self.name,
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
