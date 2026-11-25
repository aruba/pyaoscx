# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.port_access_policy_common import increment_cfg_version
from pyaoscx.pyaoscx_module import PyaoscxModule


class Class(PyaoscxModule):
    """
    Provide configuration management for traffic classes on AOS-CX devices
        (class ip, class ipv6, class mac, class gbp-ip, ... commands), stored
        as system/classes/{name},{type}. The entries of a class are managed
        with pyaoscx.class_entry.ClassEntry.
    """

    base_uri = "system/classes"
    resource_uri_name = "classes"

    indices = ["name", "type"]

    # Attributes returned by the switch that cannot be sent back with PUT.
    # cfg_entries is excluded so that updating the class never overwrites the
    # entries managed through ClassEntry.
    read_only_attrs = ["name", "type", "origin", "cfg_entries"]

    def __init__(self, session, name, type, uri=None, **kwargs):
        self.session = session
        self.name = name
        self.type = type
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.path = "{0}/{1},{2}".format(self.base_uri, self.name, self.type)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a traffic class and fill the
            object with the incoming attributes.

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

        for index in ("name", "type"):
            data.pop(index, None)

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
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all traffic classes, and create a
            dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing "name,type" indices as keys and the
            Class objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        classes = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            indices, traffic_class = cls.from_uri(session, uri)
            classes[indices] = traffic_class

        return classes

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing traffic class.

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
        Perform a PUT call to apply changes to an existing traffic class.

        :return: True if Object was modified and a PUT request was made.
        """
        class_data = utils.get_attrs(self, self.config_attrs)

        if class_data == self._original_attributes:
            return False

        put_data = json.dumps(class_data)

        try:
            response = self.session.request("PUT", self.path, data=put_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = class_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new traffic class. Only returns if no
            exception is raised.

        :return: Boolean, True if the class was created.
        """
        class_data = utils.get_attrs(self, self.config_attrs)
        class_data["name"] = self.name
        class_data["type"] = self.type

        post_data = json.dumps(class_data)

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
        Perform DELETE call to delete a traffic class and its entries.
        """
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.connected
    def update_cfg_version(self):
        """
        Increment the cfg_version of the class so that the switch applies its
            entries. Call it after the entries were created, modified or
            deleted.

        :return: The new cfg_version.
        """
        self.cfg_version = increment_cfg_version(self.session, self.path)
        return self.cfg_version

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Class object given a response_data.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param response_data: The response must be a dictionary of the form:
            {"name,type": "/rest/v10.xx/system/classes/name,type"}
        :return: Class object.
        """
        class_arr = session.api.get_keys(response_data, cls.resource_uri_name)
        return cls(session, class_arr[0], class_arr[1])

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Class object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param uri: a String with a URI.
        :return: tuple containing both the "name,type" index and the Class
            object.
        """
        index_pattern = re.compile(
            r"(.*)classes/(?P<name>.+),(?P<type>[^,/]+)$"
        )
        match = index_pattern.match(uri)
        name = match.group("name")
        class_type = match.group("type")

        traffic_class = cls(session, name, class_type)
        return "{0},{1}".format(name, class_type), traffic_class

    def __str__(self):
        return "Class name:{0}, type:{1}".format(self.name, self.type)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific traffic class URI.

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
