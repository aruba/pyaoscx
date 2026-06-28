# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class PrefixList(PyaoscxModule):
    """
    Provide configuration management for Prefix Lists on AOS-CX devices.
    """

    collection_uri = "system/prefix_lists"
    object_uri = collection_uri + "/{name}"
    resource_uri_name = "name"
    indices = ["name"]

    def __init__(self, session, name, **kwargs):
        self.session = session
        self.__name = name

        # List used to determine attributes related to the
        # Prefix List configuration
        self.config_attrs = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET request
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)

        # Used to know if the object was changed since the last request
        self.__modified = False

        # Build the URI that identifies the current Prefix List
        self.path = self.object_uri.format(name=name)
        self.base_uri = self.collection_uri

    @property
    def name(self):
        return self.__name

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Prefix List and fill the
            object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Update the original attributes
        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all Prefix Lists and create a dictionary
            containing each of them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing Prefix List names as keys and a Prefix
            List object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.collection_uri)
        except Exception as exc:
            raise ResponseError("GET", exc)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        prefix_list_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            name, prefix_list = cls.from_uri(session, uri)
            prefix_list_dict[name] = prefix_list

        return prefix_list_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Prefix List.
            Checks whether the Prefix List exists in the switch and calls
            self.update() or self.create() accordingly.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Prefix List.

        :return: True if the object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The name is an index and cannot be part of the PUT body
        if "name" in data:
            del data["name"]
        # The address family cannot be changed after creation
        if "address_family" in data:
            del data["address_family"]
        self.__modified = self._put_data(data)
        logging.info("SUCCESS: Updating %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Prefix List in the switch.

        :return: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The name is an index and must be added explicitly
        data["name"] = self.name
        self.__modified = self._post_data(data)
        logging.info("SUCCESS: Adding %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a Prefix List from the switch. All the
            entries that belong to the Prefix List are removed with it.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Prefix List object given an URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return: tuple with the name and the Prefix List.
        """
        # The name is the last element of the URI
        name = uri.split("/")[-1]
        return name, cls(session, name)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Prefix List object given a response_data.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {name: URI}.
        :return: Prefix List object.
        """
        uri = next(iter(response_data.values()))
        _, prefix_list = cls.from_uri(session, uri)
        return prefix_list

    @classmethod
    def get_facts(cls, session):
        """
        Retrieve the information of all Prefix Lists.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing the name as key and the facts as value.
        """
        logging.info("Retrieving Prefix Lists facts")

        depth = session.api.default_facts_depth

        try:
            response = session.request(
                "GET", cls.collection_uri, params={"depth": depth}
            )
        except Exception as exc:
            raise ResponseError("GET", exc)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        return json.loads(response.text)

    def __str__(self):
        return "Prefix List {0}".format(self.name)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
