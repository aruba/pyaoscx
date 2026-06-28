# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class ClassEntry(PyaoscxModule):
    """
    Provide configuration management for traffic Class entries on AOS-CX
        devices.
    """

    collection_uri = "system/classes/{index}/cfg_entries"
    object_uri = collection_uri + "/{sequence_number}"
    resource_name = "sequence_number"
    indices = ["sequence_number"]

    def __init__(
        self, session, sequence_number, parent_class, uri=None, **kwargs
    ):
        self.__parent_class = parent_class
        self.__sequence_number = sequence_number
        self.session = session
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.path = self.object_uri.format(
            index=parent_class.index, sequence_number=sequence_number
        )
        self.base_uri = self.collection_uri.format(index=parent_class.index)

    @property
    def sequence_number(self):
        return self.__sequence_number

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a traffic Class entry and fill
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

        if "sequence_number" in data:
            data.pop("sequence_number")

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(
                self, data, "config_attrs", ["sequence_number"]
            )

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_class):
        """
        Perform a GET call to retrieve all entries of a traffic Class and
            create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_class: Class object to which the entries belong.
        :return: Dictionary containing the sequence numbers as keys and the
            ClassEntry objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = cls.collection_uri.format(index=parent_class.index)

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        entries = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            sequence_number, entry = cls.from_uri(session, parent_class, uri)
            entries[sequence_number] = entry

        return entries

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing traffic Class
            entry.

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
        Perform a PUT call to apply changes to an existing traffic Class entry.

        :return: True if Object was modified and a PUT request was made.
        """
        entry_data = utils.get_attrs(self, self.config_attrs)

        if entry_data == self._original_attributes:
            return False

        post_data = json.dumps(entry_data)

        try:
            response = self.session.request("PUT", self.path, data=post_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = entry_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new traffic Class entry. Only returns
            if no exception is raised.

        :return: Boolean, True if entry was created.
        """
        entry_data = utils.get_attrs(self, self.config_attrs)
        entry_data["sequence_number"] = self.sequence_number

        post_data = json.dumps(entry_data)

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
        Perform DELETE call to delete a traffic Class entry.
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
    def from_uri(cls, session, parent_class, uri):
        """
        Create a ClassEntry object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param parent_class: Class object to which the entry belongs.
        :param uri: a String with a URI.
        :return: tuple containing both the sequence number and the ClassEntry
            object.
        """
        sequence_number = uri.split("/")[-1]
        entry = cls(session, sequence_number, parent_class)
        return sequence_number, entry

    def __str__(self):
        return "ClassEntry sequence_number:{0}".format(self.sequence_number)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific traffic Class entry URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix,
                self.path,
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
