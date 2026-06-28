# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pbr_action_list import PbrActionList

from pyaoscx.pyaoscx_module import PyaoscxModule


class PbrActionListEntry(PyaoscxModule):
    """
    Provide configuration management for PBR Action List Entries on AOS-CX
        devices. The switch does not support modifying an existing entry, so
        a change is applied by deleting and recreating the entry.
    """

    collection_uri = "system/pbr_action_lists/{name}/cfg_entries"
    object_uri = collection_uri + "/{sequence_number}"
    resource_name = "sequence_number"
    indices = ["sequence_number"]

    def __init__(self, session, sequence_number, parent_action_list, **kwargs):
        self.__parent_action_list = parent_action_list
        self.__sequence_number = sequence_number
        self.session = session

        # List used to determine attributes related to the
        # PBR Action List Entry configuration
        self.config_attrs = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET request
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)

        # Used to know if the object was changed since the last request
        self.__modified = False

        # Build the URIs that identify the current entry
        self.path = self.object_uri.format(
            name=self.__parent_action_list.name,
            sequence_number=sequence_number,
        )
        self.base_uri = self.collection_uri.format(
            name=self.__parent_action_list.name
        )

    @property
    def sequence_number(self):
        return self.__sequence_number

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a PBR Action List Entry and
            fill the object with the incoming attributes.

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
    def get_all(cls, session, action_list_name):
        """
        Perform a GET call to retrieve all entries of the same PBR Action List
            and create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param action_list_name: Name of the PBR Action List to which the
            entries belong.
        :return: Dictionary containing entry sequence numbers as keys and a PBR
            Action List Entry object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = cls.collection_uri.format(name=action_list_name)

        try:
            response = session.request("GET", uri)
        except Exception as exc:
            raise ResponseError("GET", exc)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        entry_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            sequence_number, entry = cls.from_uri(session, uri)
            entry_dict[sequence_number] = entry

        return entry_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing PBR Action
            List Entry. Checks whether the entry exists in the switch and
            calls self.update() or self.create() accordingly.

        :return modified: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing entry.

        Note: the switch does not allow modifying a PBR Action List Entry in
            place. Callers that need to change an entry must delete it and
            create it again.

        :return: True if the object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The sequence number is an index and cannot be part of the PUT body
        if "sequence_number" in data:
            del data["sequence_number"]
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new entry in the switch.

        :return: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The sequence number is an index and must be added explicitly
        data["sequence_number"] = self.sequence_number
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a PBR Action List Entry from the
            switch.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a PbrActionListEntry object given an URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return: tuple with the sequence number and the entry.
        """
        # URI format is:
        # /system/pbr_action_lists/{name}/cfg_entries/{sequence_number}
        parts = uri.split("/")
        action_list_name = parts[-3]
        sequence_number = parts[-1]
        action_list = PbrActionList(session, action_list_name)
        entry = cls(session, sequence_number, action_list)
        return sequence_number, entry

    @classmethod
    def get_facts(cls, session, action_list_name):
        """
        Retrieve the information of all entries of a PBR Action List.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param action_list_name: Name of the PBR Action List to which the
            entries belong.
        :return: Dictionary containing the sequence number as key and the
            facts as value.
        """
        logging.info("Retrieving PBR Action List Entries facts")

        depth = session.api.default_facts_depth

        uri = cls.collection_uri.format(name=action_list_name)

        try:
            response = session.request("GET", uri, params={"depth": depth})
        except Exception as exc:
            raise ResponseError("GET", exc)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        return json.loads(response.text)

    def __str__(self):
        return "PBR Action List Entry {0} of List {1}".format(
            self.sequence_number, self.__parent_action_list.name
        )

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
