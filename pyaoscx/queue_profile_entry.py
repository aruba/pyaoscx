# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.queue_profile import QueueProfile

from pyaoscx.pyaoscx_module import PyaoscxModule


class QueueProfileEntry(PyaoscxModule):
    """
    Provide configuration management for Queue Profile Entries on AOS-CX
        devices.
    """

    collection_uri = "system/q_profiles/{name}/q_profile_entries"
    object_uri = collection_uri + "/{queue_number}"
    resource_name = "queue_number"
    indices = ["queue_number"]

    def __init__(self, session, queue_number, parent_profile, **kwargs):
        self.__profile = parent_profile
        self.__queue_number = queue_number
        self.session = session
        # List used to determine attributes related to the
        # Queue profile configuration
        self.config_attrs = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET request
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)

        # Used to know if the object was changed since the last
        # request
        self.__modified = False

        # Build the URI that identifies the current Queue profile
        self.path = self.object_uri.format(
            name=self.__profile.name, queue_number=queue_number
        )
        self.base_uri = self.collection_uri.format(name=self.__profile.name)

    @property
    def queue_number(self):
        return self.__queue_number

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Queue Profile Entry and fill
            the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information
            to return.
        :return: Returns True if there is not an exception raised.
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
    def get_all(cls, session, queue_profile_name):
        """
        Perform a GET call to retrieve all Queue Profile Entries  of the same
            profile and create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param queue_profile_name: Name of the profile to which the entries
            belong.
        :return: Dictionary containing Queue Profile Entry names as keys
            and a Queue Profile Entry object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = cls.collection_uri.format(name=queue_profile_name)

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
            entry_number, entry = cls.from_uri(session, uri)
            entry_dict[entry_number] = entry

        return entry_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Queue
            Profile Entry. Checks whether the Queue Profile exists in the
            switch and calls self.update() or self.create() accordingly.
        :return modified: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        else:
            return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Queue Profile Entry.
        :return modified: True if the object was modified and a PUT request was
            made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # Manually remove the queue_number
        if "queue_number" in data:
            del data["queue_number"]
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Queue Profile Entry in the switch.
        :return modified: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # Manually add the queue_number
        data["queue_number"] = self.queue_number
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a Queue Profile Entry from the switch.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Queue profile object given an URI.
        :param cls: Object's class.
        :param session: Pyaoscx.Session objec used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return id, object: tuple with the name and the Profile.
        """
        # Obtain the ID from URI
        # URI format is /system/q_profile/{name}/q_entry/{queue_number}
        parts = uri.split("/")
        profile_name = parts[-3]
        queue_number = parts[-1]
        profile = QueueProfile(session, profile_name)
        entry = cls(session, queue_number, profile)
        return queue_number, entry

    @classmethod
    def get_facts(cls, session, queue_profile_name):
        """
        Retrieve the information of all Queue profiles.
        :param cls: Class reference.
        :param session: Pyaoscx.Session object used to represent a logical
            connection to the device.
        :param queue_profile_name: Name of the profile to which the entries
            belong.
        :return: Dictionary containing the name as key and the facts as value.
        """
        logging.info("Retrieving Queue Profiles facts")

        depth = session.api.default_facts_depth

        uri = cls.collection_uri.format(name=queue_profile_name)

        try:
            response = session.request("GET", uri, params={"depth": depth})
        except Exception as exc:
            raise ResponseError("GET", exc)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        return json.loads(response.text)

    def __str__(self):
        return "Queue Profile Entry {0} of Profile {1}".format(
            self.queue_number, self.__profile.name
        )

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
