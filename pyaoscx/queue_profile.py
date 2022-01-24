# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.device import Device

from pyaoscx.pyaoscx_module import PyaoscxModule


class QueueProfile(PyaoscxModule):
    """
    Provide configuration management for Queue profiles on AOS-CX devices.
    """

    collection_uri = "system/q_profiles"
    object_uri = collection_uri + "/{name}"
    resource_uri_name = "name"
    indices = ["name"]

    def __init__(self, session, name, **kwargs):
        self.session = session
        self.__name = name

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
        self.path = self.object_uri.format(name=self.name)
        self.base_uri = self.collection_uri

    @property
    def name(self):
        return self.__name

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Queue profile and fill
            the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information
            to return.
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
        Perform a GET call to retrieve all Queue profiles and create a
            dictionary containing each of them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing Queue profile names as keys and a Queue
            profile object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.collection_uri)
        except Exception as exc:
            raise ResponseError("GET", exc)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        profile_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            profile_name, profile = cls.from_uri(session, uri)
            profile_dict[profile_name] = profile

        return profile_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Queue Profile.
            Checks whether the Queue Profile exists in the switch and calls
            self.update() or self.create() accordingly.
        :return modified: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        else:
            return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Queue Profile.
        :return modified: True if the object was modified and a PUT request was
            made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # Manually remove the name
        if "name" in data:
            del data["name"]
        self.__modified = self._put_data(data)
        logging.info("SUCCESS: Updating %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Queue profile in the switch.
        :return modified: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # Manually add the name
        data["name"] = self.name
        self.__modified = self._post_data(data)
        logging.info("SUCCESS: Adding %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a Queue Profile from the switch.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Queue profile object given an URI.
        :param cls: Object's class.
        :param session: Pyaoscx.Session objec used to represent a logical
            connection to the device.
        :param uri: a string with the URI
        :return id, object: tuple with the name and the Profile.
        """
        # Obtain the ID from URI
        name = uri.split("/")[-1]
        return name, cls(session, name)

    @classmethod
    def get_facts(cls, session):
        """
        Retrieve the information of all Queue profiles.
        :param cls: Class reference.
        :param session: Pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing the name as key and the materialized
            object as value.
        """
        logging.info("Retrieving Queue Profiles facts")

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
        return "Queue Profile {0}".format(self.name)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified

    @classmethod
    def set_global_queue_profile(cls, session, profile):
        """
        Sets the global queue profile for the switch.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param profile: Name of a queue profile to set as the global queue
            profile.
        """
        logging.info("Setting global queue profile to: %s", profile)
        device = Device(session)
        if not device.materialized:
            device.get()
        setattr(device, "q_profile_default", profile)
        return device.apply()
