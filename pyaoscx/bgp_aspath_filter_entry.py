# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.bgp_aspath_filter import BgpAspathFilter

from pyaoscx.pyaoscx_module import PyaoscxModule


class BgpAspathFilterEntry(PyaoscxModule):
    """
    Provide configuration management for BGP AS-Path Filter Entries on AOS-CX
        devices.
    """

    collection_uri = (
        "system/bgp_aspath_filters/{name}/bgp_aspath_filter_entries"
    )
    object_uri = collection_uri + "/{preference}"
    resource_name = "preference"
    indices = ["preference"]

    def __init__(self, session, preference, parent_aspath_filter, **kwargs):
        self.__parent_aspath_filter = parent_aspath_filter
        self.__preference = preference
        self.session = session

        # List used to determine attributes related to the
        # BGP AS-Path Filter Entry configuration
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
            name=self.__parent_aspath_filter.name, preference=preference
        )
        self.base_uri = self.collection_uri.format(
            name=self.__parent_aspath_filter.name
        )

    @property
    def preference(self):
        return self.__preference

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a BGP AS-Path Filter Entry and
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
    def get_all(cls, session, aspath_filter_name):
        """
        Perform a GET call to retrieve all entries of the same BGP AS-Path
            Filter and create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param aspath_filter_name: Name of the BGP AS-Path Filter to which the
            entries belong.
        :return: Dictionary containing entry preferences as keys and a BGP
            AS-Path Filter Entry object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = cls.collection_uri.format(name=aspath_filter_name)

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
            preference, entry = cls.from_uri(session, uri)
            entry_dict[preference] = entry

        return entry_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing BGP AS-Path
            Filter Entry. Checks whether the entry exists in the switch and
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

        :return: True if the object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The preference is an index and cannot be part of the PUT body
        if "preference" in data:
            del data["preference"]
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new entry in the switch.

        :return: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The preference is an index and must be added explicitly
        data["preference"] = self.preference
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a BGP AS-Path Filter Entry from the
            switch.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a BgpAspathFilterEntry object given an URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return: tuple with the preference and the entry.
        """
        # URI format is:
        # /system/bgp_aspath_filters/{name}/bgp_aspath_filter_entries/{pref}
        parts = uri.split("/")
        aspath_filter_name = parts[-3]
        preference = parts[-1]
        aspath_filter = BgpAspathFilter(session, aspath_filter_name)
        entry = cls(session, preference, aspath_filter)
        return preference, entry

    @classmethod
    def get_facts(cls, session, aspath_filter_name):
        """
        Retrieve the information of all entries of a BGP AS-Path Filter.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param aspath_filter_name: Name of the BGP AS-Path Filter to which the
            entries belong.
        :return: Dictionary containing the preference as key and the facts as
            value.
        """
        logging.info("Retrieving BGP AS-Path Filter Entries facts")

        depth = session.api.default_facts_depth

        uri = cls.collection_uri.format(name=aspath_filter_name)

        try:
            response = session.request("GET", uri, params={"depth": depth})
        except Exception as exc:
            raise ResponseError("GET", exc)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        return json.loads(response.text)

    def __str__(self):
        return "BGP AS-Path Filter Entry {0} of Filter {1}".format(
            self.preference, self.__parent_aspath_filter.name
        )

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
