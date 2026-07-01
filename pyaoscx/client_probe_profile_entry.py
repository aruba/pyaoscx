# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class ClientProbeProfileEntry(PyaoscxModule):
    """
    Provide configuration management for Client Probe Profile entries on
        AOS-CX devices. An entry is identified by its entry_id within a
        parent ClientProbeProfile.
    """

    collection_uri = "system/client_probe_profiles/{index}/entries"
    object_uri = collection_uri + "/{entry_id}"
    resource_name = "entry_id"
    indices = ["entry_id"]

    def __init__(self, session, entry_id, parent_profile, uri=None, **kwargs):
        self.__parent_profile = parent_profile
        self.__entry_id = entry_id
        self.session = session
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.path = self.object_uri.format(
            index=parent_profile.index, entry_id=entry_id
        )
        self.base_uri = self.collection_uri.format(index=parent_profile.index)

    @property
    def entry_id(self):
        return self.__entry_id

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Client Probe Profile entry
            and fill the object with the incoming attributes.

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

        if "entry_id" in data:
            data.pop("entry_id")

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", ["entry_id"])

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_profile):
        """
        Perform a GET call to retrieve all entries of a Client Probe Profile
            and create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_profile: ClientProbeProfile object to which the entries
            belong.
        :return: Dictionary containing the entry ids as keys and the
            ClientProbeProfileEntry objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = cls.collection_uri.format(index=parent_profile.index)

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
            entry_id, entry = cls.from_uri(session, parent_profile, uri)
            entries[entry_id] = entry

        return entries

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Client Probe
            Profile entry.

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
        Perform a PUT call to apply changes to an existing Client Probe Profile
            entry.

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
        Perform a POST call to create a new Client Probe Profile entry. Only
            returns if no exception is raised.

        :return: Boolean, True if entry was created.
        """
        entry_data = utils.get_attrs(self, self.config_attrs)
        entry_data["entry_id"] = self.entry_id
        # The switch requires the origin column to be present on creation.
        entry_data.setdefault("origin", "local")

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
        Perform DELETE call to delete a Client Probe Profile entry.
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
    def from_uri(cls, session, parent_profile, uri):
        """
        Create a ClientProbeProfileEntry object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param parent_profile: ClientProbeProfile object to which the entry
            belongs.
        :param uri: a String with a URI.
        :return: tuple containing both the entry id and the
            ClientProbeProfileEntry object.
        """
        entry_id = uri.split("/")[-1]
        entry = cls(session, entry_id, parent_profile)
        return entry_id, entry

    def __str__(self):
        return "ClientProbeProfileEntry entry_id:{0}".format(self.entry_id)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific Client Probe Profile entry URI.

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
