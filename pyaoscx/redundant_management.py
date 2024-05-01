# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from urllib.parse import quote, unquote

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.pyaoscx_module import PyaoscxModule
from pyaoscx.utils import util as utils


class RedundantManagement(PyaoscxModule):
    """
    Provide configuration management for Redundant Management on AOS-CX
    devices.
    """

    resource_uri_name = "redundant_managements"
    collection_uri = "system/{resource}".format(resource=resource_uri_name)
    object_uri = collection_uri + "/{name}"
    indices = ["name"]

    def __init__(self, session, name, **kwargs):
        """
        Create an instance of Redundant Management Class.

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param name: String representing a user-defined name for a Redundant
            Management object.
        """
        self.session = session
        self.__name = name
        # List used to determine attributes related to the Redundant
        # Management configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(
            name=quote(self.__name)
        )

    @property
    def name(self):
        """
        Method used to obtain the specific name.

        :return: returns the name of this Redundant Management object.
        """
        return self.__name

    @PyaoscxModule.connected
    def get(self, depth=None, selector="status"):
        """
        Perform a GET call to retrieve data for a Redundant Management table
            entry and fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information
            to return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s data from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(self, session):
        """
        Perform a GET call to retrieve all Redundant Management information
            and create a dictionary containing each respective Redundant
            Management data.

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing all system Redundant Management
            information.
        """
        logging.info("Retrieving all Redundant Management data from switch")

        try:
            response = session.request("GET", self.collection_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        rdntmgmt_collection = {}

        data = json.loads(response.text)
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            name, rdntmgmt = RedundantManagement.from_uri(session, uri)
            rdntmgmt_collection[name] = rdntmgmt

        return rdntmgmt_collection

    @PyaoscxModule.connected
    def apply(self):
        """
        Not needed for Redundant Management
        """
        pass

    @PyaoscxModule.connected
    def create(self):
        """
        Not needed for Redundant Management
        """
        pass

    @PyaoscxModule.connected
    def delete(self):
        """
        Not needed for Redundant Management
        """
        pass

    @PyaoscxModule.connected
    def update(self):
        """
        Not needed for Redundant Management
        """
        pass

    @classmethod
    def from_response(self, session, response_data):
        """
        Create a Redundant Management object given a response_data related to
            it.

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
            "<Redundant Management name>":
            "/rest/v10.xx/system/redundant_managements/
            <Redundant Management name>"
            }
        :return: Redundant Management Object.
        """
        rdntmgmt_name_arr = session.api.get_keys(
            response_data, self.resource_uri_name
        )
        rdntmgmt_name = rdntmgmt_name_arr[0]
        return RedundantManagement(session, rdntmgmt_name)

    @classmethod
    def from_uri(self, session, uri):
        """
        Create a Redundant Management object given a Redundant Management URI.

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return name, rdntmgmt: tuple with the name of a Redundant Management
            configuration and a corresponding object.
        """
        if self.base_uri not in uri:
            raise ValueError(
                "ERROR: URI must be a valid Redundant Management URI.")

        name = unquote(uri.split("/")[-1])
        rdntmgmt = RedundantManagement(session, name)

        return name, rdntmgmt

    def __str__(self):
        return "Redundant Management {0}".format(self.name)
