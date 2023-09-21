# (C) Copyright 2023 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from urllib.parse import quote_plus, unquote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class LLDPNeighbor(PyaoscxModule):
    """
    Provide information from LLDP_Neighbor on AOS-CX devices.
    """

    collection_uri = "system/interfaces/{interface}/lldp_neighbors"
    object_uri = collection_uri + "/{chassis_id},{port_id}"
    indices = ["chassis_id", "port_id"]
    resource_uri_name = "lldp_neighbors"

    def __init__(self, session, chassis_id, port_id, parent_interface):
        self.session = session
        self.chassis_id = chassis_id
        self.port_id = port_id
        self._parent_interface = (
            session.api.get_module(session, "Interface", parent_interface)
            if isinstance(parent_interface, str)
            else parent_interface
        )
        self.materialized = False
        self.__modified = False
        uri_indices = {
            "interface": self._parent_interface.percents_name,
            "chassis_id": quote_plus(chassis_id),
            "port_id": quote_plus(port_id),
        }
        self.collection_uri = self.collection_uri.format(**uri_indices)
        self.object_uri = self.object_uri.format(**uri_indices)
        self.base_uri = self.collection_uri
        self.path = self.object_uri

    @PyaoscxModule.connected
    def get(self, depth=None, selector="status"):
        """
        Perform a GET call to retrieve data for a LLDP Neighbor table entry and
            fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_interface):
        """
        Perform a GET call to retrieve all LLDP Neighbors for an interface
            and create a dictionary containing each LLDP Neighbor.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_interface: parent Interface object where LLDP Neighbor
            is stored.
        :return: Dictionary containing LLDP Neighbor's name as key and a LLDP
            Neighbor objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)
        if isinstance(parent_interface, str):
            parent_interface = session.api.get_module(
                session, "Interface", parent_interface
            )
        try:
            uri = cls.collection_uri.format(
                interface=parent_interface.percents_name
            )
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)

        lldp_n_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create an LLDP Neighbor object
            name, lldp_n_obj = cls.from_uri(session, uri)
            lldp_n_dict[name] = lldp_n_obj

        return lldp_n_dict

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create an LLDP Neighbor object given a response_data related to the
            LLDP Neighbor object.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            { "chassis_id,port_id": URL }, with URL:
            ".../system/interfaces/<interface_name>/lldp_neighbors/<c,p>"
        :return: LLDPNeighbor object.
        """
        lldp_n_uri = next(iter(response_data))
        _, lldp_n_obj = cls.from_uri(session, lldp_n_uri)
        return lldp_n_obj

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an LLDP Neighbor object given a URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: tuple containing both the LLDP Neighbor's name and LLDP
            Neighbor object object.
        """
        # Obtain ID from URI
        index_pattern = re.compile(
            r"(.*)/(?P<intf>.+)/lldp_neighbors/(?P<chassis>.+),(?P<port_id>.+)"
        )
        intf_name = index_pattern.match(uri).group("intf")
        chassis_id = index_pattern.match(uri).group("chassis")
        port_id = index_pattern.match(uri).group("port_id")
        # Create LLDP Neighbor object
        lldp_neighbor_obj = cls(
            session,
            unquote_plus(chassis_id),
            unquote_plus(port_id),
            unquote_plus(intf_name),
        )

        return "{0},{1}".format(chassis_id, port_id), lldp_neighbor_obj

    @classmethod
    def get_facts(cls, session):
        """
        Perform a GET call to retrieve all LLDP Neighbors and their data.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return facts: Dictionary containing Interface IDs as keys and
            LLDP Neighbors objects as values.
        """
        logging.info("Retrieving the switch LLDP Neighbors facts")

        # Set depth
        depth = session.api.default_facts_depth

        # Build URI to get all LLDP Neighbors from all Interfaces
        uri = cls.collection_uri.format(interface=quote_plus("*"))
        uri += "?depth={0}".format(depth)

        try:
            # Try to get facts via GET method
            response = session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load into json format
        facts = json.loads(response.text)
        return facts

    @PyaoscxModule.connected
    def apply(self):
        """
        Not applicable for LLDP Neighbor.
        """
        pass

    @PyaoscxModule.connected
    def update(self):
        """
        Not applicable for LLDP Neighbor.
        """
        pass

    @PyaoscxModule.connected
    def create(self):
        """
        Not applicable for LLDP Neighbor.
        """
        pass

    @PyaoscxModule.connected
    def delete(self):
        """
        Not applicable for LLDP Neighbor.
        """
        pass

    def __str__(self):
        return "LLDP Neighbor for interface {0}: {1},{2}".format(
            self._parent_interface.name, self.chassis_id, self.port_id
        )

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.

        return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)
