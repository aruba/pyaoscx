# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

import pyaoscx.utils.util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class UdpBcastForwarderServer(PyaoscxModule):
    """
    Provide configuration management for UDP Broadcast Forwarder Servers on
        AOS-CX devices. A forwarder is identified by the routed source port,
        the destination VRF and the destination UDP port.
    """

    base_uri = "system/udp_bcast_forwarder_servers"
    resource_uri_name = "udp_bcast_forwarder_servers"

    indices = ["dest_vrf", "src_port", "udp_dport"]

    def __init__(
        self, session, dest_vrf, src_port, udp_dport, uri=None, **kwargs
    ):
        self.session = session
        # Assign IDs
        self.dest_vrf = dest_vrf
        self.src_port = src_port
        self.udp_dport = udp_dport
        self._uri = uri
        # List used to determine attributes related to the UDP Broadcast
        # Forwarder Server configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    def _index_uri(self):
        """
        Build the object URI from its compound index.

        :return: String with the object URI.
        """
        separator = self.session.api.compound_index_separator
        return "{0}/{1}{2}{3}{4}{5}".format(
            UdpBcastForwarderServer.base_uri,
            self.dest_vrf.name,
            separator,
            self.src_port.percents_name,
            separator,
            self.udp_dport,
        )

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a UDP Broadcast Forwarder
            Server and fill the object with the incoming attributes.

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

        uri = self._index_uri()
        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Remove index fields because they are not needed for the PUT request
        for index in UdpBcastForwarderServer.indices:
            if index in data:
                data.pop(index)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the forwarder is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete indices from it
            utils.set_config_attrs(
                self, data, "config_attrs", UdpBcastForwarderServer.indices
            )

        # Set original attributes
        self.__original_attributes = data

        # Sets object as materialized
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all UDP Broadcast Forwarder Servers,
            and create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing forwarder IDs as keys and a
            UdpBcastForwarderServer object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        forwarder_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            indices, forwarder = cls.from_uri(session, uri)
            forwarder_dict[indices] = forwarder

        return forwarder_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing UDP Broadcast
            Forwarder Server. Checks whether the forwarder exists in the
            switch. Calls self.update() if it is being updated. Calls
            self.create() if a new forwarder is being created.

        :return: Boolean, True if object was created or modified.
        """
        modified = False
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        # Set internal attribute
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing UDP Broadcast
            Forwarder Server.

        :return: True if Object was modified and a PUT request was made.
        """
        # Variable returned
        modified = False

        forwarder_data = utils.get_attrs(self, self.config_attrs)

        uri = self._index_uri()

        # Compare dictionaries
        if forwarder_data == self.__original_attributes:
            # Object was not modified
            modified = False
        else:
            post_data = json.dumps(forwarder_data)

            try:
                response = self.session.request("PUT", uri, data=post_data)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code
                )

            logging.info("SUCCESS: Updating %s", self)
            # Set new original attributes
            self.__original_attributes = forwarder_data

            # Object was modified, returns True
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new UDP Broadcast Forwarder Server.
            Only returns if no exception is raised.

        :return: Boolean, True if entry was created.
        """
        forwarder_data = utils.get_attrs(self, self.config_attrs)
        forwarder_data["dest_vrf"] = self.dest_vrf.get_info_format()
        forwarder_data["src_port"] = self.src_port.get_info_format()
        forwarder_data["udp_dport"] = self.udp_dport

        post_data = json.dumps(forwarder_data)

        try:
            response = self.session.request(
                "POST", UdpBcastForwarderServer.base_uri, data=post_data
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all object's data
        self.get()

        # Object was created, means modified
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete a UDP Broadcast Forwarder Server.
        """
        uri = self._index_uri()

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a UdpBcastForwarderServer object given a response_data.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
            {vrf},{port},{dport}:
                "/rest/v10.09/system/udp_bcast_forwarder_servers/"
                "{vrf},{port},{dport}"
            }
        :return: UdpBcastForwarderServer object.
        """
        keys_arr = session.api.get_keys(
            response_data, UdpBcastForwarderServer.resource_uri_name
        )
        vrf_name = keys_arr[0]
        port_name = keys_arr[1]
        udp_dport = keys_arr[2]
        # Create Modules
        vrf_obj = session.api.get_module(session, "Vrf", vrf_name)
        port_obj = session.api.get_module(session, "Interface", port_name)

        return UdpBcastForwarderServer(session, vrf_obj, port_obj, udp_dport)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a UdpBcastForwarderServer object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: tuple containing both the indices and the
            UdpBcastForwarderServer object.
        """
        # Obtain indices from URI
        index_pattern = re.compile(
            r"(.*)udp_bcast_forwarder_servers/"
            r"(?P<index1>.+),(?P<index2>.+),(?P<index3>.+)"
        )
        match = index_pattern.match(uri)
        vrf_name = match.group("index1")
        port_name = match.group("index2")
        udp_dport = match.group("index3")

        vrf_obj = session.api.get_module(session, "Vrf", vrf_name)
        port_obj = session.api.get_module(session, "Interface", port_name)

        # Create UDP Broadcast Forwarder Server object
        forwarder = UdpBcastForwarderServer(
            session, vrf_obj, port_obj, udp_dport
        )
        indices = "{0},{1},{2}".format(vrf_name, port_name, udp_dport)

        return indices, forwarder

    def __str__(self):
        return (
            "UdpBcastForwarderServer dest_vrf:{0}, src_port:{1}, "
            "udp_dport:{2}".format(
                self.dest_vrf, self.src_port.name, self.udp_dport
            )
        )

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific UDP Broadcast Forwarder Server URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix, self._index_uri()
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

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.

        :return: Boolean True if the object was recently modified.
        """
        return self.modified
