# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

import pyaoscx.utils.util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class DhcpRelay(PyaoscxModule):
    """
    Provide configuration management for DHCP Relay on AOS-CX devices.
    """

    base_uri = "system/dhcp_relays"
    resource_uri_name = "dhcp_relays"

    indices = ["vrf", "port"]

    def __init__(self, session, vrf, port, uri=None, **kwargs):
        self.session = session
        # Assign IDs
        self.vrf = vrf
        self.port = port
        self._uri = uri
        # List used to determine attributes related to the DHCP Relay
        # configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a DHCP Relay table entry and
            fill the object with the incoming attributes.
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

        uri = "{0}/{1}{2}{3}".format(
            DhcpRelay.base_uri,
            self.vrf.name,
            self.session.api.compound_index_separator,
            self.port.percents_name,
        )
        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Remove fields because they are not needed for the PUT request
        if "vrf" in data:
            data.pop("vrf")
        if "port" in data:
            data.pop("port")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the DHCP Relay is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", ["vrf", "port"])

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "vrf" in self.__original_attributes:
            self.__original_attributes.pop("vrf")
        # Remove ID
        if "port" in self.__original_attributes:
            self.__original_attributes.pop("port")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system DHCP Relays, and create a
            dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing DHCP Relays IDs as keys and a DHCP Relay
            objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", DhcpRelay.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        dhcp_relay_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a DHCP Relay object
            indices, dhcp_relay = DhcpRelay.from_uri(session, uri)
            dhcp_relay_dict[indices] = dhcp_relay

        return dhcp_relay_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing DHCP Relay.
            Checks whether the DHCP Relay exists in the switch. Calls
            self.update() if DHCP Relay is being updated. Calls self.create()
            if a new DHCP Relay is being created.
        :return modified: Boolean, True if object was created or modified.
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
        Perform a PUT call to apply changes to an existing DHCP Relay.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Variable returned
        modified = False

        dhcp_relay_data = utils.get_attrs(self, self.config_attrs)

        uri = "{0}/{1}{2}{3}".format(
            DhcpRelay.base_uri,
            self.vrf.name,
            self.session.api.compound_index_separator,
            self.port.percents_name,
        )

        # Compare dictionaries
        if dhcp_relay_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:

            post_data = json.dumps(dhcp_relay_data)

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
            self.__original_attributes = dhcp_relay_data

            # Object was modified, returns True
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new DHCP Relay. Only returns if no
            exception is raised.
        :return modified: Boolean, True if entry was created.
        """
        dhcp_relay_data = utils.get_attrs(self, self.config_attrs)
        dhcp_relay_data["vrf"] = self.vrf.get_info_format()
        dhcp_relay_data["port"] = self.port.get_info_format()

        post_data = json.dumps(dhcp_relay_data)

        try:
            response = self.session.request(
                "POST", DhcpRelay.base_uri, data=post_data
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
        Perform DELETE call to delete DhcpRelay table entry.
        """
        uri = "{0}/{1}{2}{3}".format(
            DhcpRelay.base_uri,
            self.vrf.name,
            self.session.api.compound_index_separator,
            self.port.percents_name,
        )

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
        Create a DhcpRelay object given a response_data.
        :param cls: Class calling the method.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
                {vrf},{port}: "/rest/v10.04/system/dhcp_relays/{vrf},{port}"
            }
        return: DhcpRelay object.
        """
        dhcp_relay_arr = session.api.get_keys(
            response_data, DhcpRelay.resource_uri_name
        )
        port_name = dhcp_relay_arr[1]
        vrf_name = dhcp_relay_arr[0]
        # Create Modules
        port_obj = session.api.get_module(session, "Interface", port_name)
        vrf_obj = session.api.get_module(session, "Vrf", vrf_name)

        return DhcpRelay(session, vrf_obj, port_obj)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a DHCP Relay object given a URI.
        :param cls: Class calling the method.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return indices, dhcp_relay: tuple containing both the indices and
            DhcpRelay object.
        """
        # Obtain ID from URI
        index_pattern = re.compile(
            r"(.*)dhcp_relays/(?P<index1>.+)/(?P<index2>.+)"
        )
        vrf = index_pattern.match(uri).group("index1")
        port = index_pattern.match(uri).group("index2")

        port_obj = session.api.get_module(session, "Interface", port)
        vrf_obj = session.api.get_module(session, "Vrf", vrf)

        # Create DHCP Relay object
        dhcp_relay = DhcpRelay(session, vrf_obj, port_obj)
        indices = "{0},{1}".format(vrf, port)

        return indices, dhcp_relay

    def __str__(self):
        return "DhcpRelay vrf:{0}, port:{1}".format(self.vrf, self.port.name)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific DhcpRelay URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}{3}{4}".format(
                self.session.resource_prefix,
                DhcpRelay.base_uri,
                self.vrf.name,
                self.session.api.compound_index_separator,
                self.port.percents_name,
            )

        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified
        """
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def add_ipv4_addresses(self, ipv4_list):
        """
        Perform a PUT calls to modify an existing DhcpRelay. Adding a list of
            IPv4 addresses into IPv4_ucast_server
        :param ipv4_list: List of IPv4 addresses. Example: ['1.1.1.1',
            '2.2.2.2']
        :return: True if object was changed.
        """
        # Set IPv4
        if ipv4_list is not None and ipv4_list != []:
            for i in range(len(ipv4_list)):
                if ipv4_list[i] not in self.ipv4_ucast_server:
                    self.ipv4_ucast_server.append(ipv4_list[i])

        # Apply changes inside switch
        return self.apply()

    def add_ipv6_addresses(self, ipv6_list):
        """
        Perform a PUT calls to modify an existing DhcpRelay. Adding a list of
            IPv6 addresses into IPv6_ucast_server.
        :param ipv6_list: List of IPv6 addresses. Example:
            ['2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
        :return: True if object was changed.
        """
        # Set IPv6
        if ipv6_list is not None and ipv6_list != []:
            for i in range(len(ipv6_list)):
                if ipv6_list[i] not in self.ipv6_ucast_server:
                    self.ipv6_ucast_server.append(ipv6_list[i])

        # Apply changes inside switch
        return self.apply()
