# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from urllib.parse import quote_plus, unquote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

import pyaoscx.utils.util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class Ipv6(PyaoscxModule):
    """
    Provide configuration management for IPv6 on AOS-CX devices.
    """

    indices = ["address"]
    resource_uri_name = "ip6_addresses"

    def __init__(self, session, address, parent_int, uri=None, **kwargs):

        self.session = session
        # Assign address
        self.__set_name(address)
        # Assign parent Interface
        self.__set_interface(parent_int)
        self._uri = uri
        # List used to determine attributes related to the IPv6 configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_name(self, address):
        """
        Set name attribute in the proper form for IPv6.
        """
        # Add attributes to class
        self.address = None
        self.reference_address = None

        if r"%2F" in address or r"%3A" in address:
            self.address = unquote_plus(address)
            self.reference_address = address
        else:
            self.address = address
            self.reference_address = quote_plus(self.address)

    def __set_interface(self, parent_int):
        """
        Set parent interface as an attribute for the Ipv6 object.
        :param parent_int a Interface object.
        """
        # Set Parent Interface
        self.__parent_int = parent_int
        # Set Name for URI purposes
        self.__parent_int_name = self.__parent_int.percents_name

        # Set URI
        self.base_uri = "{0}/{1}/ip6_addresses".format(
            self.__parent_int.base_uri,
            self.__parent_int_name,
        )

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a IPv6 table entry and fill the
            object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
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

        uri = "{0}/{1}".format(self.base_uri, self.reference_address)

        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the IPv6 is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", ["address"])

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "address" in self.__original_attributes:
            self.__original_attributes.pop("address")
        # Remove type
        if "type" in self.__original_attributes:
            self.__original_attributes.pop("type")
        # Remove origin
        if "origin" in self.__original_attributes:
            self.__original_attributes.pop("origin")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_int):
        """
        Perform a GET call to retrieve all system IPv6 addresses inside an
            Interface, and create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_int: parent Interface object where IPv6 is stored
        :return: Dictionary containing IPv6 IDs as keys and a Ipv6 object as
            value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/{1}/ip6_addresses".format(
            parent_int.base_uri, parent_int.percents_name
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        ipv6_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a Ipv6 object
            address, ipv6 = Ipv6.from_uri(session, parent_int, uri)
            # Load all IPv6 data from within the Switch
            ipv6.get()
            ipv6_dict[address] = ipv6

        return ipv6_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing IPv6. Checks
            whether the IPv6 exists in the switch. Calls self.update() if IPv6
            is being updated. Calls self.create() if a new IPv6 is being
            created.
        """
        if not self.__parent_int.materialized:
            if self.__parent_int.__is_special_type:
                # Verify if it's a LAG
                self.__parent_int.apply()
            else:
                self.__parent_int.get()

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
        Perform a PUT call to apply changes to an existing IPv6 table entry
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Variable returned
        modified = False

        ip6_data = utils.get_attrs(self, self.config_attrs)

        # Delete Type
        if "type" in ip6_data:
            ip6_data.pop("type")
        if "origin" in ip6_data:
            ip6_data.pop("origin")

        uri = "{0}/{1}".format(self.base_uri, self.reference_address)
        # Compare dictionaries
        if ip6_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:

            post_data = json.dumps(ip6_data)

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
            self.__original_attributes = ip6_data

            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new IPv6 using the object's attributes
            as POST body. Only returns if an exception is not raised.
        :return modified: Boolean, True if entry was created.
        """
        ipv6_data = utils.get_attrs(self, self.config_attrs)
        ipv6_data["address"] = self.address

        post_data = json.dumps(ipv6_data)

        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all object's data
        self.get()
        # Object was created, thus modified
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete IPv6 address from interface on the
            switch.
        """
        uri = "{0}/{1}".format(self.base_uri, self.reference_address)

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

        # Delete back reference from VRF
        for ip6 in self.__parent_int.ip6_addresses:
            if ip6.address == self.address:
                self.__parent_int.ip6_addresses.remove(ip6)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_int, response_data):
        """
        Create a IPv6 object given a response_data related to the IP6 address.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_int: parent Interface object where IPv6 is stored
        :param response_data: The response must be a dictionary of the form:
            {
                <address>: "/rest/v10.04/interface/ip6_addresses/<address>"
            }
        :return: IPv6 object.
        """
        ipv6_arr = session.api.get_keys(response_data, Ipv6.resource_uri_name)
        address = ipv6_arr[0]
        return Ipv6(session, address, parent_int)

    @classmethod
    def from_uri(cls, session, parent_int, uri):
        """
        Create a Ipv6 object given a URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_int: Parent Interface class where IPv6 is stored.
        :param uri: a String with a URI.
        :return index, ipv6_obj: tuple containing both the Ipv6 Object and
            the ipv6's address.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)ip6_addresses/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create Ipv6 object
        ipv6_obj = Ipv6(session, index, parent_int, uri=uri)

        return index, ipv6_obj

    def __str__(self):
        return "IPv6 address {0}".format(self.address)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific IPv6 URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
                self.reference_address,
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
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified.
        """
        return self.modified
