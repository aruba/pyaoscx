# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils.connection import connected
from pyaoscx.pyaoscx_module import PyaoscxModule

import json
import logging
import re
import pyaoscx.utils.util as utils


class AggregateAddress(PyaoscxModule):
    """
    Provide configuration management for Aggregate Address on AOS-CX devices.
    """

    indices = ["address-family", "ip_prefix"]
    resource_uri_name = "aggregate_addresses"

    def __init__(self, session, address_family, ip_prefix, parent_bgp_router,
                 uri=None, **kwargs):
        self.session = session
        # Assign ID
        self.address_family = address_family
        self.__set_name(ip_prefix)
        # Assign parent BGP Router
        self.__set_bgp_router(parent_bgp_router)
        self._uri = uri
        # List used to determine attributes related to the Aggregate Address
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

    def __set_name(self, ip_prefix):
        """
        Set name attribute in the proper form for references
        :param ip_prefix: Object's IP
        """

        # Add attributes to class
        self._is_lag = False
        self.ip_prefix = None
        self.reference_ip_prefix = None
        if r"%2F" in ip_prefix:
            self.ip_prefix = utils._replace_percents_ip(ip_prefix)
            self.reference_ip_prefix = ip_prefix
        else:
            self.ip_prefix = ip_prefix
            self.reference_ip_prefix = utils._replace_special_characters_ip(
                self.ip_prefix)

    def __set_bgp_router(self, parent_bgp_router):
        """
        Set parent BgpRouter object as an attribute for the Aggregate Address
            class
        :param parent_bgp_router a BgpRouter object
        """

        # Set parent BGP Router
        self.__parent_bgp_router = parent_bgp_router

        # Set URI
        self.base_uri = (
            "{base_bgp_router_uri}/{bgp_router_apn}/aggregate_addresses"
            ).format(
                base_bgp_router_uri=self.__parent_bgp_router.base_uri,
                bgp_router_apn=self.__parent_bgp_router.asn)

        for address in self.__parent_bgp_router.aggregate_addresses:
            if address.address_family == self.address_family and\
                    address.ip_prefix == self.ip_prefix:
                # Make list element point to current object
                address = self
            else:
                # Add self to Aggregate Addresses list in parent BGP Router
                self.__parent_bgp_router.aggregate_addresses.append(self)

    @connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Aggregate Address table entry
        and fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        """
        logging.info("Retrieving the switch Aggregate Addresses")

        depth = self.session.api_version.default_depth\
            if depth is None else depth
        selector = self.session.api_version.default_selector\
            if selector is None else selector

        if not self.session.api_version.valid_depth(depth):
            depths = self.session.api_version.valid_depths
            raise Exception("ERROR: Depth should be {}".format(depths))

        if selector not in self.session.api_version.valid_selectors:
            selectors = " ".join(self.session.api_version.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {}".format(selectors))

        payload = {
            "depth": depth,
            "selector": selector
        }

        uri = "{base_url}{class_uri}/{id1}{separator}{id2}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id1=self.address_family,
            separator=self.session.api_version.compound_index_separator,
            id2=self.reference_ip_prefix
        )

        try:
            response = self.session.s.get(
                uri, verify=False, params=payload, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the Aggregate Address is configurable
        if selector in self.session.api_version.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["address-family"])

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "address-family" in self.__original_attributes:
            self.__original_attributes.pop("address-family")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_bgp_router):
        """
        Perform a GET call to retrieve all system Aggregate Addresses inside a
        BGP Router,
        and create a dictionary containing them
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_bgp_router: parent bgp_router object where Aggregate
            Address is stored
        :return: Dictionary containing Aggregate Addresses IDs as keys and a
            AggregateAddress objects as values
        """

        logging.info("Retrieving the switch Aggregate Address")

        base_uri = (
            "{base_bgp_router_uri}/{bgp_router_apn}/aggregate_addresses"
        ).format(
            base_bgp_router_uri=parent_bgp_router.base_uri,
            bgp_router_apn=parent_bgp_router.asn)

        uri = "{base_url}{class_uri}".format(
            base_url=session.base_url,
            class_uri=base_uri)

        try:
            response = session.s.get(uri, verify=False, proxies=session.proxy)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        agg_address_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api_version.get_uri_from_data(data)

        for uri in uri_list:
            # Create a AggregateAddress object
            indices, aggregate_address = AggregateAddress.from_uri(
                session, parent_bgp_router, uri)
            agg_address_dict[indices] = aggregate_address

        return agg_address_dict

    @connected
    def apply(self):
        """
        Main method used to either create or update an existing
        Aggregate Address table entry.
        Checks whether the Aggregate Addresses exists in the switch
        Calls self.update() if Aggregate Address is being updated
        Calls self.create() if a new Aggregate Address is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise

        """
        if not self.__parent_bgp_router.materialized:
            self.__parent_bgp_router.apply()

        modified = False
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        # Set internal attribute
        self.__modified = modified
        return modified

    @connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Aggregate
        Address table entry

        :return modified: True if Object was modified and a PUT
            request was made. False otherwise

        """
        # Variable returned
        modified = False
        agg_address_data = {}

        agg_address_data = utils.get_attrs(self, self.config_attrs)

        uri = "{base_url}{class_uri}/{id1}{separator}{id2}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id1=self.address_family,
            separator=self.session.api_version.compound_index_separator,
            id2=self.reference_ip_prefix
        )
        # Compare dictionaries
        if agg_address_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(agg_address_data, sort_keys=True, indent=4)

            try:
                response = self.session.s.put(
                    uri, verify=False, data=post_data,
                    proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code)

            else:
                logging.info(
                    "SUCCESS: Update Aggregate Address table entry {} succeeded\
                        ".format(
                        self.address_family))
            # Set new original attributes
            self.__original_attributes = agg_address_data

            # Object was modified
            modified = True
        return modified

    @connected
    def create(self):
        """
        Perform a POST call to create a new Aggregate Address table entry
        Only returns if an exception is not raise

        :return modified: True if entry was created.

        """

        ag_address_data = {}

        ag_address_data = utils.get_attrs(self, self.config_attrs)
        ag_address_data["address-family"] = self.address_family
        ag_address_data["ip_prefix"] = self.ip_prefix

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri
        )
        post_data = json.dumps(ag_address_data, sort_keys=True, indent=4)

        try:
            response = self.session.s.post(
                uri, verify=False, data=post_data, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info(
                "SUCCESS: Adding Aggregate Address table entry {} succeeded\
                    ".format(self.address_family))

        # Get all object's data
        self.get()
        # Object was modified
        return True

    @connected
    def delete(self):
        """
        Perform DELETE call to delete Aggregate Address.

        """

        uri = "{base_url}{class_uri}/{id1}{separator}{id2}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id1=self.address_family,
            separator=self.session.api_version.compound_index_separator,
            id2=self.reference_ip_prefix
        )

        try:
            response = self.session.s.delete(
                uri, verify=False, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info(
                "SUCCESS: Delete Aggregate Address table entry {} succeeded\
                    ".format(self.address_family))

        # Delete back reference from BGP Router
        for address in self.__parent_bgp_router.aggregate_addresses:
            if address.address_family == self.address_family and\
                    address.ip_prefix == self.ip_prefix:
                self.__parent_bgp_router.aggregate_addresses.remove(address)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_bgp_router, response_data):
        """
        Create a AggregateAddress object given a response_data related to the
            Aggregate Address ID object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_bgp_router: parent BGP Router class where Aggregate
            Address is stored
        :param response_data: The response can be either a
            dictionary: {
                    id: "/rest/v10.04/system/vrfs/bgp_routers/asn
                        /aggregate_addresses/id"
                }
            or a
            string: "/rest/v10.04/system/vrfs/bgp_routers/asn
                    /aggregate_addresses/address_family/ip_prefix"
        :return: AggregateAddress object
        """
        aggr_address_arr = session.api_version.get_keys(
            response_data, cls.resource_uri_name)
        ip_prefix = aggr_address_arr[1]
        address_family = aggr_address_arr[0]

        return AggregateAddress(
            session, address_family, ip_prefix, parent_bgp_router)

    @classmethod
    def from_uri(cls, session, parent_bgp_router, uri):
        """
        Create a AggregateAddress object
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_bgp_router: parent BGP Router class where Aggregate
            Address is stored
        :param uri: a String with a URI

        :return indices, aggr_address: tuple containing both the Aggregate
            Address object and the Aggregate Address' ID
        """
        # Obtain ID from URI
        index_pattern = \
            re.compile(
                r"(.*)aggregate_addresses/(?P<index1>.+)[,./-](?P<index2>.+)")
        index1 = index_pattern.match(uri).group("index1")
        index2 = index_pattern.match(uri).group("index2")

        # Create Create a AggregateAddress object
        aggr_address = AggregateAddress(session, index1, index2,
                                        parent_bgp_router)
        indices = "{},{}".format(index1, index2)

        return indices, aggr_address

    def __str__(self):
        return "Aggregate Address ID {}".format(self.address_family)

    def get_uri(self):
        """
        Method used to obtain the specific Aggregate Address URI
        return: Object's URI
        """

        if self._uri is None:
            self._uri = (
                "{resource_prefix}{class_uri}/{id1}{separator}{id2}"
            ).format(
                resource_prefix=self.session.resource_prefix,
                class_uri=self.base_uri,
                id1=self.address_family,
                separator=self.session.api_version.compound_index_separator,
                id2=self.reference_ip_prefix
            )

        return self._uri

    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
        """
        return self.session.api_version.get_index(self)

    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified,
            False otherwise.
        """

        return self.__modified