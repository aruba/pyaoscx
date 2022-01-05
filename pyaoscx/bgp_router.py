# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.bgp_neighbor import BgpNeighbor
from pyaoscx.aggregate_address import AggregateAddress
from pyaoscx.pyaoscx_module import PyaoscxModule


import json
import logging
import re
import pyaoscx.utils.util as utils
from pyaoscx.utils.list_attributes import ListDescriptor


class BgpRouter(PyaoscxModule):
    """
    Provide configuration management for BGP on AOS-CX devices.
    """

    indices = ["asn"]
    resource_uri_name = "bgp_routers"

    # Use to manage BGP Neighbors
    bgp_neighbors = ListDescriptor("bgp_neighbors")
    aggregate_addresses = ListDescriptor("aggregate_addresses")

    def __init__(self, session, asn: int, parent_vrf, uri=None, **kwargs):

        self.session = session
        # Assign id
        self.asn = asn
        # Assign parent Vrf object
        self.__set_vrf(parent_vrf)
        self._uri = uri
        # List used to determine attributes related to the BGP configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage BGP Neighbors
        self.bgp_neighbors = []
        # Use to manage Aggregate Addresses
        self.aggregate_addresses = []
        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_vrf(self, parent_vrf):
        """
        Set parent Vrf object as an attribute for the BGP class
        :param parent_vrf: a Vrf object
        """

        # Set parent Vrf object
        self.__parent_vrf = parent_vrf

        # Set URI
        self.base_uri = "{base_vrf_uri}/{vrf_name}/bgp_routers".format(
            base_vrf_uri=self.__parent_vrf.base_uri,
            vrf_name=self.__parent_vrf.name)

        # Verify BGP Router doesn't exist already inside VRF
        for bgp_router in self.__parent_vrf.bgp_routers:
            if bgp_router.asn == self.asn:
                # Make list element point to current object
                bgp_router = self
            else:
                # Add self to bgp_routers list in parent_vrf
                self.__parent_vrf.bgp_routers.append(self)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a BGP Router table entry and
            fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        """
        logging.info("Retrieving the switch BGP Routers")

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {}".format(depths))

        if selector not in self.session.api.valid_selectors:
            selectors = " ".join(self.session.api.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {}".format(selectors))

        payload = {"depth": depth, "selector": selector}

        uri = "{base_url}{class_uri}/{asn}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            asn=self.asn)
        try:
            response = self.session.s.get(uri,
                                          verify=False,
                                          params=payload,
                                          proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)
        # Delete unwanted data
        if "bgp_neighbors" in data:
            data.pop("bgp_neighbors")
        if "aggregate_addresses" in data:
            data.pop("aggregate_addresses")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the BGP Router is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs",
                ["asn", "bgp_neighbors", "aggregate_addresses"])

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "asn" in self.__original_attributes:
            self.__original_attributes.pop("asn")
        # Remove ID
        if "bgp_neighbors" in self.__original_attributes:
            self.__original_attributes.pop("bgp_neighbors")
        # Remove ID
        if "aggregate_addresses" in self.__original_attributes:
            self.__original_attributes.pop("aggregate_addresses")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        # Get BGP Neighbors
        if self.bgp_neighbors == []:
            # Set BGP Neighbor if any
            # Adds BGP Neighbor to parent BGP Router already
            BgpNeighbor.get_all(self.session, self)

        if self.aggregate_addresses == []:
            # Set Aggregate address if any
            # Adds Aggregate Addresses to parent BGP Router already
            AggregateAddress.get_all(self.session, self)
        return True

    @classmethod
    def get_all(cls, session, parent_vrf):
        """
        Perform a GET call to retrieve all system BGP inside a VRF,
        and create a dictionary containing them
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent Vrf object where VRF is stored
        :return: Dictionary containing BGP Router IDs as keys and a BGP Router
            objects as values
        """

        logging.info("Retrieving the switch BGP Routers")

        base_uri = "{base_vrf_uri}/{vrf_name}/bgp_routers".format(
            base_vrf_uri=parent_vrf.base_uri, vrf_name=parent_vrf.name)

        uri = "{base_url}{class_uri}".format(base_url=session.base_url,
                                             class_uri=base_uri)

        try:
            response = session.s.get(uri, verify=False, proxies=session.proxy)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        bgp_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a BgpRouter object and adds it to parent Vrf object list
            asn, bgp = BgpRouter.from_uri(session, parent_vrf, uri)
            # Load all BGP Router data from within the Switch
            bgp.get()
            bgp_dict[asn] = bgp

        return bgp_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing
        BGP Router table entry.
        Checks whether the BGP Router exists in the switch
        Calls self.update() if BGP Router is being updated
        Calls self.create() if a new BGP Router is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise

        """
        if not self.__parent_vrf.materialized:
            self.__parent_vrf.apply()

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
        Perform a PUT call to apply changes to an existing BGP Router
        table entry

        :return modified: True if Object was modified and a PUT request
            was made. False otherwise
        """
        # Variable returned
        modified = False

        bgp_router_data = utils.get_attrs(self, self.config_attrs)

        uri = "{base_url}{class_uri}/{asn}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            asn=self.asn)

        # Compare dictionaries
        if bgp_router_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(bgp_router_data)

            try:
                response = self.session.s.put(uri,
                                              verify=False,
                                              data=post_data,
                                              proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(response.text,
                                            response.status_code)

            else:
                logging.info(
                    "SUCCESS: Update BGP table entry {} succeeded".format(
                        self.asn))

            # Set new original attributes
            self.__original_attributes = bgp_router_data

            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new BGP Router table entry
        Only returns if an exception is not raise

        :return modified: Boolean, True if entry was created
        """
        bgp_data = utils.get_attrs(self, self.config_attrs)
        bgp_data["asn"] = self.asn

        uri = "{base_url}{class_uri}".format(base_url=self.session.base_url,
                                             class_uri=self.base_uri)
        post_data = json.dumps(bgp_data)

        try:
            response = self.session.s.post(uri,
                                           verify=False,
                                           data=post_data,
                                           proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Adding BGP table entry {} succeeded".format(
                self.asn))

        # Get all object's data
        self.get()
        # Object was created, thus modified
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete BGP Router table entry.

        """

        uri = "{base_url}{class_uri}/{asn}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            asn=self.asn)

        try:
            response = self.session.s.delete(uri,
                                             verify=False,
                                             proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Delete BGP table entry {} succeeded".format(
                self.asn))

        # Delete back reference from VRF
        for bgp_router in self.__parent_vrf.bgp_routers:
            if bgp_router.asn == self.asn:
                self.__parent_vrf.bgp_routers.remove(bgp_router)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vrf, response_data):
        """
        Create a BgpRouter object given a response_data related to the
        BGP asn object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent Vrf object where VRF is stored
        :param response_data: The response can be either a
            dictionary: {
                    asn: "/rest/v10.04/system/vrfs/bgp_routers/asn"
                }
            or a
            string: "/rest/v10.04/system/vrfs/bgp_routers/asn"
        :return: BgpRouter object
        """
        bgp_arr = session.api.get_keys(response_data,
                                               BgpRouter.resource_uri_name)
        asn = bgp_arr[0]
        return BgpRouter(session, asn, parent_vrf)

    @classmethod
    def from_uri(cls, session, parent_vrf, uri):
        """
        Create a BgpRouter object given a URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent Vrf object where BGP Router is stored
        :param uri: a String with a URI

        :return index, bgp_obj: tuple containing both the BgpRouter object
            and the BGP's asn
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)bgp_routers/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create BGP object
        bgp_obj = BgpRouter(session, index, parent_vrf, uri=uri)

        return index, bgp_obj

    def __str__(self):
        return "BGP Router ID {}".format(self.asn)

    def get_uri(self):
        """
        Method used to obtain the specific BGP Router URI
        return: Object's URI
        """

        if self._uri is None:
            self._uri = "{resource_prefix}{class_uri}/{asn}".format(
                resource_prefix=self.session.resource_prefix,
                class_uri=self.base_uri,
                asn=self.asn)

        return self._uri

    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
        """
        return self.session.api.get_index(self)

    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified,
            False otherwise.
        """

        return self.__modified

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def create_bgp_neighbors(self,
                             group_ip,
                             family_type="l2vpn_evpn",
                             reflector=False,
                             send_community=False,
                             local_interface=""):
        """
        Perform a POST call to create BGP Neighbors to the associated current
        BGP Router - ASN.
        With l2vpn_evpn being True, this will also apply EVPN settings to the
        BGP neighbor configurations.

        :param group_ip: IPv4 address or name of group of the neighbors that
            functions as the BGP Router link.
            Example IPv4:
                10.10.12.11/255.255.255.255
        :param family_type: Alphanumeric to specify what type of neighbor
            settings to configure. The options are 'l2vpn-evpn',
            'ipv4-unicast', or 'ipv6-unicast'. When setting to l2vpn-evpn,
            the neighbor configurations also will add
            route-reflector-client and send-community settings.
            Defaults to "l2vpn_evpn"
        :param reflector: Boolean value to determine whether this neighbor has
            route reflector enabled.  Default is False.
        :param send_community: Boolean value to determine whether this
            neighbor has send-community enabled.  Default is False.
        :param local_interface: Optional alphanumeric to specify which
            interface the neighbor will apply to.
            Defaults to ""
        :return bgp_neighbor_obj: BgpRouter object
        """

        if not self.materialized:
            raise VerificationError("VRF {}".format(self.name),
                                    "Object not materialized")

        if local_interface != "":
            if isinstance(local_interface, str):
                local_interface = self.session.api.get_module(
                    self.session, "Interface", local_interface)

        # Set values needed
        activate = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False
        }

        next_hop_unchanged = {"l2vpn-evpn": False}

        route_reflector_client = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False
        }

        send_community_data = {
            "ipv4-unicast": "none",
            "ipv6-unicast": "none",
            "l2vpn-evpn": "none"
        }

        activate[family_type] = True

        if send_community:
            send_community_data[family_type] = "both"

        if reflector:
            route_reflector_client[family_type] = reflector

        bgp_neighbor_obj = self.session.api.get_module(
            self.session,
            "BgpNeighbor",
            group_ip,
            parent_bgp_router=self,
            is_peer_group=False,
            remote_as=self.asn,
            shutdown=False,
            local_interface=local_interface,
            activate=activate,
            next_hop_unchanged=next_hop_unchanged,
            route_reflector_client=route_reflector_client,
            send_community=send_community_data)

        # Try to obtain data; if not, create
        try:
            bgp_neighbor_obj.get()
        except GenericOperationError:
            # Create object inside switch
            bgp_neighbor_obj.apply()

        return bgp_neighbor_obj
