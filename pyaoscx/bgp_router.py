# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.aggregate_address import AggregateAddress
from pyaoscx.bgp_neighbor import BgpNeighbor

from pyaoscx.pyaoscx_module import PyaoscxModule


class BgpRouter(PyaoscxModule):
    """
    Provide configuration management for BGP Routers on AOS-CX devices.
    """

    indices = ["asn"]
    resource_uri_name = "bgp_routers"

    # Use to manage BGP Neighbors
    bgp_neighbors = ListDescriptor("bgp_neighbors")
    aggregate_addresses = ListDescriptor("aggregate_addresses")

    collection_uri = "system/vrfs/{name}/bgp_routers"
    object_uri = collection_uri + "/{asn}"

    def __init__(self, session, asn, parent_vrf, uri=None, **kwargs):
        self.session = session
        # Assign id
        self.__asn = asn
        self.__parent_vrf = parent_vrf
        self._uri = uri
        # List used to determine attributes related to the BGP configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage BGP Neighbors
        self.bgp_neighbors = []
        # Use to manage Aggregate Addresses
        self.aggregate_addresses = []
        # Attribute used to know if object was changed recently
        self.__modified = False
        uri_indices = {
            "name": self.__parent_vrf.name,
            "asn": self.__asn,
        }
        self._uri_indices = uri_indices
        self.base_uri = self.collection_uri.format(**uri_indices)
        self.path = self.object_uri.format(**uri_indices)
        self.__parent_vrf.update_bgp_routers(self)

    @property
    def asn(self):
        return self.__asn

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a BGP Router table entry and
            fill the object with the incoming attributes
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

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
            utils.set_config_attrs(self, data, "config_attrs", self.indices)

        # Set original attributes
        self._original_attributes = data
        # Remove ID
        if "asn" in self._original_attributes:
            self._original_attributes.pop("asn")
        # Remove ID
        if "bgp_neighbors" in self._original_attributes:
            self._original_attributes.pop("bgp_neighbors")
        # Remove ID
        if "aggregate_addresses" in self._original_attributes:
            self._original_attributes.pop("aggregate_addresses")

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
        Perform a GET call to retrieve all system BGP Routers inside a VRF, and
            create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: Vrf object where BGP Router is stored.
        :return: Dictionary containing BGP Router IDs as keys and a BGP Router
            objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/{1}/bgp_routers".format(
            parent_vrf.base_uri, parent_vrf.name
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        bgp_dict = {}

        for uri in data.values():
            # Create a BgpRouter object and adds it to parent Vrf object list
            asn, bgp = BgpRouter.from_uri(session, parent_vrf, uri)
            # Load all BGP Router data from within the Switch
            bgp_dict[asn] = bgp

        return bgp_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing BGP Router.
            Checks whether the BGP Router exists in the switch. Calls
            self.update() if BGP Router is being updated. Calls self.create()
            if a new BGP Router is being created.
        :return modified: Boolean, True if object was created or modified.
        """
        if not self.__parent_vrf.materialized:
            self.__parent_vrf.apply()
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing BGP Router.
        :return modified: True if Object was modified and a PUT request
            was made.
        """
        bgp_router_data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(bgp_router_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new BGP Router table entry. Only
            returns if no exception is raised.
        :return modified: Boolean, True if entry was created.
        """
        bgp_data = utils.get_attrs(self, self.config_attrs)
        bgp_data["asn"] = self.asn

        self.__modified = self._post_data(bgp_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete BGP Router.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        self.__parent_vrf.remove_bgp_router(self)
        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vrf, response_data):
        """
        Create a BgpRouter object given a response_data related to it.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: Vrf object where BGP Router is stored.
        :param response_data: The response must be a dictionary of the form:
            {
                <asn>: "/rest/v10.04/system/vrfs/<name>/bgp_routers/<asn>"
            }
        :return: BgpRouter object.
        """
        bgp_arr = session.api.get_keys(
            response_data, BgpRouter.resource_uri_name
        )
        asn = bgp_arr[0]
        return BgpRouter(session, asn, parent_vrf)

    @classmethod
    def from_uri(cls, session, parent_vrf, uri):
        """
        Create a BgpRouter object given a URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: Vrf object where BGP Router is stored.
        :param uri: a String with a URI.
        :return index, bgp_obj: tuple containing both the BgpRouter object
            and the BGP's asn.
        """
        # Obtain ID from URI
        # system/vrfs/<name>/bgp_routers/<asn>
        asn = uri.split("/")[-1]

        # Create BGP object
        bgp_obj = BgpRouter(session, asn, parent_vrf)

        return asn, bgp_obj

    def __str__(self):
        return "BGP Router ID {0}".format(self.asn)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific BGP Router URI.
        return: Object's URI.
        """
        return self.path

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
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def update_bgp_neighbors(self, new_neighbor):
        """
        Update references to BGP Neighbors. If a Neighbor with the same IP,
            Interface or group name is found, update the reference to the new
            neighbor, otherwise, add reference to the new neighbor.
        :param new_neighbor: Neighbor to add reference to.
        """
        for neighbor in self.neighbors:
            if (
                neighbor.ip_or_ifname_or_group_name
                == new_neighbor.ip_or_ifname_or_group_name
            ):
                neighbor = new_neighbor
                return
        self.new_neighbor.append(new_neighbor)

    def remove_bgp_neighbor(self, neighbor):
        """
        Update references to BGP Neighbors. If a Neighbor with the same IP,
            Interface or group name is found, delete the reference to it.
        :param new_neighbor: Neighbor to add reference to.
        """
        for i in self.neighbors:
            if (
                i.ip_or_ifname_or_group_name
                == neighbor.ip_or_ifname_or_group_name
            ):
                self.neighbor.remove(i)

    @PyaoscxModule.materialized
    def create_bgp_neighbors(
        self,
        ip_or_ifname_or_group_name,
        family_type=None,
        activate=None,
        inbound_soft_reconfiguration=None,
        route_reflector_client=None,
        send_community=None,
        remote_as=None,
        update_source=None,
    ):
        """
        Perform a POST call to create BGP Neighbors to the associated current
            BGP Router. With l2vpn_evpn being True, this will also apply EVPN
            settings to the BGP neighbor configurations.
        :param family_type: Alphanumeric to specify what type of neighbor
            settings to configure. The options are 'ipv4-unicast',
            'ipv6-unicast' and 'l2vpn-evpn'.
        :param ip_or_ifname_or_group_name: IPv4 address or name of group of
            the neighbors that functions as the BGP Router link. Example IPv4:
            10.10.12.11/255.255.255.255
        :param activate: Boolean value to activate neighbor in the address
            family.
        :param inbound_soft_reconfiguration: Boolean value that allow inbound
            soft reconfiguration.
        :param route_reflector_client: Boolean value to determine whether this
            neighbor has route reflector enabled.
        :param send_community: Boolean value to determine whether this neighbor
            has send-community enabled.
        :param remote_as: Integer peer ASN.
        :param update_source: Source address for the neighbor session.
        :return bgp_neighbor_obj: BgpRouter object.
        """
        if (
            activate is not None
            or inbound_soft_reconfiguration is not None
            or route_reflector_client is not None
            or send_community is not None
        ):
            if family_type is None:
                raise VerificationError(
                    "family_type must be provided when at least one of "
                    '"inbound_soft_reconfiguration", "send_community",'
                    '"activate", "route_reflector_client", is enabled'
                )

        _activate = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False,
        }

        _inbound_soft_reconfiguration = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
        }

        _route_reflector_client = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False,
        }

        _send_community = {
            "ipv4-unicast": "none",
            "ipv6-unicast": "none",
            "l2vpn-evpn": "none",
        }

        kw = dict()

        if activate is not None:
            _activate[family_type] = True
            kw["activate"] = activate

        if inbound_soft_reconfiguration is not None:
            _inbound_soft_reconfiguration[family_type] = True
            kw["inbound_soft_reconfiguration"] = inbound_soft_reconfiguration

        if route_reflector_client is not None:
            _route_reflector_client[family_type] = True
            kw["route_reflector_client"] = route_reflector_client

        if send_community is not None:
            _send_community[family_type] = send_community
            kw["send_community"] = send_community

        if update_source:
            kw["update_source"] = update_source

        if remote_as:
            kw["remote_as"] = remote_as

        bgp_neighbor_obj = self.session.api.get_module(
            self.session,
            "BgpNeighbor",
            ip_or_ifname_or_group_name,
            parent_bgp_router=self,
            **kw
        )

        # Try to obtain data; if not, create
        try:
            bgp_neighbor_obj.get()
            for key, val in kw.items():
                setattr(bgp_neighbor_obj, key, val)
        except GenericOperationError:
            pass  # not an error, just doesn't exist yet
        finally:
            bgp_neighbor_obj.apply()

        return bgp_neighbor_obj
