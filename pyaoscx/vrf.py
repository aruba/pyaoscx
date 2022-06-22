# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.device import Device

from pyaoscx.pyaoscx_module import PyaoscxModule


class Vrf(PyaoscxModule):
    """
    Provide configuration management for VRF on AOS-CX devices.
    """

    base_uri = "system/vrfs"
    indices = ["name"]
    resource_uri_name = "vrfs"

    bgp_routers = ListDescriptor("bgp_routers")
    address_families = ListDescriptor("address_families")
    ospf_routers = ListDescriptor("ospf_routers")
    ospfv3_routers = ListDescriptor("ospfv3_routers")
    static_routes = ListDescriptor("static_routes")

    def __init__(self, session, name, uri=None, **kwargs):

        self.session = session
        self._uri = uri
        self.name = name
        # List used to determine attributes related to the VRF configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)

        # Use to manage BGP Routers
        self.bgp_routers = []
        # Use to manage Vrf Address Families
        self.address_families = []
        # Use to manage OSPF Routers
        self.ospf_routers = []
        # Use to manage OSPFv3 Routers
        self.ospfv3_routers = []
        # Use to manage Static Routes
        self.static_routes = []
        # Attribute used to know if object was changed recently
        self.__modified = False

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a VRF table entry and fill the
            class with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information
            to return.
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

        uri = "{0}/{1}".format(Vrf.base_uri, self.name)

        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)
        # Delete unwanted data
        if "ospf_routers" in data:
            data.pop("ospf_routers")
        if "ospfv3_routers" in data:
            data.pop("ospfv3_routers")
        if "ospf_routers" in data or "ospfv3_routers" in data:
            data.pop("bgp_routers")
        if "static_routes" in data:
            data.pop("static_routes")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the VRF is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            unwanted_attributes = [
                "name",
                "type",
                "bgp_routers",
                "ospf_routers",
                "ospfv3_routers",
                "vrf_address_families",
                "static_routes",
            ]
            utils.set_config_attrs(
                self, data, "config_attrs", unwanted_attributes
            )
        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "name" in self.__original_attributes:
            self.__original_attributes.pop("name")
        # Remove type
        if "type" in self.__original_attributes:
            self.__original_attributes.pop("type")
        # Remove bgp_routers
        if "bgp_routers" in self.__original_attributes:
            self.__original_attributes.pop("bgp_routers")
        # Remove ospf_routers
        if "ospf_routers" in self.__original_attributes:
            self.__original_attributes.pop("ospf_routers")
        # Remove static_routes
        if "static_routes" in self.__original_attributes:
            self.__original_attributes.pop("static_routes")
        # Remove vrf_address_families
        if "vrf_address_families" in self.__original_attributes:
            self.__original_attributes.pop("vrf_address_families")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        device = Device(self.session)
        if not device.materialized:
            device.get()

        # Clean BGP Router settings
        if "bgp" in device.capabilities and self.bgp_routers == []:
            # gotta use deferred import to avoid cyclical import error
            from pyaoscx.bgp_router import BgpRouter

            # Set BGP Routers if any
            # Adds bgp_bouters to parent Vrf object
            bgp_routers = BgpRouter.get_all(self.session, self)
            for bgp_router in bgp_routers.values():
                self.bgp_routers.append(bgp_router)

        # Clean Address Families settings
        if self.address_families == []:
            # gotta use deferred import to avoid cyclical import error
            from pyaoscx.vrf_address_family import VrfAddressFamily

            # Set Address Families if any
            # Adds address_families to parent Vrf object
            address_families = VrfAddressFamily.get_all(self.session, self)
            for address_family in address_families.values():
                self.address_families.append(address_family)

        # Clean OSPF Routers settings
        if "ospfv2" in device.capabilities and self.ospf_routers == []:
            # gotta use deferred import to avoid cyclical import error
            from pyaoscx.ospf_router import OspfRouter

            # Set OSPF Routers if any
            # Adds ospf_routers to parent Vrf object
            ospfv2_routers = OspfRouter.get_all(self.session, self)
            for ospfv2_router in ospfv2_routers.values():
                self.ospf_routers.append(ospfv2_router)

        # If no OSPFv3 Routers are present
        if "ospfv3" in device.capabilities and self.ospfv3_routers == []:
            # gotta use deferred import to avoid cyclical import error
            from pyaoscx.ospfv3_router import Ospfv3Router

            # Add all ospfv3_routers (if any) to parent Vrf object
            ospfv3_routers = Ospfv3Router.get_all(self.session, self)
            for ospfv3_router in ospfv3_routers.values():
                self.ospfv3_routers.append(ospfv3_router)

        # Clean Static Routess settings
        if self.static_routes == []:
            # gotta use deferred import to avoid cyclical import error
            from pyaoscx.static_route import StaticRoute

            # Set Static Route if any
            # Adds static_routes to parent Vrf object
            static_routes = StaticRoute.get_all(self.session, self)
            for static_route in static_routes.values():
                self.static_routes.append(static_route)

        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system VRFs and create a dictionary
            containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing VRF names as keys and a Vrf objects as
            values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", Vrf.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        vrfs_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create Vrf object
            name, vrf = Vrf.from_uri(session, uri)
            # Set VRF in dictionary
            vrfs_dict[name] = vrf

        return vrfs_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing VRF table
            entry. Checks whether the VRF exists in the switch. Calls
            self.update() if VRF is being updated. Calls self.create() if a new
            VRF is being created.
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
        Perform a PUT call to apply changes to an existing VRF table entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        vrf_data = utils.get_attrs(self, self.config_attrs)

        uri = "{0}/{1}".format(Vrf.base_uri, self.name)

        # Compare dictionaries
        # if vrf_data == self.__original_attributes:
        if json.dumps(vrf_data, sort_keys=True, indent=4) == json.dumps(
            self.__original_attributes, sort_keys=True, indent=4
        ):
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(vrf_data)

            try:
                response = self.session.request("PUT", uri, data=post_data)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code
                )

            logging.info("SUCCESS: Adding %s", self)
            # Set new original attributes
            self.__original_attributes = vrf_data
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new VRF using the object's attributes
            as POST body. Only returns if no exception is raised.
        :return modified: Boolean, True if entry was created
        """
        vrf_data = utils.get_attrs(self, self.config_attrs)

        vrf_data["name"] = self.name

        post_data = json.dumps(vrf_data)
        try:
            response = self.session.request(
                "POST", Vrf.base_uri, data=post_data
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all objects data
        self.get()

        # Object was modified
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete VRF table entry.
        """
        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

        uri = "{0}/{1}".format(Vrf.base_uri, self.name)

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Vrf object given a response_data related to the Vrf object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
                "test_vrf": "/rest/v10.04/system/vrfs/test_vrf"
            }
        :return: Vrf object
        """
        # An interfaces's VRF is returned with an empty index in some
        # switch models (confirmed with a 4100), this empty index causes a
        # subsequent GET request to fail, because the constructed URI is
        # not correct, this may be due to these models supporting a single
        # VRF. This behavior occurs with the default VRF, so it's safe to
        # use 'default' when the value gotten in the response is the empty
        # string
        # TODO: determine if this is correct/intended behavior to take into
        # account for a possible refactor/rework to check for this earlier
        if next(iter(response_data)) == "":
            vrf_name = "default"
        else:
            vrf_name_arr = session.api.get_keys(
                response_data, cls.resource_uri_name
            )
            vrf_name = vrf_name_arr[0]
        return cls(session, vrf_name)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Vrf object given a VRF URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return name, vrf_obj: tuple containing both the VRF's name and a Vrf
            object.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)vrfs/(?P<index>.+)")
        name = index_pattern.match(uri).group("index")
        # Create vlan object
        vrf_obj = Vrf(session, name, uri=uri)

        return name, vrf_obj

    @classmethod
    def get_facts(cls, session):
        """
        Modify this to Perform a GET call to retrieve all VRFs and their
            respective data.
        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return facts: Dictionary containing VRF IDs as keys and VRF objects as
            values.
        """
        logging.info("Retrieving switch VRF facts")

        # Set VRF facts depth
        vrf_depth = session.api.default_facts_depth

        # Build URI
        uri = "{0}?depth={1}".format(Vrf.base_uri, vrf_depth)

        try:
            # Try to get facts data via GET method
            response = session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load response text into json format
        facts = json.loads(response.text)

        return facts

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific VRF URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                Vrf.base_uri,
                self.name,
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

    def __str__(self):
        return "VRF name: '{0}'".format(self.name)

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

    def add_address_family(
        self, family_type="ipv4_unicast", export_target=[], import_targets=[]
    ):
        """
        Add a VRF Address Family to the current Vrf object.
        :param family_type: Alphanumeric type of the Address Family.
            The options are 'ipv4_unicast' and 'ipv6_unicast'.
            The default value is set to 'ipv4_unicast'.
        :param export_target: Optional list of export route targets.
        :param import_targets: Optional list of import route targets
        :return address_family: VrfAddressFamily Object
        """
        if not self.materialized:
            raise VerificationError(
                "VRF {0}".format(self.name), "Object not materialized"
            )

        # Verify if incoming address is a string
        if isinstance(family_type, str):
            # Create Vrf_Family_Address object -- add it to it's internal
            # address_families
            vrf_address_family = self.session.api.get_module(
                self.session,
                "VrfAddressFamily",
                family_type,
                parent_vrf=self,
                export_route_targets=export_target,
                import_route_targets=import_targets,
                route_map={},
            )
            # Try to get data, if non existent create
            try:
                # Try to obtain vrf_address_family address data
                vrf_address_family.get()
            # If vrf_address_family object is non existent, create it
            except GenericOperationError:
                # Create vrf_address_family inside switch
                vrf_address_family.apply()
            self.address_families.append(vrf_address_family)

        # Apply changes inside switch
        self.apply()

        return vrf_address_family

    def delete_address_family(self, family_type="ipv4_unicast"):
        """
        Given an address family type, delete that address from the current Vrf.
        :param family_type: Alphanumeric type of the Address Family.
            The options are 'ipv4_unicast' and 'ipv6_unicast'.
            A VrfAddressFamily object is accepted.
            The default value is set to 'ipv4_unicast'.
        """
        if not self.materialized:
            raise VerificationError(
                "VRF {0}".format(self.name), "Object not materialized"
            )
        # gotta use deferred import to avoid cyclical import error
        from pyaoscx.vrf_address_family import VrfAddressFamily

        # Verify if incoming address is a object
        if isinstance(family_type, VrfAddressFamily):
            # Obtain address
            family_type = family_type.address_family

        # Iterate through every address inside interface
        for add_family_obj in self.address_families:
            if add_family_obj.address_family == family_type:
                # Removing address does an internal delete
                self.address_families.remove(add_family_obj)

        self.apply()

    def setup_dns(
        self,
        domain_name=None,
        domain_list=None,
        domain_servers=None,
        host_v4_address_mapping=None,
        host_v6_address_mapping=None,
    ):
        """
        Setup DNS client configuration within a VRF.
        :param domain_name: Domain name used for name resolution by the DNS
            client, if 'dns_domain_list' is not configured.
        :param domain_list: dict of DNS Domain list names to be used for
            address resolution, keyed by the resolution priority order.
            Example:
                {
                    0: "hpe.com"
                    1: "arubanetworks.com"
                }
        :param domain_servers: dict of DNS Name servers to be used for address
            resolution, keyed by the resolution priority order. Example:
                {
                    0: "4.4.4.10"
                    1: "4.4.4.12"
                }
        :param host_v4_address_mapping: dict of static host
            address configurations and the IPv4 address associated with them.
            Example:
                {
                    "host1": "5.5.44.5"
                    "host2": "2.2.44.2"
                }
        :param host_v6_address_mapping: dict of static host address
            configurations and the IPv6 address associated with them. Example:
                {
                    "host1": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
                }
        :return modified: Returns True if modified.
        """
        # Update Values

        if domain_name is not None:
            self.dns_domain_name = domain_name

        if domain_list is not None:
            self.dns_domain_list = domain_list

        if domain_servers is not None:
            self.dns_name_servers = domain_servers

        if host_v4_address_mapping is not None:
            self.dns_host_v4_address_mapping = host_v4_address_mapping

        if host_v6_address_mapping is not None:
            self.dns_host_v6_address_mapping = host_v6_address_mapping

        return self.apply()

    def delete_dns(
        self,
        domain_name=None,
        domain_list=None,
        domain_servers=None,
        host_v4_address_mapping=None,
        host_v6_address_mapping=None,
    ):
        """
        Delete DNS client configuration within a Vrf object.
        :param domain_name: If value is not None, it is deleted
        :param domain_list: If value is not None, it is deleted
        :param domain_servers: If value is not None, it is deleted
        :param host_v4_address_mapping: If value is not None, it is deleted
        :param host_v6_address_mapping: If value is not None, it is deleted
        :return modified: Returns True if modified.
        """
        # Update Values

        if domain_name is not None:
            self.dns_domain_name = None

        if domain_list is not None:
            self.dns_domain_list = None

        if domain_servers is not None:
            self.dns_name_servers = None

        if host_v4_address_mapping is not None:
            self.dns_host_v4_address_mapping = None

        if host_v6_address_mapping is not None:
            self.dns_host_v6_address_mapping = None

        return self.apply()

    def update_ospf_routers(self, router):
        """
        Update references to OSPF Routers. If a Router with the same instance
            tag is found, update the reference to the new router, otherwise,
            add reference to the new router.
        """
        routers = getattr(self, router.resource_uri_name)
        for r in routers:
            if r.instance_tag == router.instance_tag:
                # Make list element point to current object
                # See utils.list_attributes.ListDescriptor
                r = router
                return
        routers.append(router)

    def remove_ospf_router(self, router):
        """
        Update references to OSPF Routers. If a Router with the same instance
            tag is found, delete the reference to it.
        """
        routers = getattr(self, router.resource_uri_name)
        for r in routers:
            if r.instance_tag == router.instance_tag:
                routers.remove(r)

    def update_bgp_routers(self, router):
        """
        Update references to BGP Routers. If a Router with the same instance
            tag is found, update the reference to the new router, otherwise,
            add reference to the new router.
        """
        routers = getattr(self, router.resource_uri_name)
        for r in routers:
            if r.asn == router.asn:
                # Make list element point to current object
                # See utils.list_attributes.ListDescriptor
                r = router
                return
        routers.append(router)

    def remove_bgp_router(self, router):
        """
        Update references to BGP Routers. If a Router with the same instance
            tag is found, delete the reference to it.
        """
        routers = getattr(self, router.resource_uri_name)
        for r in routers:
            if r.asn == router.asn:
                routers.remove(r)
