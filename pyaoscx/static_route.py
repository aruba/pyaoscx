# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from urllib.parse import quote_plus, unquote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.static_nexthop import StaticNexthop

from pyaoscx.pyaoscx_module import PyaoscxModule


class StaticRoute(PyaoscxModule):
    """
    Provide configuration management for Static Route on AOS-CX devices.
    """

    indices = ["prefix"]
    static_nexthops = ListDescriptor("static_nexthops")
    resource_uri_name = "static_routes"

    def __init__(self, session, prefix, parent_vrf, uri=None, **kwargs):

        self.session = session
        # Assign IP
        self.prefix = unquote_plus(prefix)
        self.reference_address = quote_plus(self.prefix)
        self.address_family = utils.get_ip_version(self.prefix)
        # Assign parent Vrf object
        self.__set_vrf(parent_vrf)
        self._uri = uri
        # List used to determine attributes related to the Static Route
        # configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage Ospf routers
        self.static_nexthops = []

        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_vrf(self, parent_vrf):
        """
        Set parent Vrf object as an attribute for the StaticRoute object.
        :param parent_vrf: a Vrf object.
        """
        # Set parent Vrf object
        self.__parent_vrf = parent_vrf

        # Set URI
        self.base_uri = "{0}/{1}/static_routes".format(
            self.__parent_vrf.base_uri,
            self.__parent_vrf.name,
        )

        # Verify Static Route doesn't exist already inside VRF
        for static_route in self.__parent_vrf.static_routes:
            if static_route.prefix == self.prefix:
                # Make list element point to current object
                static_route = self
            else:
                # Add self to static_routes list in parent Vrf object
                self.__parent_vrf.static_routes.append(self)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Static Route table entry and
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

        uri = "{0}/{1}".format(self.base_uri, self.reference_address)
        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)
        # Delete unwanted data
        if "static_nexthops" in data:
            data.pop("static_nexthops")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the Static Route is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["prefix", "static_nexthops"]
            )

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "prefix" in self.__original_attributes:
            self.__original_attributes.pop("prefix")
        # Remove Static Nexthops
        if "static_nexthops" in self.__original_attributes:
            self.__original_attributes.pop("static_nexthops")

        # Clean Static Nexthops settings
        if self.static_nexthops == []:
            # Set Static Nexthops if any
            # Adds Static Nexthop to parent Vrf object
            StaticNexthop.get_all(self.session, self)

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session, parent_vrf):
        """
        Perform a GET call to retrieve all system Static Routes inside a VRF,
            and create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: parent Vrf object where vrf is stored.
        :return: Dictionary containing Static Route IDs as keys and a Static
            Route objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/{1}/static_routes".format(
            parent_vrf.base_uri, parent_vrf.name
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        static_route_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a StaticRoute object and adds it to parent_vrf list
            prefix, static_route = StaticRoute.from_uri(
                session, parent_vrf, uri
            )
            # Load all Static Route data from within the Switch
            static_route.get()
            static_route_dict[prefix] = static_route

        return static_route_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create a new or update an existing Static
            Route table entry. Checks whether the Static Route exists in the
            switch. Calls self.update() if object being updated. Calls
            self.create() if a new Static Route is being created.
        :return modified: Boolean, True if object was created or modified.
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
        Perform a PUT call to apply changes to an existing Static Route table
            entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Variable returned
        modified = False

        static_route_data = utils.get_attrs(self, self.config_attrs)

        uri = "{0}/{1}".format(self.base_uri, self.reference_address)

        # Compare dictionaries
        if static_route_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(static_route_data)

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
            self.__original_attributes = static_route_data

            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Static Route table entry. Only
            returns if no exception is raised.
        :return: Boolean, True if entry was created
        """
        # Add 'address_family' as a config attribute and remove duplicates
        self.config_attrs.append("address_family")
        self.config_attrs = list(set(self.config_attrs))

        static_route_data = utils.get_attrs(self, self.config_attrs)
        static_route_data["prefix"] = self.prefix
        static_route_data["vrf"] = self.__parent_vrf.get_uri()

        post_data = json.dumps(static_route_data)

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
        Perform DELETE call to delete specified Static Route table entry.
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
        for static_route in self.__parent_vrf.static_routes:
            if static_route.prefix == self.prefix:
                self.__parent_vrf.static_routes.remove(static_route)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vrf, response_data):
        """
        Create a StaticRoute object given a response_data related to the Static
            Route prefix object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: parent Vrf object where Static Route is stored.
        :param response_data: The response must be a dictionary of the form:
            {
                prefix: "/rest/v10.04/system/vrfs/static_routes/prefix"
            }
        :return: Static Route Object.
        """
        static_route_arr = session.api.get_keys(
            response_data, StaticRoute.resource_uri_name
        )
        prefix = static_route_arr[0]
        return StaticRoute(session, prefix, parent_vrf)

    @classmethod
    def from_uri(cls, session, parent_vrf, uri):
        """
        Create a StaticRoute object given a URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: parent Vrf object where Static Route is stored.
        :param uri: a String with a URI.
        :return index, static_route: tuple containing both the static_route
            object and the static_route's prefix.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)static_routes/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create StaticRoute object
        static_route_obj = StaticRoute(session, index, parent_vrf, uri=uri)

        return index, static_route_obj

    def __str__(self):
        return "Static Route: {0}".format(self.prefix)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific static route URI.
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
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def add_static_nexthop(
        self,
        next_hop_ip_address=None,
        next_hop_interface=None,
        distance=None,
        nexthop_type=None,
        bfd_enable=None,
    ):
        """
        Create a Static Nexthop, with a VRF and a Destination Address related
            to a Static Route.
        :param next_hop_ip_address: The IPv4 address or the IPv6 address of
            next hop.
            Example:
                '1.1.1.1'
                or
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param next_hop_interface: The interface through which the next hop
            can be reached.
        :param distance: Administrative distance to be used for the next
            hop in the static route instead of default value.
        :param nexthop_type: Specifies whether the static route is a forward,
            blackhole or reject route.
        :param bfd_enable: Boolean to enable BFD.
        :return: StaticNexthop object.
        """
        if distance is None:
            distance = 1
        # Set variable
        next_hop_interface_obj = None
        if next_hop_interface is not None:
            next_hop_interface_obj = self.session.api.get_module(
                self.session, "Interface", next_hop_interface
            )

        if nexthop_type is None:
            nexthop_type = "forward"

        if nexthop_type == "forward":
            bfd_enable = False

        static_nexthop_obj = self.session.api.get_module(
            self.session,
            "StaticNexthop",
            0,
            parent_static_route=self,
        )

        # Try to obtain data; if not, create
        try:
            static_nexthop_obj.get()
            # Delete previous static nexthop
            static_nexthop_obj.delete()
        except GenericOperationError:
            # Catch error
            pass

        finally:
            static_nexthop_obj = self.session.api.get_module(
                self.session,
                "StaticNexthop",
                0,
                parent_static_route=self,
                ip_address=next_hop_ip_address,
                distance=distance,
                port=next_hop_interface_obj,
                type=nexthop_type,
                bfd_enable=bfd_enable,
            )
            # Create object inside switch
            static_nexthop_obj.apply()

        return static_nexthop_obj
