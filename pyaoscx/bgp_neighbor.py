# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class BgpNeighbor(PyaoscxModule):
    """
    Provide configuration management for BGP Neighbor on AOS-CX devices.
    """

    indices = ["ip_or_ifname_or_group_name"]
    resource_uri_name = "bgp_neighbors"

    def __init__(
        self,
        session,
        ip_or_ifname_or_group_name,
        parent_bgp_router,
        uri=None,
        **kwargs
    ):

        self.session = session
        # Assign ID
        self.ip_or_ifname_or_group_name = ip_or_ifname_or_group_name
        # Assign parent BGP Router
        self.__set_bgp_router(parent_bgp_router)
        self._uri = uri
        # List used to determine attributes related to the BGP configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_bgp_router(self, parent_bgp_router):
        """
        Set parent BgpRouter object as an attribute for the BGP class
        :param parent_bgp_router a BgpRouter object
        """

        # Set parent BGP Router
        self.__parent_bgp_router = parent_bgp_router

        # Set URI
        self.base_uri = "{0}/{1}/bgp_neighbors".format(
            self.__parent_bgp_router.base_uri, self.__parent_bgp_router.asn
        )

        for bgp_ngh in self.__parent_bgp_router.bgp_neighbors:
            if (
                bgp_ngh.ip_or_ifname_or_group_name
                == self.ip_or_ifname_or_group_name
            ):
                # Make list element point to current object
                bgp_ngh = self
            else:
                # Add self to BGP Neighbors list in parent BGP Router
                self.__parent_bgp_router.bgp_neighbors.append(self)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a BGP Neighbor table
        entry and fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
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

        uri = "{0}/{1}".format(self.base_uri, self.ip_or_ifname_or_group_name)

        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the BGP Neighbor is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["ip_or_ifname_or_group_name"]
            )

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "ip_or_ifname_or_group_name" in self.__original_attributes:
            self.__original_attributes.pop("ip_or_ifname_or_group_name")

        # If the BGP Neighbor has a local_interface inside the switch
        if hasattr(self, "local_interface") and self.local_interface:
            local_interface_response = self.local_interface
            interface_cls = self.session.api.get_module(
                self.session, "Interface", ""
            )
            # Set port as a Interface Object
            self.local_interface = interface_cls.from_response(
                self.session, local_interface_response
            )
            self.local_interface.get()

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_bgp_router):
        """
        Perform a GET call to retrieve all system BGP Neighbors inside a BGP
        Router, and create a dictionary containing them
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_bgp_router: parent BgpRouter object where BGP Neighbor
            is stored
        :return: Dictionary containing BGP Neighbors IDs as keys and a BGP
            Neighbors objects as values
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/{1}/bgp_neighbors".format(
            parent_bgp_router.base_uri, parent_bgp_router.asn
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        bgp_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a BgpNeighbor object
            ip_or_ifname_or_group_name, bgp_neighbor = BgpNeighbor.from_uri(
                session, parent_bgp_router, uri
            )
            # Load all BGP Neighbor data from within the Switch
            bgp_neighbor.get()
            bgp_dict[ip_or_ifname_or_group_name] = bgp_neighbor

        return bgp_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing BGP Neighbor.
            Checks whether the BGP Neighbor exists in the switch. Calls
            self.update() if BGP Neighbor is being updated. Calls self.create()
            if a new BGP Neighbor is being created.
        :return modified: Boolean, True if object was created or modified.
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

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing BGP Neighbor.
        :return modified: True if Object was modified and a PUT request
            was made.
        """
        # Variable returned
        modified = False

        bgp_neighbor_data = utils.get_attrs(self, self.config_attrs)

        # Get ISL port uri
        if self.local_interface is not None:
            bgp_neighbor_data[
                "local_interface"
            ] = self.local_interface.get_info_format()

        uri = "{0}/{1}".format(self.base_uri, self.ip_or_ifname_or_group_name)

        # Compare dictionaries
        if bgp_neighbor_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            put_data = json.dumps(bgp_neighbor_data)

            try:
                response = self.session.request("PUT", uri, data=put_data)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code
                )

            logging.info("SUCCESS: Updating %s", self)
            # Set new original attributes
            self.__original_attributes = bgp_neighbor_data
            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new BGP Neighbor table entry
        Only returns if an exception is not raise

        :return modified: Boolean, True if entry was created

        """
        bgp_neighbor_data = utils.get_attrs(self, self.config_attrs)
        bgp_neighbor_data[
            "ip_or_ifname_or_group_name"
        ] = self.ip_or_ifname_or_group_name

        if hasattr(self, "local_interface"):

            # If local interface is NOT a string
            if not isinstance(self.local_interface, str):
                if not self.local_interface.materialized:
                    raise VerificationError(
                        "Local Interface", "Object not materialized"
                    )

                # Get ISL port uri
                bgp_neighbor_data[
                    "local_interface"
                ] = self.local_interface.get_info_format()

        post_data = json.dumps(bgp_neighbor_data)

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

        # Object was modified, as it was created inside Device
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete  BGP Neighbor table entry.

        """

        uri = "{0}/{1}".format(self.base_uri, self.ip_or_ifname_or_group_name)

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

        # Delete back reference from BGP_Routers
        for neighbor in self.__parent_bgp_router.bgp_neighbors:
            if (
                neighbor.ip_or_ifname_or_group_name
                == self.ip_or_ifname_or_group_name
            ):
                self.__parent_bgp_router.bgp_neighbors.remove(neighbor)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_bgp_router, response_data):
        """
        Create a  BgpNeighbor object given a response_data related to the
        BGP Router ID object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_bgp_router: parent BgpRouter object where BGP
            Neighbor is stored
        :param response_data: The response can be either a
            dictionary: {
                    id: "/rest/v10.04/system/vrfs/<vrf_name>/bgp_routers/asn
                        /bgp_neighbors/id"
                }
            or a
            string: "/rest/v10.04/system/vrfs/<vrf_name>/bgp_routers/asn/
                bgp_neighbors/id"
        :return: BgpNeighbor object
        """
        bgp_arr = session.api.get_keys(
            response_data, BgpNeighbor.resource_uri_name
        )
        bgp_neighbor_id = bgp_arr[0]
        return BgpNeighbor(session, bgp_neighbor_id, parent_bgp_router)

    @classmethod
    def from_uri(cls, session, parent_bgp_router, uri):
        """
        Create a BgpNeighbor object given a URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_bgp_router: parent BgpRouter object where BGP Neighbor
            is stored
        :param uri: a String with a URI

        :return index, bgp_obj: tuple containing both the BGP object and the
            BGP's ID
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)bgp_neighbors/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create BGP object
        bgp_obj = BgpNeighbor(session, index, parent_bgp_router, uri=uri)

        return index, bgp_obj

    def __str__(self):
        return "Bgp Neighbor ID {0}".format(self.ip_or_ifname_or_group_name)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific BGP Neighbor URI
        return: Object's URI
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
                self.ip_or_ifname_or_group_name,
            )

        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
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
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified.
        """
        return self.modified
