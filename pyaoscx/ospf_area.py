# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.pyaoscx_module import PyaoscxModule
from pyaoscx.ospf_interface import OspfInterface
from pyaoscx.utils.connection import connected

import json
import logging
import re
import pyaoscx.utils.util as utils
from pyaoscx.utils.list_attributes import ListDescriptor


class OspfArea(PyaoscxModule):
    """
    Provide configuration management for OSPF Area instance on AOS-CX devices.
    """

    indices = ["area_id"]
    resource_uri_name = "areas"

    # Use to manage references
    ospf_interfaces = ListDescriptor("ospf_interfaces")

    def __init__(self, session, area_id, parent_ospf_router, uri=None,
                 **kwargs):

        self.session = session
        # Assign ID
        self.area_id = area_id
        # Assign parent OSPF Router
        self.__set_ospf_router(parent_ospf_router)
        self._uri = uri
        # List used to determine attributes related to the OPSF configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage OSPF Interfaces
        self.ospf_interfaces = []
        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_ospf_router(self, parent_ospf_router):
        """
        Set parent OSPF Router as an attribute for the OspfArea object
        :param parent_ospf_router a OspfRouter object where OSPF Area
            is stored
        """

        # Set parent OSPF router
        self.__parent_ospf_router = parent_ospf_router

        # Set URI
        self.base_uri = \
            "{base_ospf_router_uri}/{ospf_router_instance_tag}/areas".format(
                base_ospf_router_uri=self.__parent_ospf_router.base_uri,
                ospf_router_instance_tag=(
                    self.__parent_ospf_router.instance_tag))

        for ospf_area in self.__parent_ospf_router.areas:
            if ospf_area.area_id == self.area_id:
                # Make list element point to current object
                ospf_area = self
            else:
                # Add self to OSPF Routers list in parent OSPF Router
                self.__parent_ospf_router.areas.append(self)

    @connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a OSPF Area table entry and
        fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        """
        logging.info("Retrieving the switch OSPF Areas")

        depth = self.session.api_version.default_depth if depth is None \
            else depth
        selector = self.session.api_version.default_selector if selector is \
            None else selector

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

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id=self.area_id
        )

        try:
            response = self.session.s.get(
                uri, verify=False, params=payload, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Delete unwanted data
        if "ospf_interfaces" in data:
            data.pop("ospf_interfaces")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the OSPF Area is configurable
        if selector in self.session.api_version.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", ["area_id"])

        # Set original attributes
        self.__original_attributes = data

        # Remove ID
        if "area_id" in self.__original_attributes:
            self.__original_attributes.pop("area_id")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        # Clean areas
        if self.ospf_interfaces == []:
            # Set Areas if any
            # Adds OSPF Interface to parent OSPF Area already
            OspfInterface.get_all(self.session, self)

        return True

    @classmethod
    def get_all(cls, session, parent_ospf_router):
        """
        Perform a GET call to retrieve all system OSPF Area inside a
        OPSF Router, and create a dictionary containing them
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_ospf_router: parent OPSF Router object where OPSF Area
            is stored
        :return: Dictionary containing OSPF Area IDs as keys and a OSPF
            Area objects as values
        """

        logging.info("Retrieving the switch OSPF Area")

        base_uri = \
            "{base_ospf_router_uri}/{ospf_router_instance_tag}/areas".format(
                base_ospf_router_uri=parent_ospf_router.base_uri,
                ospf_router_instance_tag=parent_ospf_router.instance_tag)

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

        ospf_area_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api_version.get_uri_from_data(data)

        for uri in uri_list:
            # Create an OspfArea object
            area_id, ospf_area = OspfArea.from_uri(
                session, parent_ospf_router, uri)
            # Load all OSPF Router data from within the Switch
            ospf_area.get()
            ospf_area_dict[area_id] = ospf_area

        return ospf_area_dict

    @connected
    def apply(self):
        """
        Main method used to either create or update an existing
        Ospf Area table entry.
        Checks whether the OSPF Area exists in the switch
        Calls self.update() if OSPF Area is being updated
        Calls self.create() if a new OSPF Area is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        """
        if not self.__parent_ospf_router.materialized:
            self.__parent_ospf_router.apply()

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
        Perform a PUT call to apply changes to an existing OSPF Area table
        entry

        :return modified: True if Object was modified and a PUT request was
            made. False otherwise
        """
        # Variable returned
        modified = False

        ospf_area_data = {}

        ospf_area_data = utils.get_attrs(self, self.config_attrs)

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id=self.area_id
        )

        # Compare dictionaries
        if ospf_area_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(ospf_area_data, sort_keys=True, indent=4)

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
                    "SUCCESS: Update osf area table entry {} success".format(
                        self.area_id))
            # Set new original attributes
            self.__original_attributes = ospf_area_data
            # Object was modified
            modified = True
        return modified

    @connected
    def create(self):
        """
        Perform a POST call to create a new OSPF Area
        Only returns if an exception is not raise

        :return modified: Boolean, True if entry was created
        """
        ospf_area_data = {}

        ospf_area_data = utils.get_attrs(self, self.config_attrs)
        ospf_area_data["area_id"] = self.area_id

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri
        )
        post_data = json.dumps(ospf_area_data, sort_keys=True, indent=4)

        try:
            response = self.session.s.post(
                uri, verify=False, data=post_data, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info(
                "SUCCESS: Adding OSPF Area table entry {} succeeded".format(
                    self.area_id))

        # Get all object's data
        self.get()
        # Object was created, thus modified
        return True

    @connected
    def delete(self):
        """
        Perform DELETE call to delete OSPF Area table entry.

        """

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id=self.area_id
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
                "SUCCESS: Delete OSPF Area table entry {} succeeded".format(
                    self.area_id))

        # Delete back reference from ospf_routers
        for area in self.__parent_ospf_router.areas:
            if area.area_id == self.area_id:
                self.__parent_ospf_router.areas.remove(area)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_ospf_router, response_data):
        """
        Create an OspfArea object given a response_data related to the ospf
            router ID object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_ospf_router: parent OspfRouter object where OspfArea
            object is stored
        :param response_data: The response can be either a
        dictionary: {
                id: "/rest/v10.04/system/vrfs/<vrf_name>/ospf_routers/
                instance_tag/areas/area_id"
            }
        or a
        string: "/rest/v10.04/system/vrfs/<vrf_name>/ospf_routers/
            instance_tag/areas/area_id"
        :return: OspfArea object

        """
        ospf_area_arr = session.api_version.get_keys(
            response_data, OspfArea.resource_uri_name)
        ospf_area_id = ospf_area_arr[0]
        return OspfArea(session, ospf_area_id, parent_ospf_router)

    @classmethod
    def from_uri(cls, session, parent_ospf_router, uri):
        """
        Create an OspfArea object given a URI
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_ospf_router: parent OspfRouter object where OspfArea
            object is stored
        :param uri: a String with a URI
        :return index, ospf_area_obj: tuple containing both the OspfArea object
            and the OSPF Area's ID
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)areas/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create OspfArea object
        ospf_area_obj = OspfArea(
            session, index, parent_ospf_router, uri=uri)

        return index, ospf_area_obj

    def __str__(self):
        return "OSPF Area ID {}".format(self.area_id)

    def get_uri(self):
        """
        Method used to obtain the specific OSPF Area URI
        return: Object's URI
        """

        if self._uri is None:
            self._uri = "{resource_prefix}{class_uri}/{id}".format(
                resource_prefix=self.session.resource_prefix,
                class_uri=self.base_uri,
                id=self.area_id
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
