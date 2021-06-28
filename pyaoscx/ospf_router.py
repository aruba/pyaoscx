# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re
import pyaoscx.utils.util as utils
import pyaoscx.interface as interface_mod


from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.pyaoscx_module import PyaoscxModule

from pyaoscx.ospf_area import OspfArea
from pyaoscx.utils.connection import connected

from pyaoscx.utils.list_attributes import ListDescriptor


class OspfRouter(PyaoscxModule):
    """
    Provide configuration management for an OSPF routing protocol on AOS-CX
    devices.
    """

    indices = ["instance_tag"]
    resource_uri_name = "ospf_routers"

    # Use to manage references
    areas = ListDescriptor("areas")

    def __init__(self, session, instance_tag, parent_vrf, uri=None, **kwargs):

        self.session = session
        # Assign ID
        self.instance_tag = instance_tag
        # Assign parent Vrf object
        self.__set_vrf(parent_vrf)
        self._uri = uri
        # List used to determine attributes related to the OSPF
        # configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage Areas
        self.areas = []
        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_vrf(self, parent_vrf):
        """
        Set parent Vrf object as an attribute for the OspfRouter object
        :param parent_vrf a Vrf object
        """

        # Set parent Vrf object
        self.__parent_vrf = parent_vrf

        # Set URI
        self.base_uri = "{base_vrf_uri}/{vrf_name}/ospf_routers".format(
            base_vrf_uri=self.__parent_vrf.base_uri,
            vrf_name=self.__parent_vrf.name)

        # Verify OSPF Router instance doesn't exist already inside VRF
        for ospf_router in self.__parent_vrf.ospf_routers:
            if ospf_router.instance_tag == self.instance_tag:
                # Make list element point to current object
                ospf_router = self
            else:
                # Add self to ospf_routers list in parent Vrf object
                self.__parent_vrf.ospf_routers.append(self)

    @connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a OSPF Router table entry and
        fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        """
        logging.info("Retrieving the switch OSPF Router information")

        depth = self.session.api_version.default_depth \
            if depth is None else depth
        selector = self.session.api_version.default_selector \
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

        uri = "{base_url}{class_uri}/{instance_tag}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            instance_tag=self.instance_tag
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
        if "areas" in data:
            data.pop("areas")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the OSPF Router is configurable
        if selector in self.session.api_version.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["instance_tag"])

        # Set original attributes
        self.__original_attributes = data

        # Remove ID
        if "instance_tag" in self.__original_attributes:
            self.__original_attributes.pop("instance_tag")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        # Set a list of passive_interfaces as an attribute
        if hasattr(self, "passive_interfaces") and \
                self.passive_interfaces is not None:
            interfaces_list = []
            # Get all URI elements in the form of a list
            uri_list = self.session.api_version.get_uri_from_data(
                self.passive_interfaces)

            for uri in uri_list:
                # Create an Interface object
                name, interface = interface_mod.Interface.from_uri(self.session, uri)

                # Materialize interface
                interface.get()

                # Add interface to list
                interfaces_list.append(interface)

            # Set list as Interfaces
            self.passive_interfaces = interfaces_list

        # Clean OSPF Area settings
        if self.areas == []:
            # Set Areas if any
            # Adds Area to parent OspfRouter
            OspfArea.get_all(self.session, self)
        return True

    @classmethod
    def get_all(cls, session, parent_vrf):
        """
        Perform a GET call to retrieve all system OSPF settings for a
        given VRF, and create a dictionary containing them
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent Vrf object where OspfRouter object is stored
        :return: Dictionary containing OSPF Router IDs as keys and a OspfRouter
            objects as values
        """

        logging.info("Retrieving the switch OSPF Router data")

        base_uri = "{base_vrf_uri}/{vrf_name}/ospf_routers".format(
            base_vrf_uri=parent_vrf.base_uri,
            vrf_name=parent_vrf.name)

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

        ospf_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api_version.get_uri_from_data(data)

        for uri in uri_list:
            # Create a OspfRouter object and adds it to parent Vrf object list
            instance_tag, ospf = OspfRouter.from_uri(session, parent_vrf, uri)
            # Load all OSPF Router data from within the Switch
            ospf.get()
            ospf_dict[instance_tag] = ospf

        return ospf_dict

    @connected
    def apply(self):
        """
        Main method used to either create update an existing
        OSPF Router Table Entry.
        Checks whether the VRF exists in the switch
        Calls self.update() if OSPF Router is being updated
        Calls self.create() if a new OSPF Router is being created

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

    @connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing OSPF Router table
        entry

        :return modified: True if Object was modified and a PUT request was
            made. False otherwise
        """

        ospf_router_data = {}

        ospf_router_data = utils.get_attrs(self, self.config_attrs)

        # Set passive_interfaces into correct form
        if hasattr(self, "passive_interfaces") and \
                self.passive_interfaces is not None:
            formated_interfaces = {}

            # Set interfaces into correct form
            for element in self.passive_interfaces:
                # Verify object is materialized
                if not element.materialized:
                    raise VerificationError(
                        "Interface {}".format(element.name),
                        "Object inside passive_interfaces not materialized")
                formated_element = element.get_info_format()
                formated_interfaces.update(formated_element)

            # Set values in correct form
            ospf_router_data["passive_interfaces"] = formated_interfaces

        uri = "{base_url}{class_uri}/{instance_tag}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            instance_tag=self.instance_tag
        )

        # Compare dictionaries
        if ospf_router_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(ospf_router_data, sort_keys=True, indent=4)

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
                    "SUCCESS: Update  OSPF Router table entry {} succeeded\
                    ".format(
                        self.instance_tag))
            # Set new original attributes
            self.__original_attributes = ospf_router_data
            # Object was modified
            modified = True
        return modified

    @connected
    def create(self):
        """
        Perform a POST call to create a new  OSPF Router table entry
        Only returns if an exception is not raise

        :return modified: True if entry was created

        """

        ospf_router_data = {}

        ospf_router_data = utils.get_attrs(self, self.config_attrs)
        ospf_router_data["instance_tag"] = self.instance_tag

        # Set passive_interfaces into correct form
        if hasattr(self, "passive_interfaces") \
                and self.passive_interfaces is not None:
            formated_interfaces = {}

            # Set interfaces into correct form
            for element in self.passive_interfaces:
                # Verify object is materialized
                if not element.materialized:
                    raise VerificationError(
                        "Interface {}".format(element.name),
                        "Object inside passive_interfaces not materialized")
                formated_element = element.get_info_format()
                formated_interfaces.update(formated_element)

            # Set values in correct form
            ospf_router_data["passive_interfaces"] = formated_interfaces

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri
        )
        post_data = json.dumps(ospf_router_data, sort_keys=True, indent=4)

        try:
            response = self.session.s.post(
                uri, verify=False, data=post_data, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Adding OSPF table entry {} succeeded\
                ".format(self.instance_tag))

        # Get all object's data
        self.get()
        # Object was created
        return True

    @connected
    def delete(self):
        """
        Perform DELETE call to delete  OSPF Router table entry.

        """

        uri = "{base_url}{class_uri}/{instance_tag}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            instance_tag=self.instance_tag
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
                "SUCCESS: Delete OSPF Router table entry {} succeeded".format(
                    self.instance_tag))

        # Delete back reference from VRF
        for ospf_router in self.__parent_vrf.ospf_routers:
            if ospf_router.instance_tag == self.instance_tag:
                self.__parent_vrf.ospf_routers.remove(ospf_router)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vrf, response_data):
        """
        Create a OspfRouter object given a response_data related to the
            OspfRouter object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent Vrf object where OspfRouter object is stored
        :param response_data: The response can be either a
            dictionary: {
                    instance_tag: "/rest/v10.04/system/vrfs/ospf_routers/
                        instance_tag"
                }
            or a
            string: "/rest/v10.04/system/vrfs/ospf_routers/instance_tag"
        :return: OspfRouter object
        """
        ospf_arr = session.api_version.get_keys(
            response_data, OspfRouter.resource_uri_name)
        instance_tag = ospf_arr[0]
        return OspfRouter(session, instance_tag, parent_vrf)

    @classmethod
    def from_uri(cls, session, parent_vrf, uri):
        """
        Create a OspfRouter object given a URI
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent Vrf object where OspfRouter object is stored
        :param uri: a String with a URI

        :return index, ospf_obj: tuple containing both the OspfRouter object
            and the OSPF Router's instance_tag
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)ospf_routers/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create OspfRouter object
        ospf_obj = OspfRouter(session, index, parent_vrf, uri=uri)

        return index, ospf_obj

    def __str__(self):
        return "OSPF Router ID {}".format(self.instance_tag)

    def get_uri(self):
        """
        Method used to obtain the specific OSPF Router URI
        return: Object's URI
        """

        if self._uri is None:
            self._uri = "{resource_prefix}{class_uri}/{instance_tag}".format(
                resource_prefix=self.session.resource_prefix,
                class_uri=self.base_uri,
                instance_tag=self.instance_tag
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
