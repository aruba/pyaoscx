# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.pyaoscx_module import PyaoscxModule


class OspfArea(PyaoscxModule):
    """
    Provide configuration management for OSPF Area instance on AOS-CX devices.
    """

    collection_uri = (
        "system/vrfs/{name}/ospf{version}_routers/{instance_tag}/areas"
    )
    object_uri = collection_uri + "/{area_id}"

    indices = ["area_id"]
    resource_uri_name = "areas"

    # Use to manage references
    ospf_interfaces = ListDescriptor("ospf_interfaces")

    def __init__(self, session, area_id, parent_ospf_router, **kwargs):
        self.session = session
        # Assign ID
        self.__area_id = area_id
        # Assign parent OSPF Router
        self.__parent_ospf_router = parent_ospf_router
        # List used to determine attributes related to the OPSF configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage OSPF Interfaces
        self.ospf_interfaces = []
        # Attribute used to know if object was changed recently
        self.__modified = False
        self.base_uri = self.__parent_ospf_router.path + "/areas"
        self.path = "{0}/{1}".format(self.base_uri, self.__area_id)
        self.__parent_ospf_router.update_ospf_areas(self)

    @property
    def area_id(self):
        return self.__area_id

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a OSPF Area and fill the object
            with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is no exception raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)
        # Delete unwanted data
        if "ospf_interfaces" in data:
            data.pop("ospf_interfaces")
        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)
        # Determines if the OSPF Area is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", self.indices)
        # Set original attributes
        if "area_id" in data:
            del data["area_id"]
        self._original_attributes = data
        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        # Clean areas
        if self.ospf_interfaces == []:
            # Set Areas if any
            # Adds OSPF Interface to parent OSPF Area already
            from pyaoscx.ospf_interface import OspfInterface

            OspfInterface.get_all(self.session, self)

        return True

    @classmethod
    def get_all(cls, session, parent_ospf_router):
        """
        Perform a GET call to retrieve all system OSPF Area inside a OPSF
            Router, and create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_ospf_router: parent OPSF Router object where OPSF Area
            is stored.
        :return: Dictionary containing OSPF Area IDs as keys and a OSPF Area
            objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)
        uri = "{0}/{1}/areas".format(
            parent_ospf_router.base_uri, parent_ospf_router.instance_tag
        )
        try:
            response = session.request("GET", uri)
        except Exception as exc:
            raise ResponseError("GET", exc) from exc
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        ospf_area_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            # Create an OspfArea object
            area_id, ospf_area = OspfArea.from_uri(
                session, parent_ospf_router, uri
            )
            # Load all OSPF Router data from within the Switch
            ospf_area_dict[area_id] = ospf_area
        return ospf_area_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Ospf Area.
            Checks whether the OSPF Area exists in the switch. Calls
            self.update() if OSPF Area is being updated. Calls self.create() if
            a new OSPF Area is being created.
        :return modified: Boolean, True if object was created or modified.
        """
        if not self.__parent_ospf_router.materialized:
            self.__parent_ospf_router.apply()
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing OSPF Area.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # IMPORTANT: OSPF Area's ipsec_ah, ipsec_esp, and other_config MUST be
        # configured together, so if any of them needs to be updated, existing
        # values MUST be sent for all other attributes that have not changed
        # NOTE: 'other_config' is mistakenly not getting added to
        # self.config_attrs, so this is fixed here
        if "other_config" not in self.config_attrs:
            self.config_attrs.append("other_config")
        put_data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(put_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new OSPF Area. Only returns if an
            exception is not raised.
        :return modified: Boolean, True if entry was created.
        """
        post_data = utils.get_attrs(self, self.config_attrs)
        post_data["area_id"] = self.area_id

        self.__modified = self._post_data(post_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete OSPF Area table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        self.__parent_ospf_router.remove_ospf_area(self)
        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_ospf_router, response_data):
        """
        Create an OspfArea object given a response_data related to the ospf
            router ID object
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_ospf_router: parent OspfRouter object where OspfArea
            object is stored.
        :param response_data: The response must be a dictionary of the form:
            { id: URL }, with the URL being of the form:
            "/rest/v10.04/system/vrfs/<name>/ospf_routers/<id>/areas/<id>"
        :return: OspfArea object.
        """
        ospf_area_arr = session.api.get_keys(
            response_data, cls.resource_uri_name
        )
        ospf_area_id = ospf_area_arr[0]
        return cls(session, ospf_area_id, parent_ospf_router)

    @classmethod
    def from_uri(cls, session, parent_ospf_router, uri):
        """
        Create an OspfArea object given a URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return index, ospf_area_obj: tuple containing both the OspfArea object
            and the OSPF Area's ID.
        """
        # Obtain ID from URI
        # system/vrfs/name/ospf_routers/1/areas/1.1.1.1
        # or
        # system/vrfs/name/ospfv3_routers/1/areas/1.1.1.1
        uri_parts = uri.split("/")
        area_id = uri_parts[-1]

        # Create OspfArea object
        ospf_area_obj = cls(
            session,
            area_id,
            parent_ospf_router,
        )

        return area_id, ospf_area_obj

    def __str__(self):
        return "{0} with area_id {1}".format(type(self).__name__, self.area_id)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific OSPF Area URI.
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

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    def update_ospf_interfaces(self, new_interface):
        """
        Update references to OSPF Interfaces. If an Interface with the same
            interface_name is found, update the reference to the new interface,
            otherwise, add reference to the new interface.
        :param new_interface: Interface to add reference to.
        """
        for interface in self.ospf_interfaces:
            if interface.interface_name == new_interface.interface_name:
                # Make list element point to current object
                # See utils.list_attributes.ListDescriptor
                interface = new_interface
                return
        self.ospf_interfaces.append(new_interface)

    def remove_ospf_interface(self, interface):
        """
        Update references to OSPF Interfaces. If an Interface with the same
            interface_name is found, delete the reference to it.
        :param interface: Interface to add reference to.
        """
        for i in self.ospf_interfaces:
            if i.interface_name == interface.interface_name:
                self.ospf_interfaces.remove(i)
