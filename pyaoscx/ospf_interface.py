# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from urllib.parse import quote_plus, unquote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError
from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class OspfInterface(PyaoscxModule):
    """
    Provide configuration management for OSPF Interface on AOS-CX devices.
    """

    collection_uri = (
        "system/vrfs/{name}/ospf{version}_routers/"
        "{instance_tag}/areas/{area_id}/ospf_interfaces"
    )
    object_uri = collection_uri + "/{interface_name}"

    indices = ["interface_name"]
    resource_uri_name = "ospf_interfaces"

    def __init__(self, session, interface_name, parent_ospf_area, **kwargs):
        self.session = session
        # Assign ID
        self.__interface_name = quote_plus(interface_name)
        # Assign parent OspfArea object
        self.__parent_ospf_area = parent_ospf_area
        port_name = kwargs.pop("port", interface_name)
        if port_name != interface_name:
            raise VerificationError(
                "OSPF interfaces must have the same name as the "
                "interface they are associated with."
            )
        self._set_port(interface_name)
        # List used to determine attributes related to the OSPF Interface
        # configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False
        self.base_uri = self.__parent_ospf_area.path + "/ospf_interfaces"
        self.path = "{0}/{1}".format(self.base_uri, quote_plus(interface_name))
        self.__parent_ospf_area.update_ospf_interfaces(self)

    @property
    def interface_name(self):
        return unquote_plus(self.__interface_name)

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @property
    def port(self):
        return self.interface_name

    def _set_port(self, name):
        from pyaoscx.interface import Interface

        self.__port = Interface(self.session, name)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a OSPF Interfaces table entry
            and fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        selector = selector or self.session.api.default_selector
        data = self._get_data(depth, selector)
        if "port" in data:
            del data["port"]
        if "interface_name" in data:
            del data["interface_name"]
        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)
        # Determines if the OSPF Interfaces is configurable
        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs")
        # Set original attributes
        self._original_attributes = data
        # Remove ID
        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_ospf_area):
        """
        Perform a GET call to retrieve all system OSPF Interfaces inside a OSPF
            Area, and create a dictionary containing them as OspfInterface
            objects.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_ospf_area: parent OspfArea object where OspfInterface
            object is stored.
        :return: Dictionary containing OSPF Interface IDs as keys and a
            OspfInterface objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)
        uri = "{0}/{1}/ospf_interfaces".format(
            parent_ospf_area.base_uri, parent_ospf_area.area_id
        )
        try:
            response = session.request("GET", uri)
        except Exception as exc:
            raise ResponseError("GET", exc) from exc
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        ospf_interface_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            # Create a OspfInterface object
            interface_name, ospf_interface = cls.from_uri(
                session, parent_ospf_area, uri
            )
            # Load all OSPF Interfaces data from within the Switch
            ospf_interface_dict[interface_name] = ospf_interface
        return ospf_interface_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing OSPF Interface.
            Checks whether the OSPF Interface exists in the switch. Calls
            self.update() if OSPF Interface being updated. Calls self.create()
            if a new OSPF Interface is being created.
        :return modified: Boolean, True if object was created or modified.
        """
        if not self.__parent_ospf_area.materialized:
            self.__parent_ospf_area.apply()
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing OSPF Interface.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        put_data = utils.get_attrs(self, self.config_attrs)
        # Get port uri
        put_data["port"] = self.__port.get_info_format()
        self.__modified = self._put_data(put_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new OSPF Interface table entry. Only
            returns if an exception is not raised.
        :return: True if OSPF Interface table entry was added.
        """
        post_data = utils.get_attrs(self, self.config_attrs)
        post_data["port"] = self.__port.get_info_format()
        post_data["interface_name"] = self.interface_name

        self.__modified = self._post_data(post_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete OSPF Interface.
        """
        self._send_data(self.path, None, "DELETE", "Delete")

        self.__parent_ospf_area.remove_ospf_interface(self)
        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_ospf_area, response_data):
        """
        Create a OspfInterface object given a response_data related to the OSPF
            Area ID object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_ospf_area: parent OspfArea object where OspfInterface
            object is stored.
        :param response_data: The response must be a dictionary of the form:
            {id: URL}, with the URL being of the form:
            "ospf_routers/<id>/areas/<id>/ospf_interfaces/<interface_name>"
            under the path:
            "/rest/v10.04/system/vrfs/<vrf_name>/"
        :return: OspfInterface object.
        """
        ospf_interface_arr = session.api.get_keys(
            response_data, cls.resource_uri_name
        )
        ospf_interface_name = ospf_interface_arr[0]
        return cls(session, ospf_interface_name, parent_ospf_area)

    @classmethod
    def from_uri(cls, session, parent_ospf_area, uri):
        """
        Create a OspfInterface object given a URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return interface_name, ospf_interface_obj: tuple containing both the
            OspfInterface name, and an OspfInterface object.
        """
        # Obtain ID from URI like:
        # system/vrfs/vrf/ospf_routers/1/areas/1.1.1.1/ospf_interfaces/iface
        interface_name = uri.split("/")[-1]

        # Create OspfInterface object
        ospf_interface_obj = cls(session, interface_name, parent_ospf_area)

        return interface_name, ospf_interface_obj

    def __str__(self):
        return "{0} with interface_name {1}".format(
            type(self).__name__, self.interface_name
        )

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific OSPF Interface uri.
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
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified
