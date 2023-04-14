# (C) Copyright 2019-2023 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from netaddr import valid_mac

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class StaticMac(PyaoscxModule):
    """
    Provide configuration management for Static MAC on AOS-CX devices.
    """

    indices = ["mac_addr"]
    resource_uri_name = "static_macs"

    collection_uri = "system/vlans/{vlan_id}/static_macs"
    object_uri = collection_uri + "/{mac_addr}"

    def __init__(self, session, mac_addr, parent_vlan, uri=None, **kwargs):

        """
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param mac_addr: String MAC address, or netaddr EUI object.
            Example:
                '01:02:03:04:05:06'
        :param parent_vlan: Vlan object to which this MAC belongs
        :param uri: Optional string containing the uri of the MAC object
        """
        self.session = session
        # Assign id
        self.__mac_addr = mac_addr
        self.__parent_vlan = parent_vlan
        self._uri = uri
        # List used to determine attributes related to the Static MAC
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
        uri_indices = {
            "vlan_id": self.__parent_vlan.id,
            "mac_addr": self.__mac_addr,
        }
        self._uri_indices = uri_indices
        self.base_uri = self.collection_uri.format(**uri_indices)
        self.path = self.object_uri.format(**uri_indices)

    @property
    def mac_addr(self):
        return self.__mac_addr

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Static MAC table entry and
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

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the Static MAC is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", self.indices)

        # Set original attributes
        self._original_attributes = data
        # Remove ID
        if "mac_addr" in self._original_attributes:
            self._original_attributes.pop("mac_addr")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session, parent_vlan):
        """
        Perform a GET call to retrieve all system Static MACs inside a VLAN,
            and create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vlan: VLAN object where Static MAC is stored.
        :return: Dictionary containing Static MAC IDs as keys and a Static MAC
            objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/{1}/static_macs".format(
            parent_vlan.base_uri, parent_vlan.id
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        static_mac_dict = {}

        for uri in data.values():
            # Create a StaticMac object and adds it to parent Vrf object list
            mac_addr, static_mac = StaticMac.from_uri(
                session, parent_vlan, uri
            )
            # Load all Static MAC data from within the Switch
            static_mac_dict[mac_addr] = static_mac

        return static_mac_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Static MAC.
            Checks whether the Static MAC exists in the switch. Calls
            self.update() if Static MAC is being updated. Calls self.create()
            if a new Static MAC is being created.

        :return: Boolean, True if object was created or modified.
        """
        if not self.__parent_vlan.materialized:
            self.__parent_vlan.apply()
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Static MAC.

        :return: True if Object was modified and a PUT request was
            made.
        """
        static_mac_data = utils.get_attrs(self, self.config_attrs)

        if hasattr(self, "port") and self.port is not None:
            if isinstance(self.port, str):
                port = self.session.api.get_module(
                    self.session, "Interface", self.port
                )
            port.get()
            if not port.materialized:
                raise VerificationError(
                    "Port {0} not materialized".format(port.name)
                )
            if hasattr(port, "routing") and port.routing:
                raise VerificationError(
                    "{0} is not an L2 port".format(port.name)
                )
            static_mac_data["port"] = port.get_info_format()

        self.__modified = self._put_data(static_mac_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Static MAC using the object's
            attributes as POST body. Only returns if no exception is raised.

        :return: Boolean, True if entry was created
        """
        static_mac_data = utils.get_attrs(self, self.config_attrs)
        if not valid_mac(self.mac_addr):
            raise ParameterError("Invalid MAC Address")
        static_mac_data["mac_addr"] = self.mac_addr
        static_mac_data["vlan"] = self.__parent_vlan.get_info_format()
        if hasattr(self, "port") and self.port is not None:
            if isinstance(self.port, str):
                port = self.session.api.get_module(
                    self.session, "Interface", self.port
                )
            port.get()
            if not port.materialized:
                raise VerificationError(
                    "Port {0} not materialized".format(port.name)
                )
            if hasattr(port, "routing") and port.routing:
                raise VerificationError(
                    "{0} is not an L2 port".format(port.name)
                )
            static_mac_data["port"] = port.get_info_format()

        self.__modified = self._post_data(static_mac_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete Static MAC.
        """
        self._send_data(self.path, None, "DELETE", "Delete")

        # Delete back reference from VLAN
        for static_mac in self.__parent_vlan.static_macs:
            if static_mac.mac_address == self.mac_address:
                self.__parent_vlan.static_macs.remove(static_mac)

        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vlan, response_data):
        """
        Create a Static MAC object given a response_data related to it.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vlan: parent Vlan object where Static MAC is stored.
        :param response_data: The response must be a dictionary of the form:
            {
            <mac_addr>: (
            "/rest/v10.04/system/vlans/<vlan_id>/static_macs/<mac_addr>"
            )
            }
        :return: Static MAC object
        """
        static_mac_arr = session.api.get_keys(
            response_data, StaticMac.resource_uri_name
        )
        mac_addr = static_mac_arr[0]
        return StaticMac(session, mac_addr, parent_vlan)

    @classmethod
    def from_uri(cls, session, parent_vlan, uri):
        """
        Create a StaticMac object given a URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vlan: VLAN object where Static MAC is stored.
        :param uri: a String with a URI.
        :return index, static_mac_obj: tuple containing both the StaticMac
            Object and the static_mac's mac_address.
        """
        # Obtain ID from URI
        # system/vlans/<vlan_id>/static_macs/<mac_addr>
        mac_addr = uri.split("/")[-1]

        # Create Static MAC object
        static_mac_obj = StaticMac(session, mac_addr, parent_vlan)

        return mac_addr, static_mac_obj

    def __str__(self):
        return "Static MAC ID {0}".format(self.mac_addr)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific Statis MAC URI.

        :return: Object's URI.
        """
        return self.path

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.

        :return: Object format depending on the API Version.
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
