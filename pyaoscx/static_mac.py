# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import re

from urllib.parse import quote_plus, unquote_plus

from netaddr import EUI as MacAddress
from netaddr import mac_eui48

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule

from pyaoscx.mac import Mac


class StaticMac(Mac):
    """
    Provide configuration management for Static MAC on AOS-CX devices.
    """

    indices = ["mac_addr"]
    resource_uri_name = "static_macs"

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
        super(StaticMac, self).__init__(
            session, "static", mac_addr, parent_vlan, uri=uri
        )
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.display_name = "static Mac"

    def _mac_path(self):
        """
        Get the path for internal purposes.
        """
        return "{0}/{1}".format(
            self.base_uri, quote_plus(str(self.mac_address))
        )

    def _set_configuration_items(self, data, selector):
        # Determines if the Static MAC is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", ["mac_addr"])

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Static MAC.
            Checks whether the Static MAC exists in the switch. Calls
            self.update() if Static MAC is being updated. Calls self.create()
            if a new Static MAC is being created.
        """
        if not self._parent_vlan.materialized:
            self._parent_vlan.apply()

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
        Perform a PUT call to apply changes to an existing Static MAC.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Transform the MAC object to string to be sent to the switch
        self.mac_addr = str(self.mac_address)
        # Create the address representation for the URI
        static_mac_data = utils.get_attrs(self, self.config_attrs)

        if "port" in static_mac_data:
            static_mac_data["port"] = self.port.get_info_format()

        return self._put_data(static_mac_data)

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Static MAC using the object's
            attributes as POST body. Only returns if no exception is raised.
        :return modified: Boolean, True if entry was created
        """
        self.mac_addr = str(self.mac_address)
        static_mac_data = utils.get_attrs(self, self.config_attrs)
        # Set attributes
        static_mac_data["mac_addr"] = self.mac_addr
        static_mac_data["vlan"] = self._parent_vlan.get_uri()
        if hasattr(self, "port") and self.port is not None:
            static_mac_data["port"] = self.port.get_uri()

        return self._post_data(static_mac_data)

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete Static MAC mac_addr from interface on
            the switch.
        """
        reference_address = quote_plus(str(self.mac_address))
        uri = "{0}/{1}".format(self.base_uri, reference_address)

        self._send_data(uri, None, "DELETE", "Delete")

        # Delete back reference from VRF
        for static_mac in self._parent_vlan.static_macs:
            if static_mac.mac_address == self.mac_address:
                self._parent_vlan.static_macs.remove(static_mac)

        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vlan, response_data):
        """
        Create a Static MAC object given a response_data related to the IP6
            mac_addr object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vlan: parent Vlan object where Static MAC is stored.
        :param response_data: The response must be a dictionary of the form:
            {
                mac_addr: "/rest/v10.04/interface/static_macs/mac_addr"
            }
        :return: Static MAC object
        """
        mac_format = mac_eui48
        mac_format.word_sep = ":"
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
        :param parent_vlan: Parent VLAN class where Static MAC is stored.
        :param uri: a String with a URI.
        :return index, static_mac_obj: tuple containing both the StaticMac
            Object and the static_mac's mac_address.
        """
        mac_format = mac_eui48
        mac_format.word_sep = ":"
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)static_macs/(?P<index>.+)")
        reference_mac_addr = index_pattern.match(uri).group("index")

        mac_addr = MacAddress(
            unquote_plus(reference_mac_addr), dialect=mac_format
        )

        static_mac_obj = StaticMac(session, mac_addr, parent_vlan, uri=uri)

        return reference_mac_addr, static_mac_obj

    @PyaoscxModule.deprecated
    def get_uri(self):
        # TODO: remove this method in favor of uri_path once all
        # modules have been translated to the 'properties' style
        return self.uri_path

    @property
    def uri_path(self):
        """
        Method used to obtain the specific Static MAC URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = self.session.resource_prefix + self._mac_path()

        return self._uri

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
