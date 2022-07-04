# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from copy import deepcopy
from urllib.parse import quote_plus, unquote_plus
from warnings import warn

from netaddr import mac_eui48
from netaddr import EUI as MacAddress
from netaddr.core import AddrFormatError

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

import pyaoscx.vrf as vrf_mod

from pyaoscx.ipv6 import Ipv6
from pyaoscx.vlan import Vlan

from pyaoscx.device import Device
from pyaoscx.pyaoscx_module import PyaoscxModule


class Interface(PyaoscxModule):
    """
    Provide configuration management for Interface on AOS-CX devices.
    """

    base_uri = "system/interfaces"
    indices = ["name"]
    resource_uri_name = "interfaces"

    ip6_addresses = ListDescriptor("ip6_addresses")

    def __init__(self, session, name, uri=None, ip6_addresses=[], **kwargs):
        self.session = session
        self._uri = uri

        # List used to determine attributes related to the configuration
        self.config_attrs = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}

        # Set name, percents name and determine if Interface is a LAG
        self.name = ""
        self.__set_name(name)

        # List of previous interfaces before update
        # used to verify if an interface is deleted from lag
        self.__prev_interfaces = []

        # Set ip6 addresses
        self.ip6_addresses = ip6_addresses

        # Type required for configuration
        self.type = None
        # Set type
        self.__set_type()

        # Check if data should be added to object
        if self.__is_special_type:
            utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    def __set_name(self, name):
        """
        Set name attribute in the proper form for Interface object. Also sets
            the "percents name"-the name with any special characters replaced
            with percent-encodings.
        :param name: Interface name.
        """
        # Add attributes to class
        self.name = None
        self.percents_name = None

        if r"%2F" in name or r"%2C" in name or r"%3A" in name:
            self.name = unquote_plus(name)
            self.percents_name = name
        else:
            self.name = name
            self.percents_name = quote_plus(self.name)

    def __set_type(self):
        """
        Set Interface type when creating an Interface Object.
        """
        # Define all patterns
        lag_pattern = re.compile(r"lag[0-9]+$")
        loopback_pattern = re.compile(r"loopback[0-9]+$")
        tunnel_pattern = re.compile(r"tunnel(.*)")
        vlan_pattern = re.compile(r"vlan[0-9]+$")
        vxlan_pattern = re.compile(r"vxlan(.*)")

        # Sets interface as a special type
        self.__is_special_type = True

        if lag_pattern.match(self.name):
            self.type = "lag"
        elif loopback_pattern.match(self.name):
            self.type = "loopback"
        elif tunnel_pattern.match(self.name):
            self.type = "tunnel"
        elif vlan_pattern.match(self.name):
            self.type = "vlan"
        elif vxlan_pattern.match(self.name):
            self.type = "vxlan"
        else:
            self.__is_special_type = False

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Interface table entry.
        :param depth: Integer deciding how many levels into the API JSON
            that references will be returned.
        :param selector: Alphanumeric option to select specific
            information to return.
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

        uri = "{0}/{1}".format(Interface.base_uri, self.percents_name)

        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the module is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["name", "type"]
            )

        # Set original attributes
        self.__original_attributes = deepcopy(data)

        # Set a list of interfaces as an attribute
        if hasattr(self, "interfaces") and self.interfaces is not None:
            interfaces_list = []
            # Get all URI elements in the form of a list
            uri_list = self.session.api.get_uri_from_data(self.interfaces)

            for uri in uri_list:
                # Create an Interface object
                name, interface = Interface.from_uri(self.session, uri)

                # Check for circular reference
                # No need to get() if it's circular; it is already
                # materialized. Just set flag
                if name == self.name:
                    interface.materialized = True
                else:
                    # Materialize interface
                    interface.get()

                # Add interface to list
                interfaces_list.append(interface)

            # Set list as Interfaces
            self.interfaces = interfaces_list
            # Set list of previous Interfaces
            self.__prev_interfaces = list(self.interfaces)

        # Set VRF
        if hasattr(self, "vrf") and self.vrf is not None:
            # Set VRF as a Vrf object
            vrf_obj = vrf_mod.Vrf.from_response(self.session, self.vrf)
            self.vrf = vrf_obj
            # Materialized VRF
            self.vrf.get()

        # Set VLAN
        if hasattr(self, "vlan_tag") and self.vlan_tag is not None:
            # Set vlan_tag as a Vlan object
            vlan_obj = Vlan.from_response(self.session, self.vlan_tag)
            self.vlan_tag = vlan_obj
            # Materialized Vlan
            self.vlan_tag.get()

        # vlan_trunks
        # Set a list of VLANs as an attribute
        if hasattr(self, "vlan_trunks") and self.vlan_trunks is not None:
            vlan_trunks = []
            # Get all URI elements in the form of a list
            uri_list = self.session.api.get_uri_from_data(self.vlan_trunks)

            for uri in uri_list:
                # Create a Vlan object
                vlan_id, vlan = Vlan.from_uri(self.session, uri)
                # Materialize VLAN
                vlan.get()
                # Add VLAN to dictionary
                vlan_trunks.append(vlan)
            # Set list as VLANs
            self.vlan_trunks = vlan_trunks

        # Set all ACLs
        from pyaoscx.acl import ACL

        if hasattr(self, "aclmac_in_cfg") and self.aclmac_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclmac_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclmac_in_cfg = acl

        if hasattr(self, "aclmac_out_cfg") and self.aclmac_out_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclmac_out_cfg)
            # Materialize Acl object
            acl.get()
            self.aclmac_out_cfg = acl

        if hasattr(self, "aclv4_in_cfg") and self.aclv4_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv4_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv4_in_cfg = acl

        if hasattr(self, "aclv4_out_cfg") and self.aclv4_out_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv4_out_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv4_out_cfg = acl

        if hasattr(self, "aclv4_routed_in_cfg") and self.aclv4_routed_in_cfg:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv4_routed_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv4_routed_in_cfg = acl

        if hasattr(self, "aclv4_routed_out_cfg") and self.aclv4_routed_out_cfg:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv4_routed_out_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv4_routed_out_cfg = acl

        if hasattr(self, "aclv6_in_cfg") and self.aclv6_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv6_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv6_in_cfg = acl

        if hasattr(self, "aclv6_out_cfg") and self.aclv6_out_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv6_out_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv6_out_cfg = acl

        if hasattr(self, "aclv6_routed_in_cfg") and self.aclv6_routed_in_cfg:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv6_routed_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv6_routed_in_cfg = acl

        if hasattr(self, "aclv6_routed_out_cfg") and self.aclv6_routed_out_cfg:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv6_routed_out_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv6_routed_out_cfg = acl

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        if self.ip6_addresses == []:
            # Set IPv6 addresses if any
            # Loads IPv6 objects already into the Interface
            ipv6s = Ipv6.get_all(self.session, self)
            for ipv6 in ipv6s.values():
                self.ip6_addresses.append(ipv6)
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system Interfaces and create.
        a dictionary containing each Interface as a Interface Object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing Interface's name as key and a Interface
            objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", Interface.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        interfaces_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create an Interface object
            name, interface = Interface.from_uri(session, uri)

            interfaces_dict[name] = interface

        return interfaces_dict

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create an Interface object given a response_data related to the
            Interface object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            { "<interface_name>": URL }, with URL:
            "/rest/v10.04/system/interfaces/<interface_name>"
        :return: Interface object.
        """
        interfaces_id_arr = session.api.get_keys(
            response_data, Interface.resource_uri_name
        )
        interface_name = interfaces_id_arr[0]
        return session.api.get_module(session, "Interface", interface_name)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an Interface object given a interface URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return name, interface_obj: tuple containing both the Interface's name
            and an Interface object.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)/(?P<index>.+)")
        name_percents = index_pattern.match(uri).group("index")
        name = unquote_plus(name_percents)
        # Create Interface object
        interface_obj = session.api.get_module(
            session, "Interface", name, uri=uri
        )

        return name, interface_obj

    @classmethod
    def get_facts(cls, session):
        """
        Perform a GET call to retrieve all Interfaces and their data.
        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return facts: Dictionary containing Interface IDs as keys and
            Interface objects as values.
        """
        logging.info("Retrieving the switch interfaces facts")

        # Set depth
        interface_depth = session.api.default_facts_depth

        # Build URI
        uri = "{0}?depth={1}".format(Interface.base_uri, interface_depth)

        try:
            # Try to get facts via GET method
            response = session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load into json format
        facts = json.loads(response.text)

        return facts

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create an Interface Object. Only returns if no
            exception is raised.
        :return True if entry was created inside Device.
        """
        interface_data = utils.get_attrs(self, self.config_attrs)

        interface_data["name"] = self.name
        # Set Type
        if self.type is not None:
            interface_data["type"] = self.type

        post_data = json.dumps(interface_data)

        try:
            response = self.session.request(
                "POST", Interface.base_uri, data=post_data
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all objects data
        self.get()

        return True

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to update or create a Interface or Port table entry.
            Checks whether the Interface exists in the switch. Calls
            self.update() if Interface is being updated. Calls self.create() if
            a Interface table entry is being created.
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
    def delete(self):
        """
        Perform DELETE call to delete Interface table entry.
        """
        if not self.__is_special_type:
            self.initialize_interface_entry()
        else:
            # Delete Interface via a DELETE REQUEST
            uri = "{0}/{1}".format(Interface.base_uri, self.name)

            try:
                response = self.session.request("DELETE", uri)

            except Exception as e:
                raise ResponseError("DELETE", e)

            if not utils._response_ok(response, "DELETE"):
                raise GenericOperationError(
                    response.text, response.status_code
                )

            # Clean LAG from interfaces
            # Delete interface references
            for interface in self.__prev_interfaces:
                # If interface name is not the same as the current one
                if interface.name != self.name and self.type == "lag":
                    interface.__delete_lag(self)

            # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Interface or Port
            table entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Variable returned
        modified = False

        # Get interface PUT data depending on the configuration attributes
        # list
        iface_data = utils.get_attrs(self, self.config_attrs)

        # Check if VRF is inside the data related to interface
        if hasattr(self, "vrf") and self.vrf is not None:
            # Set VRF in the correct format for PUT
            iface_data["vrf"] = (
                None
                if self.vrf.name == "default"
                else self.vrf.get_info_format()
            )

        # Check if vlan_tag is inside the data related to interface
        if hasattr(self, "vlan_tag") and self.vlan_tag is not None:
            # Set VLAN in the correct format for PUT
            iface_data["vlan_tag"] = self.vlan_tag.get_info_format()

        # Set interfaces into correct form
        if hasattr(self, "interfaces") and self.interfaces is not None:
            formatted_interfaces = {}

            # Check for interfaces no longer in LAG
            if self.__is_special_type and self.type == "lag":
                for element in self.__prev_interfaces:
                    # If element was deleted from interfaces
                    if element not in self.interfaces:
                        # Delete element reference to current LAG
                        element.__delete_lag(self)

            # Set prev interfaces with current ones
            # Copies interfaces
            self.__prev_interfaces = list(self.interfaces)

            # Set interfaces into correct form
            for element in self.interfaces:
                # If element is the same as current, ignore
                if element.name == self.name and self.type == "lag":
                    pass
                else:
                    # Verify object is materialized
                    if not element.materialized:
                        raise VerificationError(
                            "Interface {0}".format(element.name),
                            "Object inside interfaces not materialized",
                        )
                    formated_element = element.get_info_format()
                    formatted_interfaces.update(formated_element)

                    if self.type == "lag":
                        # New element being added to LAG
                        element.__add_member_to_lag(self)

            # Set values in correct form
            iface_data["interfaces"] = formatted_interfaces

        # Set VLANs into correct form
        if "vlan_trunks" in iface_data:
            formated_vlans = {}
            # Set VLANs into correct form
            for element in self.vlan_trunks:
                # Verify object is materialized
                if not element.materialized:
                    raise VerificationError(
                        "Vlan {0}".format(element),
                        "Object inside vlan trunks not materialized",
                    )
                formated_element = element.get_info_format()
                formated_vlans.update(formated_element)

            # Set values in correct form
            iface_data["vlan_trunks"] = formated_vlans

        # Set all ACLs
        if "aclmac_in_cfg" in iface_data and self.aclmac_in_cfg:
            # Set values in correct form
            iface_data["aclmac_in_cfg"] = self.aclmac_in_cfg.get_info_format()

        if "aclmac_out_cfg" in iface_data and self.aclmac_out_cfg:
            # Set values in correct form
            iface_data[
                "aclmac_out_cfg"
            ] = self.aclmac_out_cfg.get_info_format()

        if "aclv4_in_cfg" in iface_data and self.aclv4_in_cfg:
            # Set values in correct form
            iface_data["aclv4_in_cfg"] = self.aclv4_in_cfg.get_info_format()

        if "aclv4_out_cfg" in iface_data and self.aclv4_out_cfg:
            # Set values in correct form
            iface_data["aclv4_out_cfg"] = self.aclv4_out_cfg.get_info_format()

        if "aclv4_routed_in_cfg" in iface_data and self.aclv4_routed_in_cfg:
            # Set values in correct form
            iface_data[
                "aclv4_routed_in_cfg"
            ] = self.aclv4_routed_in_cfg.get_info_format()

        if "aclv4_routed_out_cfg" in iface_data and self.aclv4_routed_out_cfg:
            # Set values in correct form
            iface_data[
                "aclv4_routed_out_cfg"
            ] = self.aclv4_routed_out_cfg.get_info_format()

        if "aclv6_in_cfg" in iface_data and self.aclv6_in_cfg:
            # Set values in correct form
            iface_data["aclv6_in_cfg"] = self.aclv6_in_cfg.get_info_format()

        if "aclv6_out_cfg" in iface_data and self.aclv6_out_cfg:
            # Set values in correct form
            iface_data["aclv6_out_cfg"] = self.aclv6_out_cfg.get_info_format()

        if "aclv6_routed_in_cfg" in iface_data and self.aclv6_routed_in_cfg:
            # Set values in correct form
            iface_data[
                "aclv6_routed_in_cfg"
            ] = self.aclv6_routed_in_cfg.get_info_format()

        if "aclv6_routed_out_cfg" in iface_data and self.aclv6_routed_out_cfg:
            # Set values in correct form
            iface_data[
                "aclv6_routed_out_cfg"
            ] = self.aclv6_routed_out_cfg.get_info_format()

        uri = "{0}/{1}".format(Interface.base_uri, self.percents_name)

        # Compare dictionaries
        if iface_data == self.__original_attributes:
            # Object was not modified
            modified = False
        else:

            put_data = json.dumps(iface_data)

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
            self.__original_attributes = deepcopy(iface_data)
            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def __add_member_to_lag(self, lag):
        """
        Perform PUT calls to configure a Port as a LAG member, and enable it.
        :param lag: pyaoscx.Interface object, to which the current port is
            being assigned to.
        """
        if not lag.materialized:
            raise VerificationError(
                "LAG {0}".format(lag.name),
                "Object is not materialized - Perform get()",
            )

        lag_name = lag.name
        # Extract LAG ID from LAG name
        lag_id = int(re.search("\\d+", lag_name).group())

        # Update Values
        try:
            self.user_config["admin"] = "down"
        except AttributeError:
            pass
        try:
            self.other_config["lacp-aggregation-key"] = lag_id
        except AttributeError:
            pass

        # Make a POST call and update values
        self.update()

    @PyaoscxModule.connected
    def __delete_lag(self, lag):
        """
        Perform PUT calls to update Interface, deleting the LAG reference
            inside of the Port that was assigned to that LAG.
        :param lag: pyaoscx.Interface object.
        """
        if not lag.materialized:
            raise VerificationError(
                "LAG {0}".format(lag.name),
                "Object is not materialized - Perform get()",
            )

        # Update Values
        try:
            self.user_config["admin"] = "down"
        except AttributeError:
            pass
        self.other_config.pop("lacp-aggregation-key", None)

        # Make a PUT call and update values
        self.update()

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific Interface URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                Interface.base_uri,
                self.percents_name,
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
        """
        String containing the Interface name.
        :return: This class' string representation.
        """
        return "Interface Object, name: '{0}'".format(self.name)

    def __set_to_default(self):
        """
        Perform a PUT call to set Interface to default settings.
        :return: True if object was changed.
        """
        # Check for IPv6 addresses and delete them
        for address in self.ip6_addresses:
            address.delete()
        # Clean Attribute
        self.ip6_addresses = []

        interface_data = {}
        # Clear Interfaces
        if hasattr(self, "interfaces") and self.interfaces is not None:
            if self.__is_special_type and self.name == "lag":
                self.interfaces = []
                for element in self.__prev_interfaces:
                    # If element was deleted from interfaces
                    if element not in self.interfaces:
                        # Delete element reference to current LAG
                        try:
                            element.__delete_lag(self)
                        except AttributeError:
                            # Ignore error
                            pass
            else:
                self.interfaces = [self]

            # Set prev interfaces with current ones
            # Copies interfaces
            self.__prev_interfaces = list(self.interfaces)

        uri = "{0}/{1}".format(Interface.base_uri, self.percents_name)

        put_data = json.dumps(interface_data)

        try:
            response = self.session.request("PUT", uri, data=put_data)

        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Setting %s default settings", self)

        # Update values with new ones
        self.get()
        return True

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

    @PyaoscxModule.materialized
    def configure_mclag_options(self, mc_lag=None, lacp_fallback=None):
        """
        Configure an Interface object, set its LAG attributes. Requires a
            call to apply() afterwards.
        :param mc_lag: Boolean to set the LAG as a multi-chassis LAG.
        :param lacp_fallback: Boolean to set the LAG's LACP fallback mode.
        """
        if not self.__is_special_type:
            logging.warning(
                "Interface is not a LAG Interface, cannot set MCLAG options"
            )
        if self.__is_special_type:
            if mc_lag is not None:
                self.other_config["mclag_enabled"] = mc_lag
            if lacp_fallback is not None:
                self.other_config["lacp-fallback"] = lacp_fallback

    @PyaoscxModule.materialized
    def configure_l2(
        self,
        phys_ports=None,
        ipv4=None,
        vlan_ids_list=None,
        vlan_tag=1,
        lacp=None,
        description=None,
        fallback_enabled=None,
        mc_lag=None,
        vlan_mode="native-untagged",
        trunk_allowed_all=False,
        native_vlan_tag=True,
    ):
        """
        Configure an Interface object, set the attributes to a L2 LAG and
            apply() changes inside Switch.
        :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1",
            "1/1/2", "1/1/3"]) or list of Interface Objects.
        :param ipv4: Optional list of IPv4 address to assign to the interface.
            If more than one is specified, all addresses except for the first
            are added as secondary_ip4. Defaults to nothing if not specified.
            Example: ['1.1.1.1', '2.2.2.2']
        :param vlan_ids_list: Optional list of integer VLAN IDs or VLAN objects
            to add as trunk VLANS. Defaults to empty list if not specified.
        :param vlan_tag: Optional VLAN ID or Vlan object to be added as
            vlan_tag. Defaults to VLAN 1.
        :param lacp: Must be either "passive" or "active." Does not change if
            not specified.
        :param description: Optional description for the interface. Defaults
            to nothing if not specified.
        :param fallback_enabled: Boolean to set the LAG's LACP fallback mode.
        :param mc_lag: Boolean to set the LAG as a multi-chassis LAG.
        :param vlan_mode: Vlan mode on Interface, should be access or trunk
            Defaults to 'native-untagged'.
        :param trunk_allowed_all: Flag for vlan trunk allowed all on L2
            interface, vlan_mode must be set to trunk.
        :param native_vlan_tag: Flag for accepting only tagged packets on
            VLAN trunk native, vlan_mode must be set to trunk.
        :return: True if object was changed.
        """
        # Set Physical Ports
        if phys_ports is not None:
            self.interfaces = []
            for port in phys_ports:
                port_obj = self.session.api.get_module(
                    self.session, "Interface", port
                )
                # Materialize Port
                port_obj.get()
                self.interfaces.append(port_obj)
        if lacp:
            self.lacp = lacp
        # Set Mode, but keep it as it was if it receives None
        if vlan_mode:
            self.vlan_mode = vlan_mode

        if vlan_mode == "access":
            # Convert VLAN Tag into Object
            if isinstance(vlan_tag, int):
                # Create Vlan object
                vlan_tag = Vlan(self.session, vlan_tag)
                # Try to get data; if non-existent, throw error
                vlan_tag.get()
                self.vlan_tag = vlan_tag

        # Modify if trunk
        elif vlan_mode == "trunk":
            if vlan_tag is None:
                vlan_tag = 1

            # Create Vlan object
            vlan_tag = Vlan(self.session, vlan_tag)
            # Try to get data; if non-existent, throw error
            vlan_tag.get()
            # Set VLAN tag
            self.vlan_tag = vlan_tag

            # Set VLAN mode
            if native_vlan_tag:
                self.vlan_mode = "native-tagged"
            else:
                self.vlan_mode = "native-untagged"

            if not trunk_allowed_all:
                # Set VLAN Trunks
                if vlan_ids_list is not None:
                    self.vlan_trunks = []
                    for vlan in vlan_ids_list:
                        vlan_obj = Vlan(self.session, vlan)
                        vlan_obj.get()
                        self.vlan_trunks.append(vlan_obj)

        # Set description
        if description is not None:
            self.description = description

        # Set IPv4
        if ipv4 == []:
            self.ip4_address = None
            self.ip4_address_secondary = None
        elif isinstance(ipv4, list):
            self.ip4_address = ipv4[0]
            self.ip4_address_secondary = ipv4[1:]

        self.routing = False

        # Set all remaining attributes for a Lag to be an L2
        self.configure_mclag_options(
            mc_lag=mc_lag, lacp_fallback=fallback_enabled
        )
        # Apply Changes inside Switch
        return self.apply()

    @PyaoscxModule.materialized
    def configure_l3(
        self,
        phys_ports=None,
        ipv4=None,
        ipv6=None,
        vrf="default",
        lacp=None,
        description=None,
        fallback_enabled=None,
        mc_lag=None,
    ):
        """
        Configure an Interface object, if not materialized, materialize it and
            then set the attributes to a L3 LAG and apply() changes inside
            Switch.
        :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1",
            "1/1/2", "1/1/3"]) or list of Interface Objects.
        :param ipv4: Optional list of IPv4 address to assign
            to the interface. If more than one is specified, all addresses
            except for the first are added as secondary_ip4. Defaults to
            nothing if not specified. Example: ['1.1.1.1', '2.2.2.2']
        :param ipv6: String list of IPv6 addresses to assign to the interface.
            Defaults to nothing if not specified. List of A Ipv6 objects is
            accepted. Example:
            ['2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
        :param vrf: VRF to attach the SVI to. Defaults to "default" if not
            specified. A Vrf object is also accepted.
        :param lacp: Must be either "passive" or "active." Does not change if
            not specified.
        :param description: Optional description for the interface. Defaults to
            nothing if not specified.
        :param fallback_enabled: Boolean to set the LAG's LACP fallback mode.
        :param mc_lag: Boolean to set the LAG as a multi-chassis LAG.
        :return: True if object was changed.
        """
        # Set Physical Ports
        if phys_ports is not None:
            self.interfaces = []
            for port in phys_ports:
                port_obj = self.session.api.get_module(
                    self.session, "Interface", port
                )
                # Materialize Port
                port_obj.get()
                self.interfaces.append(port_obj)

        # Set IPv4
        if ipv4 == []:
            self.ip4_address = None
            self.ip4_address_secondary = None
        elif isinstance(ipv4, list):
            self.ip4_address = ipv4[0]
            self.ip4_address_secondary = ipv4[1:]

        # Set IPv6
        ipv6_configured = False
        if ipv6 is not None and ipv6 != []:
            for ip_address in ipv6:
                # Verify if incoming address is a string
                if isinstance(ip_address, str):
                    # Create Ipv6 object -- add it to ipv6_addresses internal
                    # list
                    ip_address = self.session.api.get_module(
                        self.session,
                        "Ipv6",
                        ip_address,
                        parent_int=self,
                        type="global-unicast",
                        preferred_lifetime=604800,
                        valid_lifetime=2592000,
                        node_address=True,
                        ra_prefix=True,
                    )
                    # Try to get data, if non existent create
                    try:
                        # Try to obtain IPv6 address data
                        ip_address.get()
                    # If Ipv6 Object is non existent, create it
                    except GenericOperationError:
                        # Create IPv6 inside switch
                        ip_address.apply()
                        ipv6_configured = True
        # If IPv6 is empty, delete
        elif ipv6 == []:
            self.ip6_addresses = []
            ipv6_configured = True
        if lacp:
            self.lacp = lacp
        # Set description
        if description is not None:
            self.description = description

        # Set VRF
        if isinstance(vrf, str):
            vrf = vrf_mod.Vrf(self.session, vrf)
            vrf.get()
        self.vrf = vrf

        self.routing = True

        # Set all remaining attributes for a Lag to be an L3
        self.configure_mclag_options(
            mc_lag=mc_lag, lacp_fallback=fallback_enabled
        )
        self.vlan_mode = None
        self.vlan_tag = None
        self.origin = "configuration"

        # Apply Changes inside Switch
        return self.apply() or ipv6_configured

    def configure_svi(
        self,
        vlan=None,
        ipv4=None,
        ipv6=None,
        vrf=None,
        description=None,
        int_type="vlan",
        user_config="up",
    ):
        """
        Configure a Interface table entry for a VLAN.
        :param vlan: Numeric ID of VLAN
            A Vlan object is also accepted
        :param ipv4: Optional list of IPv4 address to assign to the interface.
            If more than one is specified, all addresses except for the first
            are added as secondary_ip4. Defaults to nothing if not specified.
            Example: ['1.1.1.1'].
        :param ipv6: String list of IPv6 addresses to assign to the interface.
            Defaults to nothing if not specified. A Ipv6 object is also
            accepted. Example:
            ['2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
        :param vrf: VRF to attach the SVI to. Defaults to "default" if not
            specified. A Vrf object is also accepted.
        :param description: Optional description for the interface. Defaults
            to nothing if not specified.
        :param int_type: Type of interface; generally should be "vlan" for
            SVI's. Defaults to vlan.
        :return: True if object was changed.
        """
        if not self.materialized:
            raise VerificationError(
                "Interface {0}".format(self.name), "Object not materialized"
            )

        if vlan is not None:
            vlan_tag = vlan
            # Set VLAN Tag into Object
            if isinstance(vlan, int):
                name = "VLAN {0}".format(str(vlan))
                # Create Vlan object
                vlan_tag = self.session.api.get_module(
                    self.session, "Vlan", vlan, name=name
                )
                # Try to obtain data; if not, create
                try:
                    vlan_tag.get()
                except GenericOperationError:
                    # Create object inside switch
                    vlan_tag.apply()

            self.vlan_tag = vlan_tag

        # Set IPv4
        if ipv4 is not None and ipv4 != []:
            for i in range(len(ipv4)):
                if i == 0:
                    self.ip4_address = ipv4[i]
                else:
                    self.ip4_address_secondary.append(ipv4[i])
        # If IPv4 is empty, delete
        elif ipv4 == []:
            self.ip4_address = None
            self.ip4_address_secondary = None
        # Set IPv6
        ipv6_configured = False
        if ipv6 is not None and ipv6 != []:
            for ip_address in ipv6:
                # Verify if incoming address is a string
                if isinstance(ip_address, str):
                    # Create Ipv6 object -- add it to ipv6_addresses internal
                    # list
                    ip_address = self.session.api.get_module(
                        self.session,
                        "Ipv6",
                        ip_address,
                        parent_int=self,
                        type="global-unicast",
                        preferred_lifetime=604800,
                        valid_lifetime=2592000,
                        node_address=True,
                        ra_prefix=True,
                    )
                    # Try to get data, if non existent create
                    try:
                        # Try to obtain IPv6 address data
                        ip_address.get()
                    # If Ipv6 Object is non existent, create it
                    except GenericOperationError:
                        # Create IPv6 inside switch
                        ip_address.apply()
                        ipv6_configured = True
        # If IPv6 is empty, delete
        elif ipv6 == []:
            self.ip6_addresses = []
            ipv6_configured = True

        # Set VRF
        if vrf is not None:
            if isinstance(vrf, str):
                vrf = self.session.api.get_module(self.session, "Vrf", vrf)
                vrf.get()

            self.vrf = vrf

        # Set type
        self.type = int_type

        if description is not None:
            self.description = description

        # Apply changes
        return self.apply() or ipv6_configured

    @PyaoscxModule.materialized
    def add_ipv4_address(self, ip_address):
        """
        Configure a Interface object to add a new IPv4 address to it and
            calls apply(), applying changes inside Switch.
        :param ip_address: IPv4 address to assign to the interface.
            Example: "1.1.1.1"
        :return: True if object was changed.
        """
        # Set incoming IPv4 address
        self.ip4_address = ip_address

        # Apply changes inside switch
        return self.apply()

    @PyaoscxModule.materialized
    def add_ipv6_address(self, ip_address, address_type="global-unicast"):
        """
        Configure a Interface object to append a IPv6 address to its
            ip6_addresses list and apply changes.
        :param ip_address: IPv6 address to assign to the interface.
            A Ipv6 object is also accepted. Example:
            '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param address_type: Type of Address. Defaults to global-unicast.
        :return: Ipv6 object.
        """
        # Verify if incoming address is a string
        if isinstance(ip_address, str):
            # Create Ipv6 object -- add it to ipv6_addresses internal list
            ipv6 = self.session.api.get_module(
                self.session,
                "Ipv6",
                ip_address,
                parent_int=self,
                type=address_type,
                preferred_lifetime=604800,
                valid_lifetime=2592000,
                node_address=True,
                ra_prefix=True,
            )
            # Try to get data, if non existent create
            try:
                # Try to obtain IPv6 address data
                ipv6.get()
            # If Ipv6 Object is non existent, create it
            except GenericOperationError:
                # Create IPv6 inside switch
                ipv6.apply()

        # Apply changes inside switch
        self.apply()

        return ipv6

    def delete_ipv6_address(self, ip_address):
        """
        Given a IPv6 address, delete that address from the current Interface.
        :param ip_address: IPv6 address to assign to the interface. A Ipv6
            object is also accepted. Example:
            '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'.
        """
        if not self.materialized:
            raise VerificationError(
                "Interface {0}".format(self.name), "Object not materialized"
            )

        # Verify if incoming address is a object
        if isinstance(ip_address, Ipv6):
            # Obtain address
            ip_address = ip_address.address

        # Iterate through every address inside interface
        for add_obj in self.ip6_addresses:
            if add_obj.address == ip_address:
                # Removing address does an internal delete
                self.ip6_addresses.remove(add_obj)

    def configure_loopback(self, vrf, ipv4=None, description=None):
        """
        Configure an Interface object to create a Loopback Interface for a
            logical L3 Interface. If the Loopback Interface already exists and
            an IPv4 address is given, this function will update the IPv4
            address.
        :param vrf: VRF to attach the Loopback to. Defaults to "default"
            if not specified.
        :param ipv4: IPv4 address to assign to the interface. Defaults to
            nothing if not specified. Example: '1.1.1.1'
        :param description: Optional description for the interface. Defaults
            to nothing if not specified..
        :return: True if object was changed.
        """
        if not self.materialized:
            raise VerificationError(
                "Interface {0}".format(self.name), "Object not materialized"
            )

        # Set VRF
        if vrf is not None:
            if isinstance(vrf, str):
                vrf = self.session.api.get_module(self.session, "Vrf", vrf)
                vrf.get()

            self.vrf = vrf

        # Set IPv4
        if ipv4 is not None and ipv4 != []:
            for i in range(len(ipv4)):
                if i == 0:
                    self.ip4_address = ipv4[i]
                else:
                    self.ip4_address_secondary.append(ipv4[i])
        # If IPv4 is empty, delete
        elif ipv4 == []:
            self.ip4_address = None
            self.ip4_address_secondary = None

        if description is not None:
            self.description = description

        # Set all remaining attributes to create a loopback

        # when configuring a loopback interface, it must be powered on
        self.admin_state = "up"

        self.ospf_if_type = "ospf_iftype_loopback"

        # Apply changes to switch
        return self.apply()

    @PyaoscxModule.materialized
    def configure_vxlan(
        self, source_ipv4=None, description=None, dest_udp_port=4789
    ):
        """
        Configure VXLAN table entry for a logical L3 Interface. If the VXLAN
            Interface already exists and an IPv4 address is given, the function
            will update the IPv4 address.
        :param source_ipv4: Optional source IPv4 address to assign to the VXLAN
            interface. Defaults to nothing if not specified. Example:
            '1.1.1.1'.
        :param description: Optional description for the interface. Defaults
            to nothing if not specified.
        :param dest_udp_port: Optional Destination UDP Port that the VXLAN
            will use. Default is set to 4789.
        :return: True if object was changed.
        """
        # Set Values
        self.options["local_ip"] = source_ipv4
        self.options["vxlan_dest_udp_port"] = str(dest_udp_port)

        self.type = "vxlan"
        # when configuring a vxlan interface, it must be powered on
        self.admin_state = "up"

        if description is not None:
            self.description = description

        # Apply changes
        return self.apply()

    def set_vlan_mode(self, vlan_mode):
        """
        Set an L2 interface's VLAN mode. The options are 'native-tagged',
            'native-untagged', or 'access'.
        :param vlan_mode: A string, either 'native-tagged', 'native-untagged',
            or 'access', specifying the desired VLAN mode.
        :return: True if object was changed.
        """
        if not self.materialized:
            raise VerificationError(
                "Interface {0}".format(self.name), "Object not materialized"
            )

        # Set Values
        self.vlan_mode = vlan_mode
        self.routing = False

        # Apply changes
        return self.apply()

    def set_untagged_vlan(self, vlan):
        """
        Set the untagged VLAN on an access port.
        :param vlan: Numeric ID of VLAN to set on access port. A Vlan object is
            also accepted.
        :return: True if object was changed.
        """
        if not self.materialized:
            raise VerificationError(
                "Interface {0}".format(self.name), "Object not materialized"
            )

        # Set Values
        self.vlan_mode = "access"

        vlan_tag = vlan
        # Set Vlan Tag into Object
        if isinstance(vlan, int):
            # Create Vlan object
            vlan_tag = self.session.api.get_module(self.session, "Vlan", vlan)
            # Try to get data; if non-existent, throw error
            vlan_tag.get()

        # Set Vlan Tag
        self.vlan_tag = vlan_tag

        self.routing = False

        # Apply changes
        return self.apply()

    def add_vlan_trunks(self, vlan_trunk_ids):
        """
        Add specified VLANs to a trunk port. By default, this will also set
            the port to have 'no routing' and if there is not a native VLAN,
            will set the native VLAN to VLAN 1.
        :param vlan_trunk_ids: Dictionary of VLANs to specify
            as allowed on the trunk port.  If empty, the interface
            will allow all VLANs on the trunk.
        :return: True if object was changed.
        """
        # Set vlan Trunks
        if vlan_trunk_ids is not None:
            self.vlan_trunks = []

            for vlan in vlan_trunk_ids:

                vlan_obj = self.session.api.get_module(
                    self.session, "Vlan", vlan
                )
                vlan_obj.get()

                self.vlan_trunks.append(vlan_obj)

        self.routing = False

        # Set other values in case of None
        if self.vlan_mode is not None:
            self.vlan_mode = "native-untagged"

        if self.vlan_tag is not None:
            vlan_tag_obj = self.session.api.get_module(self.session, "Vlan", 1)
            vlan_tag_obj.get()
            self.vlan_tag = vlan_tag_obj

        # Apply Changes
        return self.apply()

    def set_native_vlan(self, vlan, tagged=True):
        """
        Set a VLAN to be the native VLAN on the trunk. Also gives the option to
            set the VLAN as tagged.
        :param vlan: Numeric ID of VLAN to add to trunk port. A Vlan object is
            also accepted
        :param tagged: Boolean to determine if True, the native VLAN will be
            set as the tagged VLAN. If False, the VLAN will be set as the
            native untagged VLAN. Defaults to True.
        :return: True if object was changed.
        """
        if tagged:
            self.vlan_mode = "native-tagged"
        else:
            self.vlan_mode = "native-untagged"

        vlan_tag = vlan
        # Set Vlan Tag into Object
        if isinstance(vlan_tag, int):
            # Create Vlan object
            vlan_tag = self.session.api.get_module(self.session, "Vlan", vlan)
            # Try to get data; if non-existent, throw error
            vlan_tag.get()

        self.vlan_tag = vlan_tag

        self.routing = False

        # Flag used to check if the incoming vlan has to be added to trunks
        add = True
        # Verify native vlan is in vlan trunks
        for vlan_obj in self.vlan_trunks:
            # Check vlan
            if vlan_obj.id == vlan:
                # Don't add
                add = False
        if add:
            # Add new vlan to vlan trunks
            self.vlan_trunks.append(self.vlan_tag)

        # Apply Changes
        return self.apply()

    def delete_vlan(self, vlan):
        """
        Delete a VLAN from a trunk port.
        :param vlan: Numeric ID of VLAN to delete from the trunk port.
            A Vlan object is also accepted.
        :return: True if successfully deleted.
        """
        # Import VLAN to  identify object type
        from pyaoscx.vlan import Vlan

        if isinstance(vlan, Vlan):
            vlan_id = vlan.id
        else:
            vlan_id = vlan

        deleted = False
        # Iterate through vlan trunks in search of the vlan
        for vlan_obj in self.vlan_trunks:
            if vlan_obj.id == vlan_id:
                # Delete vlan from vlan trunks
                self.vlan_trunks.remove(vlan_obj)
                deleted = True
        # Apply Changes
        self.apply()

        return deleted

    def add_port_to_lag(self, interface):
        """
        Configure a Port as a LAG member, and also enable the port. Add port
            to list of interfaces inside Interface object.
        :param interface: Alphanumeric name of the interface. A Interface
            object is also accepted.
        :return: True if object was changed.
        """
        # Identify interface variable type
        if isinstance(interface, str):
            # Create Interface Object
            interface_obj = self.session.api.get_module(
                self.session, "Interface", interface
            )
            # Try to get data; if non-existent, throw error
            interface_obj.get()

        elif isinstance(interface, Interface):
            interface_obj = interface

        for member in self.interfaces:
            # Check existance inside members
            if member.name == interface_obj.name:
                # Stop execution
                return False

        # Add interface as a member of the lag
        self.interfaces.append(interface_obj)

        # Apply changes
        return self.apply()

    def remove_port_from_lag(self, interface):
        """
        Remove a Port from LAG, and also disable the port. Remove port from
            list of interfaces inside Interface object.
        :param interface: Alphanumeric name of the interface. A Interface
            object is also accepted
        :return: True if object was changed.
        """
        if not self.__is_special_type:
            raise VerificationError(
                "Interface {0}".format(self.name),
                "Interface object must be a lag to remove a Port",
            )

        # Identify interface type
        if isinstance(interface, Interface):
            interface_name = interface.name
        elif isinstance(interface, str):
            interface_name = interface

        for member in self.interfaces:
            # Check existence inside members
            if member.name == interface_name:
                # Remove interface from Member
                self.interfaces.remove(member)

        # When changes are applied, port is disabled and lacp key changed
        return self.apply()

    def clear_acl(self, acl_type):
        """
        Clear an interface's ACL.
        :param acl_type: Type of ACL: options are 'aclv4_out', 'aclv4_in',
            'aclv6_in', or 'aclv6_out'.
        :return: True if object was changed.
        """
        if acl_type == "ipv6":
            self.aclv6_in_cfg = None
            self.aclv6_in_cfg_version = None
        if acl_type == "ipv4":
            self.aclv4_in_cfg = None
            self.aclv4_in_cfg_version = None
        if acl_type == "mac":
            self.aclmac_in_cfg = None
            self.aclmac_in_cfg_version = None

        # Apply Changes
        return self.apply()

    def initialize_interface_entry(self):
        """
        Initialize Interface to its default state.
        :return: True if object was changed.
        """
        # Set interface to default settings
        return self.__set_to_default()

    @property
    def admin_state(self):
        return self.admin

    @admin_state.setter
    def admin_state(self, state):
        """
        Set the admin state. This will power the interface on or off
        :param state: new power state, "up" to turn interface on, "down" to
            turn it off.
        """
        self.admin = state
        if (
            "lag" not in self.name
            and hasattr(self, "user_config")
            and isinstance(self.user_config, dict)
        ):
            self.user_config["admin"] = state

    def configure_vsx(
        self, active_forwarding, vsx_sync, act_gw_mac, act_gw_ip
    ):
        """
        Configure VSX IPv4 settings on a VLAN Interface.
        :param active_forwarding: True or False Boolean to set VSX active
            forwarding.
        :param vsx_sync: List of alphanumeric values to enable VSX
            configuration synchronization.  The options are
            any combination of 'active-gateways', 'irdp', and 'policies'. VSX
            Sync is mainly used in the Primary.
        :param act_gw_mac: Alphanumeric value of the Virtual MAC address for
            the interface active gateway. Example: '01:02:03:04:05:06'
        :param act_gw_ip: Alphanumeric value of the Virtual IP address for the
            interface active gateway. Example: '1.1.1.1'
        :return: True if object was changed.
        """
        # Set values
        vsx_sync_list = []
        if "active-gateways" in vsx_sync:
            vsx_sync_list.append("^vsx_virtual.*")
        if "irdp" in vsx_sync:
            vsx_sync_list.append(".irdp.*")
        if "policies" in vsx_sync:
            vsx_sync_list.append("^policy.*")

        self.vsx_active_forwarding_enable = active_forwarding
        self.vsx_sync = vsx_sync_list
        self.vsx_virtual_gw_mac_v4 = act_gw_mac
        self.vsx_virtual_ip4 = [act_gw_ip]

        # Apply changes
        return self.apply()

    def delete_vsx_configuration(self):
        """
        Delete VSX IPv4 settings on a VLAN Interface.
        :return: True if object was changed.
        """
        # Set values
        self.vsx_active_forwarding_enable = False
        self.vsx_sync = []
        self.vsx_virtual_gw_mac_v4 = None
        self.vsx_virtual_ip4 = []

        # Apply changes
        return self.apply()

    def configure_l3_ipv4_port(
        self, ip_address=None, port_desc=None, vrf="default"
    ):
        """
        Function will enable routing on the port and update the IPv4 address
            if given.
        :param ip_address: IPv4 address to assign to the interface. Defaults
            to nothing if not specified. Example: '1.1.1.1'
        :param port_desc: Optional description for the interface. Defaults to
            nothing if not specified.
        :param vrf: Name of the VRF to which the Port belongs. Defaults to
            "default" if not specified.
        :return: True if object was changed.
        """
        # Set IPv4

        if ip_address is not None:
            self.ip4_address = ip_address

        # Set description
        if port_desc is not None:
            self.description = port_desc

        # Set vrf
        vrf_obj = self.session.api.get_module(self.session, "Vrf", vrf)
        vrf_obj.get()
        self.vrf = vrf_obj

        # Set routing
        self.routing = True

        # Apply Changes inside Switch
        return self.apply()

    def update_ospf_interface_authentication(
        self, vrf, auth_type, digest_key, auth_pass
    ):
        """
        Perform PUT calls to update an Interface with OSPF to have
            authentication.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to.
        :param auth_type: Alphanumeric type of authentication, chosen between
            'md5', 'null', and 'text'.
        :param digest_key: Integer between 1-255 that functions as the digest
            key for the authentication method.
        :param auth_pass: Alphanumeric text for the authentication password.
            Note that this will be translated to a base64 String in the
            configuration and json.
        :return: True if object was changed.
        """
        # Configure Port/Interface
        self.configure_l3_ipv4_port(vrf=vrf)

        self.ospf_auth_type = auth_type
        self.ospf_auth_md5_keys = {str(digest_key): auth_pass}
        self.ospf_if_type = "ospf_iftype_broadcast"
        self.routing = True
        # Set vrf
        vrf_obj = self.session.api.get_module(self.session, "Vrf", vrf)
        vrf_obj.get()
        self.vrf = vrf_obj

        # Apply changes
        return self.apply()

    def update_ospf_interface_type(self, vrf, interface_type="pointtopoint"):
        """
        Update the Interface's OSPFv2 type, as well as enable routing on the
            interface.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to.
        :param interface_type: Alphanumeric type of OSPF interface.
            The options are 'broadcast', 'loopback', 'nbma', 'none',
            'pointomultipoint', 'pointopoint', and 'virtuallink'. Defaults to
            'pointtopoint'.
        :return: True if object was changed.
        """
        _valid_interface_types = [
            "broadcast",
            "loopback",
            "statistics",
            "nbma",
            "pointomultipoint",
            "pointopoint",
            "virtuallink",
            "none",
        ]
        if interface_type not in _valid_interface_types:
            raise Exception(
                "ERROR: interface_type must be one of: {0}".format(
                    _valid_interface_types
                )
            )

        # Configure Port/Interface
        self.configure_l3_ipv4_port(vrf=vrf)

        self.ospf_if_type = "ospf_iftype_{0}".format(interface_type)
        self.routing = True
        # Set vrf
        vrf_obj = self.session.api.get_module(self.session, "Vrf", vrf)
        vrf_obj.get()
        self.vrf = vrf_obj

        # Apply changes
        return self.apply()

    def set_active_gateway(self, ip_address, gateway_mac):
        """
        Update Active Gateway of a Interface.
        :param ip_address: IPv4 address to assign to the interface. Example:
            '1.1.1.1'.
        :param gateway_mac: Active Gateway MAC address to assign to the
            interface. Example: '01:02:03:04:05:06'.
        :return: True if object was changed.
        """
        # Configure Active Gateaway IP
        self.vsx_virtual_ip4 = [ip_address]
        # Configure Gateaway mac
        self.vsx_virtual_gw_mac_v4 = gateway_mac

        # Apply changes
        return self.apply()

    @PyaoscxModule.materialized
    def update_interface_qos(self, qos):
        """
        Update QoS attached to this Interface.
        :param qos: string to define a QoS to operate on this interface. Use
            None to remove the Qos attached to this interface.
        :return: True if object was changed.
        """
        # Verify argument type and value
        if not isinstance(qos, str) and qos is not None:
            raise ParameterError("ERROR: QoS must be in a string format")

        self.qos = qos

        # Apply changes
        return self.apply()

    @PyaoscxModule.materialized
    def update_interface_queue_profile(self, queue_profile):
        """
        Update the Queue Profile for this interface.
        :param queue_profile: Queue Profile name for this Interface.
            None is used to remove an existing Queue Profile.
        :return: True if object was changed.
        """
        if queue_profile is not None and not isinstance(queue_profile, str):
            raise ParameterError(
                "ERROR: queue_profile must be a string or None"
            )
        self.q_profile = queue_profile

        # Apply changes
        return self.apply()

    @PyaoscxModule.materialized
    def update_interface_qos_trust_mode(
        self, qos_trust_mode, cos_override=None, dscp_override=None
    ):
        """
        Update the QoS trust mode of this port.
        :param qos_trust_mode: string to define the QoS trust mode for the
            interface. It can be either "cos", "dscp" or "none". To set the
            interface to use the global configuration use "global" instead.
        :param cos_override: integer with the COS entry id to associate
            with the interface instead of automatic values. In range [0,7]
        :param dscp_override: integer with the DSCP entry id to associate
            with the interface instead of the automatic values. In the
            range [0,63].
        :return: True if object was changed.
        """
        # Verify argument type and value
        if not isinstance(qos_trust_mode, str):
            raise ParameterError(
                "ERROR: QoS trust mode must be in a string format"
            )

        allowed_trust_modes = ["cos", "dscp", "none", "global"]
        if qos_trust_mode not in allowed_trust_modes:
            raise VerificationError(
                "ERROR: QoS trust mode must be one of: ", allowed_trust_modes
            )

        # Set trust mode in a key-value format
        if qos_trust_mode == "global":
            if "qos_trust" in self.qos_config:
                del self.qos_config["qos_trust"]
        else:
            self.qos_config["qos_trust"] = qos_trust_mode

        if cos_override:
            if not isinstance(cos_override, int):
                raise ParameterError(
                    "ERROR: COS Override must be in integer" "format"
                )
            self.qos_config["cos_override"] = cos_override
        if dscp_override:
            if not isinstance(dscp_override, int):
                raise ParameterError(
                    "ERROR: DSCP Override must be in integer" "format"
                )
            self.cos_config["dscp_override"] = dscp_override

        # Apply changes
        return self.apply()

    @PyaoscxModule.materialized
    def update_interface_qos_rate(self, qos_rate):
        """
        Update the rate limit values configured for
            broadcast/multicast/unknown unicast traffic.
        :param qos_rate: dict of the rate limit values; should have the
            format ['<type of traffic>'] = <value><unit> e.g.
            {
                'unknown-unicast': '100pps',
                'broadcast': 200pps,
                'multicast': '200pps'
            }.
        :return: True if object was changed.
        """
        rate_limits = {}
        if qos_rate is not None:
            for traffic_type, rate in qos_rate.items():
                for idx, char in enumerate(rate):
                    if not char.isdigit():
                        break
                number = rate[:idx]
                unit = rate[idx:]

                rate_limits[traffic_type] = int(number)
                rate_limits[traffic_type + "_units"] = unit

        self.rate_limits = rate_limits

        # Apply changes
        return self.apply()

    def update_acl_in(self, acl_name, list_type):
        """
        Perform GET and PUT calls to apply ACL on an interface. This function
            specifically applies an ACL to Ingress traffic of the interface.
        :param acl_name: Alphanumeric String that is the name of the ACL
        :param list_type: Alphanumeric String of IPv4, IPv6 or MAC to specify
            the type of ACL.
        :return: True if object was changed.
        """
        # Create Acl object
        acl_obj = self.session.api.get_module(
            self.session, "ACL", index_id=acl_name, list_type=list_type
        )
        # Get the current version
        acl_obj.get()

        if list_type == "ipv6":
            self.aclv6_in_cfg = acl_obj
            if (
                hasattr(self, "aclv6_in_cfg_version")
                and self.aclv6_in_cfg_version is None
            ):
                self.aclv6_in_cfg_version = acl_obj.cfg_version
        elif list_type == "ipv4":
            self.aclv4_in_cfg = acl_obj
            if (
                hasattr(self, "aclv4_in_cfg_version")
                and self.aclv4_in_cfg_version is None
            ):
                self.aclv4_in_cfg_version = acl_obj.cfg_version
        elif list_type == "mac":
            self.aclmac_in_cfg = acl_obj
            if (
                hasattr(self, "aclmac_in_cfg_version")
                and self.aclmac_in_cfg_version is None
            ):
                self.aclmac_in_cfg_version = acl_obj.cfg_version

        # Apply changes
        return self.apply()

    def update_acl_out(self, acl_name, list_type):
        """
        Perform GET and PUT calls to apply ACL on an interface. This function
            specifically applies an ACL to Egress traffic of the interface,
            which must be a routing interface.
        :param acl_name: Alphanumeric String that is the name of the ACL.
        :param list_type: Alphanumeric String of IPv4, IPv6 or MAC to specify
            the type of ACL.
        :return: True if object was changed.
        """
        # Create Acl object
        acl_obj = self.session.api.get_module(
            self.session, "ACL", index_id=acl_name, list_type=list_type
        )
        # Get the current version
        acl_obj.get()

        if list_type == "ipv6":
            self.aclv6_out_cfg = acl_obj
            if (
                hasattr(self, "aclv6_out_cfg_version")
                and self.aclv6_out_cfg_version is None
            ):
                self.aclv6_out_cfg_version = acl_obj.cfg_version
        elif list_type == "ipv4":
            self.aclv4_out_cfg = acl_obj
            if (
                hasattr(self, "aclv4_out_cfg_version")
                and self.aclv4_out_cfg_version is None
            ):
                self.aclv4_out_cfg_version = acl_obj.cfg_version
        elif list_type == "mac":
            self.aclmac_out_cfg = acl_obj
            if (
                hasattr(self, "aclmac_out_cfg_version")
                and self.aclmac_out_cfg_version is None
            ):
                self.aclmac_out_cfg_version = acl_obj.cfg_version

        # Routeing
        self.routing = True

        # Apply changes
        return self.apply()

    @PyaoscxModule.materialized
    def port_security_enable(
        self,
        client_limit=None,
        sticky_mac_learning=None,
        allowed_mac_addr=None,
        allowed_sticky_mac_addr=None,
        violation_action=None,
        violation_recovery_time=None,
        violation_shutdown_recovery_enable=None,
    ):
        """
        Enable port security on an specified Interface.
        :param client_limit: Integer with the maximum amount of MAC
            addresses that can connect to the port.
        :param sticky_mac_learning: Boolean, If sticky MAC learning
            should be enabled.
        :param allowed_mac_addr: The list of allowed MAC addresses,
            each MAC address is a string, or a netaddr.EUI object.
        :param allowed_sticky_mac_addr: A dictionary where each key is
            a MAC address (string or netaddr.EUI), and the value is a list of
            integers, where each integer is a VLAN id.
        :param violation action: Action to take when unauthorized MACs
            try to connect.
        :param violation_recovery_time: integer with Time in seconds
            to wait for recovery.
        :param violation_shutdown_recovery_enable: Enable recovering
            from violation shut down.
        :return: True if the object was changed.
        """
        if not hasattr(self, "port_security"):
            raise VerificationError(
                "Unable to configure the port's security",
                "Interface {0} is not security capable".format(self.name),
            )

        if hasattr(self, "routing") and self.routing:
            raise VerificationError(
                "Configuring port-security is allowed only on bridged ports."
            )

        self.port_security["enable"] = True

        device = Device(self.session)
        device.get()
        max_clients = device.capacities[
            "port_access_port_security_max_client_limit"
        ]
        if client_limit is not None and (
            1 > client_limit or client_limit > max_clients
        ):
            raise ParameterError(
                "Can only authorize 1 to {0} clients".format(max_clients)
            )

        if client_limit:
            self.port_security["client_limit"] = client_limit

        if sticky_mac_learning:
            self.port_security[
                "sticky_mac_learning_enable"
            ] = sticky_mac_learning

        # Use netaddr.EUI to verify that all static MAC addresses are valid,
        # and use a colon (:) character as the separator.  Example: accept
        # '2C:54:91:88:C9:E3', but not '2C-54-91-88-C9-E3', then re-convert to
        # string because that is what the API accepts.
        mac_format = mac_eui48
        mac_format.word_sep = ":"
        _valid_static_macs = []
        allowed_mac_addr = allowed_mac_addr or []
        for mac_addr in allowed_mac_addr:
            try:
                mac = MacAddress(mac_addr, dialect=mac_format)
                _valid_static_macs.append(str(mac))
            except AddrFormatError as exc:
                raise ParameterError("Invalid static MAC address") from exc
        self.port_security_static_client_mac_addr = _valid_static_macs

        # Use netaddr.EUI to verify that all static MAC addresses are valid,
        # and use a colon (:) character as the separator.  Example: accept
        # '2C:54:91:88:C9:E3', but not '2C-54-91-88-C9-E3', then re-convert to
        # string because that is what the API accepts.
        _valid_sticky_macs = {}
        allowed_sticky_mac_addr = allowed_sticky_mac_addr or {}
        for mac_address, vlans in allowed_sticky_mac_addr.items():
            try:
                mac = MacAddress(mac_address, dialect=mac_format)
                _valid_sticky_macs[str(mac)] = vlans
            except AddrFormatError as exc:
                raise ParameterError("Invalid sticky MAC address") from exc

        # Verify all VLAN IDs are valid numbers
        for mac_address, vlans in _valid_sticky_macs.items():
            _valid_vlans = []
            for vlan in vlans:
                try:
                    vlan = int(vlan)
                except ValueError as exc:
                    raise ParameterError("Invalid sticky MAC VLANs") from exc
                _valid_vlans.append(vlan)

            __status_int = Interface(self.session, self.name)
            __status_int.get(selector="status")
            # NOTE: applied_vlan_tag is NOT in the default get() path, so we
            # get it as a dictionary here
            _vlan_tag = None
            _vlan_tag_present = bool(__status_int.applied_vlan_tag)
            if _vlan_tag_present:
                _vlan_tag = int(next(iter(__status_int.applied_vlan_tag)))
            # NOTE: applied_vlan_trunks is NOT in the default get() path, so we
            # get it as a dictionary here
            _vlan_trunks = None
            _vlan_trunks_present = bool(__status_int.applied_vlan_trunks)
            if _vlan_trunks_present:
                _vlan_trunks = sorted(
                    [int(k) for k in __status_int.applied_vlan_trunks]
                )
            if _valid_vlans == [] and _vlan_tag_present:
                _valid_vlans = [_vlan_tag]

            if not _vlan_tag_present and not _vlan_trunks_present:
                raise VerificationError(
                    "No VLANs are configured in this interface"
                )
            for vlan in _valid_vlans:
                if not (
                    _vlan_tag_present
                    and vlan == _vlan_tag
                    or _vlan_trunks_present
                    and vlan in _vlan_trunks
                ):
                    _err_msg_allowed_vlans = []
                    if _vlan_tag_present:
                        _err_msg_allowed_vlans.append(
                            "vlan_access: {0}".format(_vlan_tag)
                        )
                    if _vlan_trunks_present:
                        _err_msg_allowed_vlans.append(
                            "vlan_trunks: {0}".format(_vlan_trunks)
                        )
                    raise VerificationError(
                        "One or more of {0} VLANs are not configured, the "
                        "allowed VLANs for this interface are: {1}".format(
                            _valid_vlans, ", ".join(_err_msg_allowed_vlans)
                        )
                    )
                _valid_sticky_macs[mac_address] = _valid_vlans
        self.port_security_static_sticky_client_mac_addr = _valid_sticky_macs

        if violation_action:
            if violation_action == "notify" and violation_recovery_time:
                raise ParameterError(
                    "Must not specify recovery time when violation action is "
                    "'notify'"
                )
            self.port_access_security_violation["action"] = violation_action

        if violation_recovery_time:
            if 10 > violation_recovery_time or violation_recovery_time > 600:
                raise ParameterError(
                    "violation_recovery_time must be between 10s and 600s"
                )
            self.port_access_security_violation[
                "recovery_timer"
            ] = violation_recovery_time

        if violation_shutdown_recovery_enable:
            self.port_access_security_violation[
                "shutdown_recovery_enable"
            ] = violation_shutdown_recovery_enable

        return self.apply()

    def port_security_disable(self):
        """
        Disable port security on the specified interface.
        :return: True if the object was changed.
        """
        if not self.materialized:
            raise VerificationError(
                "interface {0}".format(self.name), "Object not materialized"
            )

        if not hasattr(self, "port_security"):
            # This interface is not security capable
            warn(
                "Interface {0} is not security capable".format(self.name),
                RuntimeWarning,
            )

        self.port_security["enable"] = False
        return self.apply()

    @PyaoscxModule.materialized
    def configure_speed_duplex(
        self,
        autoneg=None,
        speeds=None,
        duplex=None,
    ):
        """
        Configure the Interface speed and duplex mode.
        :param speeds: List of allowed Interface speeds.
        :param duplex: "full" for full duplex or "half" for half duplex.
        :param autonegotiation: switch autonegotiation "on" or "off".
        :return: True if object changed.
        """

        autoneg = "on" if autoneg else "off"
        _user_config = {"autoneg": autoneg}

        if speeds and duplex:
            autoneg = "off"
            _user_config["autoneg"] = autoneg
        if autoneg == "on" and duplex:
            raise ParameterError(
                "When autoneg is on, duplex must not be specified"
            )
        if autoneg == "off":
            if duplex and len(speeds) > 1:
                raise ParameterError(
                    "When specifying duplex, only a single speed can be "
                    "specified"
                )
        if speeds:
            speeds_string = ",".join(str(s) for s in speeds)
            _user_config["speeds"] = speeds_string
            stat_int = Interface(self.session, self.name)
            stat_int.get(selector="status")
            sw_capable_speeds = stat_int.hw_intf_info["speeds"]
            sw_speeds = set([int(s) for s in sw_capable_speeds.split(",")])
            configure_speeds = set(speeds)
            if not configure_speeds.issubset(sw_speeds):
                raise VerificationError(
                    "Specified speeds {0} are not supported by interface {1}, "
                    "supported values are: {2}".format(
                        speeds, self.name, sorted(sw_speeds)
                    )
                )
        if duplex:
            _user_config["duplex"] = duplex

            speeds_duplex = "{0}-{1}".format(speeds[0], duplex)
            if "forced_speeds" in stat_int.hw_intf_info:
                sw_str_speeds_duplex = stat_int.hw_intf_info["forced_speeds"]
                if speeds_duplex not in sw_str_speeds_duplex.split(","):
                    raise VerificationError(
                        "Speeds-duplex setting values are not supported by "
                        "specified interface: {0}, supported values are: "
                        "{1}".format(self.name, sw_str_speeds_duplex)
                    )
        self.user_config.update(_user_config)
        return self.apply()
