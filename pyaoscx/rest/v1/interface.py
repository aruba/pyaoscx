# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from urllib.parse import unquote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.ipv6 import Ipv6
from pyaoscx.pyaoscx_module import PyaoscxModule
from pyaoscx.vlan import Vlan
from pyaoscx.vrf import Vrf

from pyaoscx.interface import Interface as AbstractInterface


class Interface(AbstractInterface):
    """
    Provide configuration management for Interface and Ports for REST API
        Version 1. Uses methods inside AbstractInterface and any ones different
        are overridden by this class.
    """

    base_uri = "system/ports"
    base_uri_ports = "system/ports"
    base_uri_interface = "system/interfaces"

    indices = ["name"]

    ip6_addresses = ListDescriptor("ip6_addresses")

    def __init__(self, session, name, uri=None, **kwargs):
        self.session = session
        self._uri = None

        # List used to determine attributes related to the port configuration
        self.config_attrs = []
        # List used to determine attributes related to the interface
        # configuration
        self.config_attrs_int = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes_int = {}
        self.__original_attributes_port = {}

        # Set name, percents name and determine if Interface is a LAG
        self.__set_name(name)

        # List of previous interfaces before update
        # used to verify if a interface is deleted from lag
        self.__prev_interfaces = []

        # Use to manage IPv6 addresses
        self.ip6_addresses = []

        # Type required for configuration
        self.type = None
        # Set type
        self.__set_type()

        # Check if data should be added to object
        if self.__is_special_type:
            utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Port table entry, a Interface
            table entry and fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.  The options are 'configuration', 'status', or 'statistics.
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

        uri_ports = "{0}/{1}".format(
            Interface.base_uri_ports, self.percents_name
        )

        # Bring Ports information
        try:
            response_ports = self.session.request(
                "GET", uri_ports, params=payload
            )

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response_ports, "GET"):
            raise GenericOperationError(
                response_ports.text, response_ports.status_code
            )

        data_port = json.loads(response_ports.text)
        # Adding ACL attributes to data_port
        # to then be added as attributes to the object
        acl_names = [
            "aclv6_in_cfg",
            "aclv4_in_cfg",
            "aclmac_in_cfg",
            "aclv4_out_cfg",
        ]

        for acl_attr in acl_names:
            data_port[acl_attr] = None

        # Delete ip6 addresses from incoming data
        data_port.pop("ip6_addresses")
        # Add Port dictionary as attributes for the object
        utils.create_attrs(self, data_port)

        # Determines if the module is configurable
        if selector in self.session.api.configurable_selectors:
            # Get list of keys and create a list with the given keys
            utils.set_config_attrs(
                self,
                data_port,
                "config_attrs",
                ["name", "origin", "other_config", "ip6_addresses"],
            )
        # Set original attributes
        self.__original_attributes_port = data_port
        # Delete unwanted attributes
        if "name" in self.__original_attributes_port:
            self.__original_attributes_port.pop("name")
        if "ip6_addresses" in self.__original_attributes_port:
            self.__original_attributes_port.pop("ip6_addresses")
        if "origin" in self.__original_attributes_port:
            self.__original_attributes_port.pop("origin")
        if "other_config" in self.__original_attributes_port:
            self.__original_attributes_port.pop("other_config")

        # Check if port is a LAG
        # If not, makes get request to system/interfaces
        if self.type != "lag":
            uri_interfaces = "{0}/{1}".format(
                Interface.base_uri_interface, self.percents_name
            )
            # Bring Interface information
            try:
                response_ints = self.session.request(
                    "GET", uri_interfaces, params=payload
                )

            except Exception as e:
                raise ResponseError("GET", e)

            if not utils._response_ok(response_ints, "GET"):
                raise GenericOperationError(
                    response_ints.text, response_ints.status_code
                )

            data_int = json.loads(response_ints.text)
            # Add Interface dictionary as attributes for the object
            utils.create_attrs(self, data_int)

            # Determines if the module is configurable
            if selector in self.session.api.configurable_selectors:
                # Get list of keys and create a list with the given keys
                utils.set_config_attrs(
                    self, data_int, "config_attrs_int", ["name", "origin"]
                )
            # Set original attributes
            self.__original_attributes_int = data_int
            # Delete unwanted attributes
            if "name" in self.__original_attributes_int:
                self.__original_attributes_int.pop("name")
            if "origin" in self.__original_attributes_int:
                self.__original_attributes_int.pop("origin")

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
            # Set list of interfaces
            self.__prev_interfaces = list(self.interfaces)

        # Set VRF
        if hasattr(self, "vrf") and self.vrf is not None:
            # Set keepalive VRF as a Vrf object
            vrf_obj = Vrf.from_response(self.session, self.vrf)
            self.vrf = vrf_obj
            # Materialized VRF
            self.vrf.get()

        # Set VLAN
        if hasattr(self, "vlan_tag") and self.vlan_tag is not None:
            # Set VLAN as a Vlan Object
            vlan_obj = Vlan.from_response(self.session, self.vlan_tag)
            self.vlan_tag = vlan_obj
            # Materialized VLAN
            self.vlan_tag.get()

        # vlan_trunks
        # Set a list of vlans as an attribute
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

        if hasattr(self, "aclv6_in_cfg") and self.aclv6_in_cfg:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv6_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv6_in_cfg = acl

        if hasattr(self, "aclv6_out_cfg") and self.aclv6_out_cfg:
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

        # Set IPv6 addresses if any
        if self.ip6_addresses == []:
            # Set IPv6 addresses if any
            # Loads IPv6 already into the Interface
            Ipv6.get_all(self.session, self)

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system Ports and return a list of
            them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing ports IDs as keys and a port objects
            as values.
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
            # Create a Interface object
            name, interface = Interface.from_uri(session, uri)

            interfaces_dict[name] = interface

        return interfaces_dict

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an Interface object given a interface URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return name, Interface: tuple containing both the interface's name
            and an Interface object.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)/(?P<index>.+)")
        name_percents = index_pattern.match(uri).group("index")
        name = unquote_plus(name_percents)
        # Create Interface object
        interface_obj = Interface(session, name, uri=uri)

        return name, interface_obj

    @classmethod
    def get_facts(cls, session):
        """
        Perform a GET call to retrieve all Interfaces and their respective
            data.
        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return facts: Dictionary containing Interface IDs as keys and
            Interface objects as values.
        """
        logging.info("Retrieving the switch interfaces facts")

        depth = session.api.default_facts_depth

        payload = {"depth": depth}

        # Get Ports information
        try:
            response_ports = session.request(
                "GET", Interface.base_uri_ports, params=payload
            )

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response_ports, "GET"):
            raise GenericOperationError(
                response_ports.text, response_ports.status_code
            )

        ports_data = json.loads(response_ports.text)

        # Build interface URI
        uri_interface = "{0}?depth={1}".format(
            Interface.base_uri_interface, depth
        )

        # Get Interface information
        try:
            response_interface = session.request(
                "GET", uri_interface, params=payload
            )

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response_interface, "GET"):
            raise GenericOperationError(
                response_interface.text, response_interface.status_code
            )

        # Load response text into json format
        interfaces_data = json.loads(response_interface.text)
        facts_dict = {}

        # Merge Ports and Interfaces by key name
        for port in ports_data:
            if "name" in port:
                facts_dict[port["name"]] = port
        for interface in interfaces_data:
            if "name" in interface:
                if interface["name"] in facts_dict:
                    facts_dict[interface["name"]].update(interface)
                else:
                    facts_dict[interface["name"]] = interface

        return facts_dict

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create an Interface object given a response_data related to the
            Interface object.
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param response_data: The response must be a dictionary of the form:
            {id: URL}, with the URL being of the form:
            "/rest/v1/system/interfaces/1"
            or
            "/rest/v1/system/ports/1"
        :return: Interface object.
        """
        try:
            # Try using interfaces
            interfaces_id_arr = session.api.get_keys(
                response_data, "interfaces"
            )
        except AttributeError:
            # If AttributeError for Nonetype, try with ports
            interfaces_id_arr = session.api.get_keys(response_data, "ports")
        interface_name = interfaces_id_arr[0]
        return session.api.get_module(session, "Interface", interface_name)

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete Interface.
        """
        if not self.__is_special_type:
            raise VerificationError("Interface", "Can't be deleted")

        # Delete Interface via a DELETE request to Ports Table
        uri = "{0}/{1}".format(Interface.base_uri_ports, self.name)

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        # DELETE Interface via DELETE request to Interface Table
        # Check if port is a LAG
        # If not, DELETE request to Interface Table
        if self.type != "lag":
            try:
                response_ints = self.session.request(
                    "DELETE", Interface.base_uri_interface
                )

            except Exception as e:
                raise ResponseError("DELETE", e)

            if not utils._response_ok(response_ints, "DELETE"):
                raise GenericOperationError(
                    response_ints.text, response_ints.status_code
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
        Perform a PUT call to update data for a Port and Interface table entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Flag used to determine if Object was modified
        modified_port = True
        modified_int = True
        # Check if Object is a LAG
        if self.type != "lag":
            uri_interfaces = "{0}/{1}".format(
                Interface.base_uri_interface, self.percents_name
            )
            # get Interface data related to configuration
            int_data = utils.get_attrs(self, self.config_attrs_int)
            # Remove type
            if "type" in int_data:
                int_data.pop("type")
            if "type" in self.__original_attributes_int:
                self.__original_attributes_int.pop("type")
            # Set put_int_data
            put_int_data = json.dumps(int_data)
            # Compare dictionaries
            if int_data == self.__original_attributes_int:
                # Object was not modified
                modified_port = False
            else:
                # Bring Interface information
                try:
                    response_ints = self.session.request(
                        "PUT", uri_interfaces, data=put_int_data
                    )

                except Exception as e:
                    raise ResponseError("PUT", e)

                if not utils._response_ok(response_ints, "PUT"):
                    raise GenericOperationError(
                        response_ints.text, response_ints.status_code
                    )

                # Set new original attributes
                self.__original_attributes_int = int_data

        uri_ports = "{0}/{1}".format(
            Interface.base_uri_ports, self.percents_name
        )

        # get Port data related to configuration
        port_data = utils.get_attrs(self, self.config_attrs)

        # Check for Ipv4
        try:
            if self.ip4_address is not None:
                port_data["ip4_address"] = self.ip4_address
        except AttributeError:
            pass
        # Check if vrf is inside the data related to Port
        if "vrf" in port_data:
            # Set VRF in the correct format for PUT
            port_data["vrf"] = self.vrf.get_info_format()

        # Check if vlan_tag is inside the data related to Port
        if "vlan_tag" in port_data:
            # Set VLAN in the correct format for PUT
            port_data["vlan_tag"] = self.vlan_tag.get_info_format()

        # Set interfaces into correct form
        if "interfaces" in port_data:
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

            formated_interfaces = []
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
                    # Only in V1 get_uri() is used,
                    # In any other version, element.get_info_format()
                    # is used
                    formated_element = element.get_uri(True)
                    formated_interfaces.append(formated_element)

                    if self.type == "lag":
                        # New element being added to LAG
                        element.__add_member_to_lag(self)

            # Set values in correct form
            port_data["interfaces"] = formated_interfaces

        # Set VLANs into correct form
        if "vlan_trunks" in port_data:
            formated_vlans = []
            # Set interfaces into correct form
            for element in self.vlan_trunks:
                # Verify object is materialized
                if not element.materialized:
                    raise VerificationError(
                        "Vlan {0}".format(element),
                        "Object inside vlan trunks not materialized",
                    )
                formated_element = element.get_info_format()
                formated_vlans.append(formated_element)

            # Set values in correct form
            port_data["vlan_trunks"] = formated_vlans

        # Set all ACLs
        if "aclmac_in_cfg" in port_data and self.aclmac_in_cfg is not None:
            # Set values in correct form
            port_data["aclmac_in_cfg"] = self.aclmac_in_cfg.get_info_format()

        if "aclmac_out_cfg" in port_data and self.aclmac_out_cfg is not None:
            # Set values in correct form
            port_data["aclmac_out_cfg"] = self.aclmac_out_cfg.get_info_format()

        if "aclv4_in_cfg" in port_data and self.aclv4_in_cfg is not None:
            # Set values in correct form
            port_data["aclv4_in_cfg"] = self.aclv4_in_cfg.get_info_format()

        if "aclv4_out_cfg" in port_data and self.aclv4_out_cfg is not None:
            # Set values in correct form
            port_data["aclv4_out_cfg"] = self.aclv4_out_cfg.get_info_format()

        if "aclv4_routed_in_cfg" in port_data and self.aclv4_routed_in_cfg:
            # Set values in correct form
            port_data[
                "aclv4_routed_in_cfg"
            ] = self.aclv4_routed_in_cfg.get_info_format()

        if "aclv4_routed_out_cfg" in port_data and self.aclv4_routed_out_cfg:
            # Set values in correct form
            port_data[
                "aclv4_routed_out_cfg"
            ] = self.aclv4_routed_out_cfg.get_info_format()

        if "aclv6_in_cfg" in port_data and self.aclv6_in_cfg is not None:
            # Set values in correct form
            port_data["aclv6_in_cfg"] = self.aclv6_in_cfg.get_info_format()

        if "aclv6_out_cfg" in port_data and self.aclv6_out_cfg is not None:
            # Set values in correct form
            port_data["aclv6_out_cfg"] = self.aclv6_out_cfg.get_info_format()

        if "aclv6_routed_in_cfg" in port_data and self.aclv6_routed_in_cfg:
            # Set values in correct form
            port_data[
                "aclv6_routed_in_cfg"
            ] = self.aclv6_routed_in_cfg.get_info_format()

        if "aclv6_routed_out_cfg" in port_data and self.aclv6_routed_out_cfg:
            # Set values in correct form
            port_data[
                "aclv6_routed_out_cfg"
            ] = self.aclv6_routed_out_cfg.get_info_format()

        # Set addresses the correct way
        if self.ip6_addresses is not None:
            ip6_addresses_dict = {}

            for ip in self.ip6_addresses:
                ip6_addresses_dict[ip.address] = ip.get_uri()

            # Set values in correct form
            port_data["ip6_addresses"] = ip6_addresses_dict

        # Delete type from Port data
        if "type" in port_data:
            port_data.pop("type")

        if "type" in self.__original_attributes_port:
            self.__original_attributes_port.pop("type")
        # Special case, if dictionary is empty
        if port_data["ip6_addresses"] == {}:
            self.__original_attributes_port["ip6_addresses"] = {}

        # Compare dictionaries
        if port_data == self.__original_attributes_port:
            # Object was not modified
            modified_int = False
        else:
            # Set put_port_data
            put_port_data = json.dumps(port_data)

            # Bring Port information
            try:
                response_ports = self.session.request(
                    "PUT", uri_ports, data=put_port_data
                )

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response_ports, "PUT"):
                raise GenericOperationError(
                    response_ports.text, response_ports.status_code
                )
            # Set new original attributes
            self.__original_attributes_port = port_data

        return modified_int or modified_port

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a Port table entry for Interface. Only
            returns if no exception is raised.
        :return True if entry was created inside Device.
        """
        port_data = utils.get_attrs(self, self.config_attrs)
        port_data["name"] = self.name

        post_data_ports = json.dumps(port_data)
        try:
            response = self.session.request(
                "POST", Interface.base_uri_ports, data=post_data_ports
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Check if port is a LAG
        # If not, POST Request to Interface Table
        if self.type != "lag":
            # Set data for Interface Table
            interface_data = utils.get_attrs(self, self.config_attrs_int)
            interface_data["name"] = self.name
            interface_data["type"] = self.type
            interface_data["referenced_by"] = self.get_uri()

            # Set post_int_data
            post_int_data = json.dumps(interface_data)

            # Bring Interface information
            try:
                response_ints = self.session.request(
                    "POST", Interface.base_uri_interface, data=post_int_data
                )

            except Exception as e:
                raise ResponseError("POST", e)

            if not utils._response_ok(response_ints, "POST"):
                raise GenericOperationError(
                    response_ints.text, response_ints.status_code
                )

        # Get all objects data
        self.get()
        # Object was created
        return True

    @PyaoscxModule.deprecated
    def get_uri(self, interface=False):
        """
        Method used to obtain the specific Interface URI.
        :param interface: Boolean, if true URI would contain
            a /interfaces/interface_name instead of
            /ports/interface_name.
        """
        uri = ""
        if not interface:
            uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                Interface.base_uri_ports,
                self.percents_name,
            )
        else:
            uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                Interface.base_uri_interface,
                self.percents_name,
            )

        return uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    def __str__(self):
        return "Port name: '{0}'".format(self.name)

    def __set_to_default(self):
        """
        Perform a PUT call to set Interface to default settings.
        :return: True if object was changed.
        """
        uri_ports = "{0}/{1}".format(
            Interface.base_uri_ports, self.percents_name
        )

        # get Port data related to configuration
        port_data = {}

        # Set interfaces into correct form
        if "interfaces" in port_data:
            if self.__is_special_type and self.name == "lag":
                self.interfaces = []
                for element in self.__prev_interfaces:
                    # If element was deleted from interfaces
                    if element not in self.interfaces:
                        # Delete element reference to current LAG
                        element.__delete_lag(self)
            else:
                self.interfaces = [self]

            # Set prev interfaces with current ones
            # Copies interfaces
            self.__prev_interfaces = list(self.interfaces)

        # Set put_port_data
        put_port_data = json.dumps(port_data)

        # Update Port information
        try:
            response_ports = self.session.request(
                "PUT", uri_ports, data=put_port_data
            )

        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response_ports, "PUT"):
            raise GenericOperationError(
                response_ports.text, response_ports.status_code
            )

        # Update values with new ones
        self.get()
        return True
