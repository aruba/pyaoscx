# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import random
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.mac import Mac
from pyaoscx.static_mac import StaticMac

from pyaoscx.pyaoscx_module import PyaoscxModule


class Vlan(PyaoscxModule):
    """
    Provide configuration management for VLANs on AOS-CX devices.
    """

    base_uri = "system/vlans"
    resource_uri_name = "vlans"
    indices = ["id"]

    macs = ListDescriptor("macs")
    static_macs = ListDescriptor("static_macs")

    def __init__(self, session, vlan_id, uri=None, **kwargs):

        self.session = session
        self._uri = uri
        self.id = vlan_id
        # List used to determine attributes related to the VLAN configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage MACs
        self.macs = []
        # Use to manage Static MACs
        self.static_macs = []
        # Attribute used to know if object was changed recently
        self.__modified = False

        # Build the path that identifies the current Vlan
        self.path = "{0}/{1}".format(Vlan.base_uri, self.id)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a VLAN table entry and fill the
            object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # Delete unwanted data
        if "macs" in data:
            data.pop("macs")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the VLAN is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", ["id", "macs"])

        # Set original attributes
        self._original_attributes = data
        # Remove ID
        if "id" in self._original_attributes:
            self._original_attributes.pop("id")
        # Remove macs
        if "macs" in self._original_attributes:
            self._original_attributes.pop("macs")

        # Set all ACLs
        from pyaoscx.acl import ACL

        if hasattr(self, "aclmac_in_cfg") and self.aclmac_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclmac_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclmac_in_cfg = acl

        if hasattr(self, "aclv4_in_cfg") and self.aclv4_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv4_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv4_in_cfg = acl

        if hasattr(self, "aclv6_in_cfg") and self.aclv6_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv6_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv6_in_cfg = acl

        # Clean MACs
        if not self.macs:
            # Set MACs if any
            # Adds macs to parent Vlan object
            Mac.get_all(self.session, self)

        # Set Static MACs
        if self.static_macs == []:
            StaticMac.get_all(self.session, self)

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system VLAN and create a dictionary
            containing each respective VLAN.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing VLAN IDs as keys and a Vlan object as
            value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", Vlan.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        vlans_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a Vlan object
            vlan_id, vlan = Vlan.from_uri(session, uri)

            vlans_dict[vlan_id] = vlan

        return vlans_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create a VLAN, or update an existing one.
            Checks whether the VLAN exists in the switch. Calls self.update()
            if VLAN is being updated. Calls self.create() if the VLAN doesn't
            exist in the switch.
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
    def update(self):
        """
        Perform a PUT call to apply changes to an existing VLAN table entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        vlan_data = utils.get_attrs(self, self.config_attrs)

        # Set all ACLs
        if "aclmac_in_cfg" in vlan_data and self.aclmac_in_cfg is not None:
            # Set values in correct form
            vlan_data["aclmac_in_cfg"] = self.aclmac_in_cfg.get_info_format()

        if "aclv4_in_cfg" in vlan_data and self.aclv4_in_cfg is not None:
            # Set values in correct form
            vlan_data["aclv4_in_cfg"] = self.aclv4_in_cfg.get_info_format()

        if "aclv6_in_cfg" in vlan_data and self.aclv6_in_cfg is not None:
            # Set values in correct form
            vlan_data["aclv6_in_cfg"] = self.aclv6_in_cfg.get_info_format()

        return self._put_data(vlan_data)

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new VLAN using the object's attributes
            as POST body. Exception is raised if object is unable to be
            created.
        :return modified: Boolean, True if VLAN was created.
        """
        # Get all VLAN data given by the user
        vlan_data = utils.get_attrs(self, self.config_attrs)
        if isinstance(self.id, str):
            self.id = int(self.id)
        vlan_data["id"] = self.id

        return self._post_data(vlan_data)

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete VLAN table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Vlan object given a response_data related to the Vlan object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
                1: "/rest/v10.04/system/vlans/1"
            }
        :return: Vlan Object.
        """
        vlan_id_arr = session.api.get_keys(
            response_data, Vlan.resource_uri_name
        )
        vlan_id = vlan_id_arr[0]
        return Vlan(session, vlan_id)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Vlan object given a VLAN URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return vlan_id, vlan: tuple with the Vlan object its ID.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)vlans/(?P<index>.+)")
        index_str = index_pattern.match(uri).group("index")
        vlan_id = int(index_str)
        # Create Vlan object
        vlan_obj = Vlan(session, vlan_id, uri=uri)

        return vlan_id, vlan_obj

    @classmethod
    def get_facts(cls, session):
        """
        Modify this to Perform a GET call to retrieve all VLANs and their
            respective data.
        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return facts: Dictionary containing VLAN IDs as keys and Vlan objects
            as values.
        """
        logging.info("Retrieving switch VLANs facts")

        # Set VLAN facts depth
        vlan_depth = session.api.default_facts_depth

        # Build URI
        uri = "{0}?depth={1}".format(Vlan.base_uri, vlan_depth)

        try:
            # Try to get facts data via GET method
            response = session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load response text into json format
        facts = json.loads(response.text)

        # Delete internal VLANs
        internal_vlan_list = []
        for vlan in facts.keys():
            if "type" in facts[vlan].keys():
                if facts[vlan]["type"] == "internal":
                    internal_vlan_list.append(vlan)

        for vlan in internal_vlan_list:
            facts.pop(vlan)

        return facts

    def __str__(self):
        try:
            return "Vlan, name: '{0}' ID: '{1}' and description: '{2}'".format(
                self.name, self.id, self.description
            )
        except Exception:
            return "Vlan, ID: '{0}'".format(self.id)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific VLAN URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix, Vlan.base_uri, self.id
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

    def modify(self, vlan_name=None, vlan_desc=None, admin_conf_state=None):
        """
        Perform a PUT calls to modify an existing VLAN.
        :param vlan_name: Optional Alphanumeric name of VLAN. Won't be modified
            if not specified.
        :param vlan_desc: Optional description to add to VLAN. Won't be
            modified if not specified.
        :param admin_conf_state: Optional administratively-configured state of
            VLAN. Won't be modified if not specified. Only configurable for
            static VLANs.
        :return: True if object was changed.
        """
        if vlan_name is not None:
            self.name = vlan_name

        if vlan_desc is not None:
            self.description = vlan_desc

        if self.type == "static" and admin_conf_state is not None:
            # admin-configured state can only be set on static VLANs
            self.admin = admin_conf_state

        # Apply changes inside switch
        return self.apply()

    def attach_acl_in(self, acl_name, list_type):
        """
        Update ACL IN values inside a Vlan object.
        :param acl_name: Alphanumeric String that is the name of the ACL.
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to specify
            the type of ACL.
        :return: True if object was changed.
        """
        # Create Acl object
        acl_obj = self.session.api.get_module(
            self.session, "ACL", index_id=acl_name, list_type=list_type
        )

        if list_type == "ipv6":
            self.aclv6_in_cfg = acl_obj
            if self.aclv6_in_cfg_version is None:
                self.aclv6_in_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991
                )
        if list_type == "ipv4":
            self.aclv4_in_cfg = acl_obj
            if self.aclv4_in_cfg_version is None:
                self.aclv4_in_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991
                )
        if list_type == "mac":
            self.aclmac_in_cfg = acl_obj
            if self.aclmac_in_cfg_version is None:
                self.aclmac_in_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991
                )

        # Apply changes
        return self.apply()

    def attach_acl_out(self, acl_name, list_type):
        """
        Update ACL OUT values inside a Vlan object.
        :param acl_name: Alphanumeric String that is the name of the ACL.
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to specify
            the type of ACL.
        :return: True if object was changed.
        """
        # Create Acl object
        acl_obj = self.session.api.get_module(
            self.session, "ACL", index_id=acl_name, list_type=list_type
        )

        if list_type == "ipv6":
            self.aclv6_out_cfg = acl_obj
            if self.aclv6_out_cfg_version is None:
                self.aclv6_out_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991
                )
        if list_type == "ipv4":
            self.aclv4_out_cfg = acl_obj
            if self.aclv4_out_cfg_version is None:
                self.aclv4_out_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991
                )
        if list_type == "mac":
            self.aclmac_out_cfg = acl_obj
            if self.aclmac_out_cfg_version is None:
                self.aclmac_out_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991
                )

        # Apply changes
        return self.apply()

    def detach_acl_in(self, acl_name, list_type):
        """
        Detach an ACL from a VLAN.
        :param acl_name: Alphanumeric String that is the name of the ACL.
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to specify
            the type of ACL.
        :return: True if object was changed.
        """
        if list_type == "ipv6":
            self.aclv6_in_cfg = None
            self.aclv6_in_cfg_version = None
        elif list_type == "ipv4":
            self.aclv4_in_cfg = None
            self.aclv4_in_cfg_version = None
        elif list_type == "mac":
            self.aclmac_in_cfg = None
            self.aclmac_in_cfg_version = None

        # Apply changes
        return self.apply()

    def detach_acl_out(self, acl_name, list_type):
        """
        Detach an ACL from a VLAN.
        :param acl_name: Alphanumeric String that is the name of the ACL.
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to specify
            the type of ACL.
        :return: True if object was changed.
        """
        if list_type == "ipv6":
            self.aclv6_out_cfg = None
            self.aclv6_out_cfg_version = None
        elif list_type == "ipv4":
            self.aclv4_out_cfg = None
            self.aclv4_out_cfg_version = None
        elif list_type == "mac":
            self.aclmac_out_cfg = None
            self.aclmac_out_cfg_version = None

        # Apply changes
        return self.apply()

    def get_mac(self, from_id, mac_address):
        """
        Create an Mac object.
        :param from_id: String source of the MAC address. Must be "dynamic",
            "VSX", "static", "VRRP", "port-access-security", "evpn", or "hsc".
        :param mac_address: String MAC address. Example: '01:02:03:04:05:06'
        :return: Mac object.
        """
        mac_obj = self.session.api.get_module(
            self.session,
            "Mac",
            from_id,
            mac_addr=mac_address,
            parent_vlan=self,
        )

        # Get MAC data
        mac_obj.get()
        return mac_obj

    def add_static_mac(self, port, mac_address):
        """
        Create an StaticMac object.
        :param port: String for the Port's name. Example: 1/1/1
        :param mac_address: String MAC address. Example: '01:02:03:04:05:06'
        :return: StaticMac object
        """
        if isinstance(port, str):
            # Make Interface into an object
            port = self.session.api.get_module(self.session, "Interface", port)
            # Materialize interface to ensure its existence
            port.get()

        static_mac_obj = self.session.api.get_module(
            self.session, "StaticMac", mac_address, parent_vlan=self, port=port
        )

        # Create static Mac on the switch
        static_mac_obj.apply()

        return static_mac_obj
