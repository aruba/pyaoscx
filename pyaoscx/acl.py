# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from random import randint

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.pyaoscx_module import PyaoscxModule


class ACL(PyaoscxModule):
    """
    Provide configuration management for ACL on AOS-CX devices.
    """

    base_uri = "system/acls"
    resource_uri_name = "acls"

    indices = ["name", "list_type"]

    cfg_aces = ListDescriptor("cfg_aces")

    def __init__(self, session, name, list_type, uri=None, **kwargs):
        self.session = session
        # Assign IDs
        self.name = name
        self.list_type = list_type
        self._uri = uri
        # List used to determine attributes related to the ACL configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Use to manage ACL Entries
        self.cfg_aces = []
        # Attribute used to know if object was changed recently
        self.__modified = False
        # Set an initial random version
        self._update_version()

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an ACL table entry and fill
            the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
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

        uri = "{0}/{1}{2}{3}".format(
            ACL.base_uri,
            self.name,
            self.session.api.compound_index_separator,
            self.list_type,
        )
        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Remove fields because they are not needed for the PUT request
        if "name" in data:
            data.pop("name")
        if "list_type" in data:
            data.pop("list_type")
        # Delete unwanted data
        if "cfg_aces" in data:
            data.pop("cfg_aces")

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the ACL is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["name", "list_type"]
            )

        # Set original attributes
        self.__original_attributes = data

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        # Clean ACL Entries settings
        if self.cfg_aces == []:
            # Set ACL Entries if any
            # Adds ACL Entries to parent ACL already
            from pyaoscx.acl_entry import AclEntry

            AclEntry.get_all(self.session, self)
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system ACLs, and create a dictionary
            containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing ACLs IDs as keys and a Acl objects as
            values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        acl_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a Acl object
            indices, acl = ACL.from_uri(session, uri)
            acl_dict[indices] = acl

        return acl_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing ACL table
            entry. Checks whether the ACL exists in the switch. Calls
            self.update() if ACL being updated. Calls self.create() if a new
            ACL is being created.
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
        Perform a PUT call to apply changes to an existing ACL table entry.
        :return modified: True if Object was modified and a PUT request
            was made.
        """
        # Variable returned
        modified = False

        acl_data = utils.get_attrs(self, self.config_attrs)

        # Compare dictionaries
        if acl_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            # The version should change every time the ACL (or any of
            # its entries) change so that it is written to hardware
            self._update_version()
            acl_data["cfg_version"] = self.cfg_version

            post_data = json.dumps(acl_data)

            uri = "{0}/{1}{2}{3}".format(
                ACL.base_uri,
                self.name,
                self.session.api.compound_index_separator,
                self.list_type,
            )
            try:
                response = self.session.request("PUT", uri, data=post_data)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code
                )

            logging.info("SUCCESS: Updating %s", self)
            # Set new original attributes
            self.__original_attributes = acl_data
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new ACL table entry. Only returns if no
            exception is raised.
        :return modified: Boolean, True if entry was created.
        """
        acl_data = utils.get_attrs(self, self.config_attrs)
        acl_data["name"] = self.name
        acl_data["list_type"] = self.list_type

        post_data = json.dumps(acl_data)

        try:
            response = self.session.request(
                "POST", ACL.base_uri, data=post_data
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all object's data
        self.get()

        # Object was modified, as it was created
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete ACL table entry.
        """
        uri = "{0}/{1}{2}{3}".format(
            ACL.base_uri,
            self.name,
            self.session.api.compound_index_separator,
            self.list_type,
        )

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Acl object given a response_data.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param response_data: The response must be a dictionary of the form:
            { "{name},{list_type}": URL }, with URL being of the form:
            "/rest/v10.04/system/acls/{name},{list_type}"
        :return: Acl object.
        """
        acl_arr = session.api.get_keys(response_data, ACL.resource_uri_name)
        list_type = acl_arr[1]
        name = acl_arr[0]

        return ACL(session, name, list_type)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Acl object given a URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI
        :return indices, acl: tuple containing both the indices and Acl object.
        """
        # Obtain ID from URI
        index_pattern = re.compile(
            r"(.*)acls/(?P<index1>.+)[,./-](?P<index2>.+)"
        )
        name = index_pattern.match(uri).group("index1")
        list_type = index_pattern.match(uri).group("index2")

        # Create Acl object
        acl = ACL(session, name, list_type)
        indices = "{0},{1}".format(name, list_type)

        return indices, acl

    def __str__(self):
        return "ACL name:{0}, list_type:{1}".format(self.name, self.list_type)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific ACL URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}{3}{4}".format(
                self.session.resource_prefix,
                ACL.base_uri,
                self.name,
                self.session.api.compound_index_separator,
                self.list_type,
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

    def _update_version(self):
        """
        Whenever the ACL (or any of its entries) change,the version should be
            updated so that it gets written to hardware. If the version doesn't
            change, the new configuration won't get to the hardware.
        """

        new_cfg_version = randint(-9007199254740991, 9007199254740991)

        if self.materialized:
            if hasattr(self, "cfg_version"):
                logging.warning(
                    "ACL %s was modified, but the version wasn't, "
                    "so the version was changed automatically to %d",
                    str(self),
                    new_cfg_version,
                )
            else:
                logging.warning(
                    "ACL %s didn't have a version configured. %d was added",
                    str(self),
                    new_cfg_version,
                )

        self.cfg_version = new_cfg_version

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def add_acl_entry(
        self,
        sequence_num,
        action,
        count=None,
        protocol=None,
        src_ip=None,
        dst_ip=None,
        dst_l4_port_min=None,
        dst_l4_port_max=None,
        src_mac=None,
        dst_mac=None,
        ethertype=None,
    ):
        """
        Create an AclEntry object, ACL Entry already exists, value passed
            won't update the entry.
        :param sequence_num: Integer number of the sequence
        :param action: Action should be either "permit" or "deny"
        :param count: Optional boolean flag that when true, will make entry
            increment hit count for matched packets
        :param protocol: Optional integer IP protocol number
        :param src_ip: Optional source IP address. Both IPv4 and IPv6 are
            supported.
            Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_ip: Optional destination IP address. Both IPv4 and IPv6
            are supported.
            Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_l4_port_min: Optional minimum L4 port number in range; used
            in conjunction with dst_l4_port_max.
        :param dst_l4_port_max: Optional maximum L4 port number in range; used
            in conjunction with dst_l4_port_min.
        :param src_mac: Optional source MAC address
            Example:
                '01:02:03:04:05:06'
        :param dst_mac: Optional destination MAC address
            Example:
                '01:02:03:04:05:06'
        :param ethertype: Optional integer EtherType number
        :return acl_entry: A AclEntry object
        """
        # Create ACL Entry
        acl_entry_obj = self.session.api.get_module(
            self.session,
            "AclEntry",
            sequence_num,
            parent_acl=self,
            action=action,
            count=count,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_l4_port_min=dst_l4_port_min,
            dst_l4_port_max=dst_l4_port_max,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ethertype=ethertype,
        )

        # Try to obtain data; if not, create
        try:
            acl_entry_obj.get()
        except GenericOperationError:
            # Create object inside switch
            acl_entry_obj.apply()

        return acl_entry_obj

    def modify_acl_entry(
        self,
        sequence_num,
        action,
        count=None,
        src_ip=None,
        dst_ip=None,
        dst_l4_port_min=None,
        dst_l4_port_max=None,
        src_mac=None,
        dst_mac=None,
        ethertype=None,
    ):
        """
        Modify an existing ACL Entry.
        :param sequence_num: Integer number of the sequence.
        :param action: Action should be either "permit" or "deny".
        :param count: Optional boolean flag that when true, will make entry
            increment hit count for matched packets.
        :param src_ip: Optional source IP address. Both IPv4 and IPv6
            are supported.
            Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_ip: Optional destination IP address. Both IPv4 and IPv6
            are supported.
            Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_l4_port_min: Optional minimum L4 port number in range; used
            in conjunction with dst_l4_port_max.
        :param dst_l4_port_max: Optional maximum L4 port number in range; used
            in conjunction with dst_l4_port_min.
        :param src_mac: Optional source MAC address
            Example:
                '01:02:03:04:05:06'
        :param dst_mac: Optional destination MAC address
            Example:
                '01:02:03:04:05:06'
        :param ethertype: Optional integer EtherType number.
        :return acl_entry: A AclEntry object.
        """
        # Create ACL Entry
        acl_entry_obj = self.session.api.get_module(
            self.session, "AclEntry", sequence_num, parent_acl=self
        )
        # Get AclEntry object data
        acl_entry_obj.get()

        # Modify data
        acl_entry_obj.modify(
            action,
            count,
            src_ip,
            dst_ip,
            dst_l4_port_min,
            dst_l4_port_max,
            src_mac,
            dst_mac,
            ethertype,
        )

        return acl_entry_obj

    def delete_all_acl_entries(self):
        """
        Delete all ACL Entries within an ACL.
        :return: True if object was changed
        """
        # Verify ACL has the latest data
        self.get()

        # Delete all entries
        self.cfg_aces = []

        # ACL Entries deleted
        # Object modified
        return True
