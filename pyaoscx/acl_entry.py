# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class AclEntry(PyaoscxModule):
    """
    Provide configuration management for ACL Entry on AOS-CX devices.
    """

    indices = ["sequence_number"]
    resource_uri_name = "cfg_aces"

    protocol_dict = {
        "ah": 51,
        "esp": 50,
        "gre": 47,
        "icmp": 1,
        "icmpv6": 58,
        "igmp": 2,
        "ospf": 89,
        "pim": 103,
        "sctp": 132,
        "tcp": 6,
        "udp": 17,
    }

    # These parameters cannot be changed once the ACE is created
    # If any of them is set for update the entire ACE must be
    # replaced (delete and re-create). This list is needed while
    # we are not able to read the schema.
    immutable_parameter_names = [
        "action",
        "count",
        "dscp",
        "dst_ip",
        "dst_ip_group",
        "dst_l4_port_group",
        "dst_l4_port_max",
        "dst_l4_port_min",
        "dst_mac",
        "ecn",
        "ethertype",
        "fragment",
        "icmp_code",
        "icmp_type",
        "ip_precedence",
        "log",
        "pcp",
        "protocol",
        "sequence_number",
        "src_ip",
        "src_ip_group",
        "src_l4_port_group",
        "src_l4_port_max",
        "src_l4_port_min",
        "src_mac",
        "tcp_ack",
        "tcp_cwr",
        "tcp_ece",
        "tcp_established",
        "tcp_fin",
        "tcp_psh",
        "tcp_rst",
        "tcp_syn",
        "tcp_urg",
        "tos",
        "ttl",
        "vlan",
    ]

    # This list needs to be maintained only while we are not
    # able to read the schema. It is required when extracting
    # parameters to create copies.
    mutable_parameter_names = ["comment"]

    def __init__(
        self, session, sequence_number, parent_acl, uri=None, **kwargs
    ):

        self.session = session
        # Assign ID
        self.sequence_number = sequence_number
        # Assign parent Acl object
        self.__set_acl(parent_acl)
        self._uri = uri
        # List used to determine attributes related to the acl_entry
        # configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_acl(self, parent_acl):
        """
        Set parent Acl object as an attribute for the AclEntry object.
        :param parent_acl: a Acl object.
        """
        # Set parent acl
        self.__parent_acl = parent_acl

        # Set URI
        self.base_uri = "{0}/{1}{2}{3}/cfg_aces".format(
            self.__parent_acl.base_uri,
            self.__parent_acl.name,
            self.session.api.compound_index_separator,
            self.__parent_acl.list_type,
        )

        # Verify acl_entry doesn't exist already inside acl
        for acl_entry in self.__parent_acl.cfg_aces:
            if acl_entry.sequence_number == self.sequence_number:
                # Make list element point to current object
                acl_entry = self
            else:
                # Add self to cfg_aces list in parent acl
                self.__parent_acl.cfg_aces.append(self)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an ACL Entry table entry and
            fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
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

        uri = "{0}/{1}".format(self.base_uri, self.sequence_number)
        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the ACL Entry is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["sequence_number"]
            )

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "sequence_number" in self.__original_attributes:
            self.__original_attributes.pop("sequence_number")

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_acl):
        """
        Perform a GET call to retrieve all system ACL Entries inside an ACL,
            and create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_acl: parent Acl object where ACL Entry is stored.
        :return acl_entry_dict: Dictionary containing ACL Entry IDs as keys
            and an ACL Entry objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)
        uri = "{0}/{1}{2}{3}/cfg_aces".format(
            parent_acl.base_uri,
            parent_acl.name,
            session.api.compound_index_separator,
            parent_acl.list_type,
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        acl_entry_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a AclEntry object and adds it to parent acl list
            sequence_number, acl_entry = AclEntry.from_uri(
                session, parent_acl, uri
            )
            # Load all acl_entry data from within the Switch
            acl_entry.get()
            acl_entry_dict[sequence_number] = acl_entry

        return acl_entry_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create a new ACL Entry or update an existing
            one. It is possible that in case the are differences between the
            ACE on the switch and the local representation on immutable
            attributes a replace (delete+create) will take place. Note that
            unspecified parameters will be kept intact.
        :return modified: Boolean, True if object was created or modified.
        """
        if not self.__parent_acl.materialized:
            self.__parent_acl.apply()

        modified = False

        remote_ace = AclEntry(
            self.session, self.sequence_number, self.__parent_acl
        )

        try:
            # Should get all configurable attributes, not just the one that
            # are available for writing
            remote_ace.get(selector="configuration")
        except GenericOperationError:
            # If the get fails, the ACE doesn't exist, so a simple
            # create will suffice
            logging.info("%s for %s will be created", self, self.__parent_acl)
            modified = self.create()
        else:
            self._extract_missing_parameters_from(remote_ace)
            # Get was successful, so the ACE already exists
            if PyaoscxModule._is_replace_required(
                current=remote_ace,
                replacement=self,
                immutable_parameter_names=self.immutable_parameter_names,
            ):
                remote_ace.delete()
                logging.info(
                    "%s for %s will be replaced", self, self.__parent_acl.name
                )
                modified = self.create()
            else:
                # A replace was not required, so it is possible that an
                # update will suffice. Extracting the parameters from
                # the remote works as a materialization
                self.materialized = True
                modified = self.update()

        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing ACL Entry.
        :return modified: True if Object was modified and a PUT request
            was made.
        """
        # Variable returned
        modified = False

        acl_entry_data = utils.get_attrs(self, self.config_attrs)

        uri = "{0}/{1}".format(self.base_uri, self.sequence_number)

        if not self.__was_modified():
            # Object was not modified
            modified = False

        else:
            # Normally objects will pull from the switch only writable
            # attributes, but because of the replace (delete/create) behaviour
            # implemented for ACL Entries, we usually pull all configurable
            # attributes. Which means that hey have to be removed from the
            # request before being sent to the switch
            for key in list(acl_entry_data):
                if key in self.immutable_parameter_names:
                    del acl_entry_data[key]

            post_data = json.dumps(acl_entry_data)

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
            self.__original_attributes = acl_entry_data

            # Object was modified
            modified = True

        if modified:
            self.__parent_acl._update_version()
            self.__parent_acl.apply()

        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new ACL Entry. Only returns if no
            exception is raised.
        :return modified: Boolean, True if entry was created
        """
        acl_entry_data = utils.get_attrs(self, self.config_attrs)
        acl_entry_data["sequence_number"] = self.sequence_number

        # Try to get protocol number
        try:
            if isinstance(self.protocol, str):
                if self.protocol == "any" or self.protocol == "":
                    acl_entry_data.pop("protocol")
                else:
                    protocol_num = self.protocol_dict[self.protocol]
                    acl_entry_data["protocol"] = protocol_num
            elif isinstance(self.protocol, int):
                acl_entry_data["protocol"] = self.protocol
        except Exception:
            pass
        post_data = json.dumps(acl_entry_data)

        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all object's data
        self.get()

        self.__parent_acl._update_version()
        self.__parent_acl.apply()

        # Object was created, means modified
        self.__modified = True
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete ACL Entry from parent ACL on the switch.
        """
        uri = "{0}/{1}".format(self.base_uri, self.sequence_number)

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

        # Delete back reference from ACL
        for acl_entry in self.__parent_acl.cfg_aces:
            if acl_entry.sequence_number == self.sequence_number:
                self.__parent_acl.cfg_aces.remove(acl_entry)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_acl, response_data):
        """
        Create a AclEntry object given a response_data related to the ACL Entry
            sequence_number object.
        :param cls: Class calling the method.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_acl: parent Acl object where ACL Entry is stored.
        :param response_data: The response must be a dictionary of the form:
            {
                <seq_number>: "/rest/v10.04/system/acls/cfg_aces/<seq_number>"
            }
        :return: AclEntry object.
        """
        acl_entry_arr = session.api.get_keys(
            response_data, AclEntry.resource_uri_name
        )
        sequence_number = acl_entry_arr[0]
        return AclEntry(session, sequence_number, parent_acl)

    @classmethod
    def from_uri(cls, session, parent_acl, uri):
        """
        Create a AclEntry object given a URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_acl: parent Acl object where ACL Entry is stored.
        :param uri: a String with a URI.
        :return index, acl_entry_obj: tuple containing both the AclEntry
            object and the acl_entry's sequence_number.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)cfg_aces/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create AclEntry object
        acl_entry_obj = AclEntry(session, index, parent_acl, uri=uri)

        return index, acl_entry_obj

    def __str__(self):
        return "ACL Entry ID {0}".format(self.sequence_number)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific ACL Entry URI.
        return: AclEntry object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
                self.sequence_number,
            )

        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: AclEntry object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    @property
    def modified(self):
        return self.__modified

    def __was_modified(self):
        """
        Determine if the object was modified since the last materialization.
        """
        current = utils.get_attrs(self, self.config_attrs)
        original = self.__original_attributes
        if current == original:
            return False
        # Because ACL gets all configurable parameters and not just the
        # writable ones those two dictionaries could be different but because
        # on is missing members that the other one has. So it is necessary to
        # check that the missing members are set as None in the other.
        modified = False
        for key, value in current.items():
            if key in original:
                modified |= value != original[key]
            else:
                modified |= value is not None
        for key, value in original.items():
            if key in current:
                modified |= value != current[key]
            else:
                modified |= value is not None

        return modified

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

    def modify(
        self,
        action=None,
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
        Create an AclEntry object, ACL Entry already exists, value passed won't
            update the entry.
        :param action: Action should be either "permit" or "deny".
        :param count: Optional boolean flag that when true, will make entry
            increment hit count for matched packets.
        :param src_ip: Optional source IP address. Both IPv4 and IPv6 are
            supported. Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_ip: Optional destination IP address. Both IPv4 and IPv6 are
            supported. Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_l4_port_min: Optional minimum L4 port number in range; used
            in conjunction with dst_l4_port_max.
        :param dst_l4_port_max: Optional maximum L4 port number in range; used
            in conjunction with dst_l4_port_min.
        :param src_mac: Optional source MAC address. Example:
            '01:02:03:04:05:06'
        :param dst_mac: Optional destination MAC address. Example:
            '01:02:03:04:05:06'
        :param ethertype: Optional integer EtherType number.
        :return: True if object was changed.
        """
        if action is not None:
            self.action = action

        if count is not None:
            self.count = count

        if src_ip is not None:
            self.src_ip = src_ip

        if dst_ip is not None:
            self.dst_ip = dst_ip

        if dst_l4_port_min is not None:
            self.dst_l4_port_min = dst_l4_port_min

        if dst_l4_port_max is not None:
            self.dst_l4_port_max = dst_l4_port_max

        if src_mac is not None:
            self.src_mac = src_mac

        if dst_mac is not None:
            self.dst_mac = dst_mac

        if ethertype is not None:
            self.ethertype = ethertype

        # Apply changes
        return self.apply()
