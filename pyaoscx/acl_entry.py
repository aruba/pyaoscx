# (C) Copyright 2019-2023 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class AclEntry(PyaoscxModule):
    """
    Provide configuration management for ACL Entry on AOS-CX devices.
    """

    indices = ["sequence_number"]
    resource_uri_name = "cfg_aces"

    # Lists of fields according SW capablities
    cap_dscp = ["dscp"]
    cap_ecn = ["ecn"]
    cap_frg = ["fragment"]
    cap_tcp_flags = [
        "tcp_ack",
        "tcp_cwr",
        "tcp_ece",
        "tcp_established",
        "tcp_fin",
        "tcp_psh",
        "tcp_rst",
        "tcp_syn",
        "tcp_urg",
    ]
    cap_mac = [
        "dst_mac",
        "src_mac",
    ]
    cap_grp = [
        "src_ip_group",
        "dst_ip_group",
        "src_l4_port_group",
        "dst_l4_port_group",
    ]
    cap_pre = ["ip_precedence"]
    cap_pcp = ["pcp"]
    cap_tos = ["tos"]
    cap_ttl = ["ttl"]
    cap_log = ["log"]

    # These parameters cannot be changed once the ACE is created
    # If any of them is set for update the entire ACE must be
    # replaced (delete and re-create). This list is needed while
    # we are not able to read the schema.
    immutable_parameter_names = (
        [
            "action",
            "count",
            "dst_ip",
            "dst_l4_port_max",
            "dst_l4_port_min",
            "ethertype",
            "icmp_code",
            "icmp_type",
            "log",
            "protocol",
            "sequence_number",
            "src_ip",
            "src_l4_port_max",
            "src_l4_port_min",
            "vlan",
        ]
        + cap_dscp
        + cap_ecn
        + cap_frg
        + cap_tcp_flags
        + cap_mac
        + cap_grp
        + cap_pre
        + cap_pcp
        + cap_tos
        + cap_ttl
        + cap_log
    )

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
        for new_attr in [
            "src_ip",
            "dst_ip",
            "protocol",
            "src_mac",
            "dst_mac",
            "dscp",
            "ethertype",
            "icmp_type",
            "src_l4_port_min",
            "src_l4_port_max",
            "dst_l4_port_min",
            "dst_l4_port_max",
        ]:
            if new_attr in kwargs:
                setattr(self, new_attr, kwargs.pop(new_attr))

        # Checking against C&C
        _exclude_args = []
        _not_supported = []
        if "classifier_ace_dscp" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_dscp)
        if "classifier_ace_ecn" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_ecn)
        if "classifier_ace_frg" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_frg)
        if "classifier_ace_tcp_flags" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_tcp_flags)
        if "classifier_class_mac" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_mac)
        if "classifier_ace_pre" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_pre)
        if "classifier_acl_object_group" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_grp)
        if "classifier_ace_pcp" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_pcp)
        if "classifier_ace_tos" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_tos)
        if "classifier_ace_ttl" not in parent_acl.capabilities:
            _exclude_args.extend(self.cap_ttl)
        if "action" not in kwargs or kwargs["action"] == "permit":
            if "classifier_acl_log_permit" not in parent_acl.capabilities:
                _exclude_args.extend(self.cap_log)
        elif kwargs["action"] == "deny":
            if "classifier_acl_log_deny" not in parent_acl.capabilities:
                _exclude_args.extend(self.cap_log)

        for arg in _exclude_args:
            if arg in kwargs:
                _not_supported.append(arg)
        if _not_supported != []:
            raise ParameterError(
                "Parameters not supported by this platform: {0}".format(
                    ", ".join(_not_supported)
                )
            )
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    def __eq__(self, other):
        return (
            isinstance(other, AclEntry)
            and self.session == other.session
            and self.sequence_number == other.sequence_number
            and self.base_uri == other.base_uri
        )

    def __set_acl(self, parent_acl):
        """
        Set parent Acl object as an attribute for the AclEntry object.

        :param parent_acl: a Pyaoscx.Acl object.
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

        if self.sequence_number not in self.__parent_acl.cfg_aces:
            self.__parent_acl.cfg_aces[self.sequence_number] = self

    @PyaoscxModule.connected
    def get(self, depth=None, selector="configuration"):
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

        get_data = json.loads(response.text)
        orig_data = {k: v for k, v in get_data.items() if v is not None}
        ObjectGroup = self.session.api.get_module_class(
            self.session, "ObjectGroup"
        )
        for grp_attr in self.cap_grp:
            if grp_attr in orig_data:
                obj_grp = ObjectGroup.from_response(
                    self.session, orig_data[grp_attr]
                )
                orig_data[grp_attr] = obj_grp
        data = orig_data.copy()
        for new_attr in [
            "src_ip",
            "dst_ip",
            "protocol",
            "src_mac",
            "dst_mac",
            "dscp",
            "ethertype",
            "icmp_type",
            "src_l4_port_min",
            "src_l4_port_max",
            "dst_l4_port_min",
            "dst_l4_port_max",
        ]:
            if new_attr in data:
                setattr(self, new_attr, data.pop(new_attr))
        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the ACL Entry is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, "config_attrs", ["sequence_number"]
            )

        # Set original attributes
        self.__original_attributes.update(orig_data)
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
        uri = "{0}/{1}{2}{3}/cfg_aces?depth={4}".format(
            parent_acl.base_uri,
            parent_acl.name,
            session.api.compound_index_separator,
            parent_acl.list_type,
            session.api.default_facts_depth,
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        acl_entry_dict = {}

        ObjectGroup = session.api.get_module_class(session, "ObjectGroup")
        for ace_seq_num, ace_dict in data.items():
            # Create a AclEntry object and setting attributes from response
            ace_seq_num = int(ace_seq_num)
            ace_kwargs = {k: v for k, v in ace_dict.items() if v is not None}
            del ace_kwargs["sequence_number"]
            orig_keys = list(ace_kwargs.keys())
            for grp_attr in cls.cap_grp:
                if grp_attr in ace_kwargs:
                    obj_grp = ObjectGroup.from_response(
                        session, ace_kwargs[grp_attr]
                    )
                    ace_kwargs[grp_attr] = obj_grp
            ace_obj = cls(session, ace_seq_num, parent_acl, **ace_kwargs)
            ace_orig = utils.get_attrs(ace_obj, orig_keys)
            ace_obj.__original_attributes.update(ace_orig)
            ace_obj.config_attrs = list(ace_orig.keys())
            ace_obj.materialized = True
            acl_entry_dict[ace_seq_num] = ace_obj

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
            self.__parent_acl.get()

        modified = False

        remote_ace = AclEntry(
            self.session,
            self.sequence_number,
            self.__parent_acl,
            **self.__original_attributes
        )

        if not self.materialized:
            modified = self.create()
        else:
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
            self.__parent_acl.get()
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

        for new_attr in [
            "src_ip",
            "dst_ip",
            "protocol",
        ]:
            new_value = getattr(self, new_attr)
            if new_value != "any":
                acl_entry_data[new_attr] = new_value

        for new_attr in [
            "src_mac",
            "dst_mac",
            "dscp",
            "ethertype",
            "icmp_type",
            "src_l4_port_min",
            "src_l4_port_max",
            "dst_l4_port_min",
            "dst_l4_port_max",
        ]:
            new_value = getattr(self, new_attr)
            if new_value:
                acl_entry_data[new_attr] = new_value

        for group_param in self.cap_grp:
            if group_param in acl_entry_data:
                group_obj = acl_entry_data[group_param]
                acl_entry_data[group_param] = group_obj.get_info_format()

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
        self.__parent_acl.get()
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
        del self.__parent_acl.cfg_aces[self.sequence_number]

        self.__parent_acl.get()
        self.__parent_acl.apply()

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

    @property
    def src_mac(self):
        """
        Getter for src_mac attribute

        :return: Source MAC address
        """
        return self._src_mac if hasattr(self, "_src_mac") else None

    @src_mac.setter
    def src_mac(self, new_src_mac):
        """
        Setter for src_mac attribute
        """
        if new_src_mac:
            acl_type = self.__parent_acl.list_type
            if acl_type != "mac":
                raise ParameterError(
                    "MAC Address not allowed for ACL type {0}".format(acl_type)
                )
            self._src_mac = utils.validate_mac_address(new_src_mac)
        else:
            self._src_mac = None

    @property
    def dst_mac(self):
        """
        Getter for dst_mac attribute

        :return: Destination MAC address
        """
        return self._dst_mac if hasattr(self, "_dst_mac") else None

    @dst_mac.setter
    def dst_mac(self, new_dst_mac):
        """
        Setter for dst_mac attribute
        """
        if new_dst_mac:
            acl_type = self.__parent_acl.list_type
            if acl_type != "mac":
                raise ParameterError(
                    "MAC Address not allowed for ACL type {0}".format(acl_type)
                )
            self._dst_mac = utils.validate_mac_address(new_dst_mac)
        else:
            self._dst_mac = None

    @property
    def src_ip(self):
        """
        Getter method for source ip attribute.

        :return: String value for src_ip.
        """
        return self._src_ip if hasattr(self, "_src_ip") else "any"

    @src_ip.setter
    def src_ip(self, new_src_ip):
        """
        Setter method for the src_ip attribute.
        """
        if new_src_ip and new_src_ip.lower() != "any":
            version = utils.get_ip_version(new_src_ip)
            if version != self.__parent_acl.list_type:
                raise VerificationError(
                    "Version does not match the IP "
                    "version type in {}".format(self.__parent_acl.name)
                )
            self._src_ip = utils.fix_ip_mask(new_src_ip, version)
        else:
            self._src_ip = "any"

    @property
    def dst_ip(self):
        """
        Getter method for destination ip attribute.

        :return: String value for dst_ip.
        """
        return self._dst_ip if hasattr(self, "_dst_ip") else "any"

    @dst_ip.setter
    def dst_ip(self, new_dst_ip):
        """
        Setter method for the dst_ip attribute.
        """
        if new_dst_ip and new_dst_ip.lower() != "any":
            version = utils.get_ip_version(new_dst_ip)
            if version != self.__parent_acl.list_type:
                raise VerificationError(
                    "Version does not match the IP "
                    "version type in {}".format(self.__parent_acl.name)
                )
            self._dst_ip = utils.fix_ip_mask(new_dst_ip, version)
        else:
            self._dst_ip = "any"

    @property
    def dscp(self):
        """
        Getter method for DSCP attribute.

        :return: DSCP value, integer or String
        """
        return self._dscp if hasattr(self, "_dscp") else None

    @dscp.setter
    def dscp(self, new_dscp):
        """
        Setter method for the dscp attribute.
        """
        if isinstance(new_dscp, str):
            if new_dscp not in utils.dscp:
                raise ParameterError(
                    "Invalid DSCP {0} - valid DSCP values are: {1}".format(
                        new_dscp, ", ".join(utils.dscp)
                    )
                )
            self._dscp = utils.dscp[new_dscp]
        else:
            self._dscp = new_dscp

    @property
    def protocol(self):
        """
        Getter method for protocol attribute

        :return: protocol value, integer or string
        """
        return self._protocol if hasattr(self, "_protocol") else "any"

    @protocol.setter
    def protocol(self, new_proto):
        """
        Setter method for protocol attribute
        """
        if isinstance(new_proto, str):
            if new_proto in ["ip", "any", "ipv6", ""]:
                self._protocol = "any"
            elif new_proto in utils.ip_protocols:
                self._protocol = utils.ip_protocols[new_proto]
            else:
                raise ParameterError(
                    "Unknown IP protocol {0}, valid protocols: {1}".format(
                        new_proto, ", ".join(utils.ip_protocols)
                    )
                )
        else:
            self._protocol = new_proto

    @property
    def icmp_type(self):
        """
        Getter for icmp_type attribute

        :return: Icmp type value, string or integer
        """
        return self._icmp_type if hasattr(self, "_icmp_type") else None

    @icmp_type.setter
    def icmp_type(self, new_icmp_type):
        acl_type = self.__parent_acl.list_type
        icmp_types_dict = (
            utils.icmp_types if acl_type == "ipv4" else utils.icmpv6_types
        )
        if isinstance(new_icmp_type, str):
            if new_icmp_type in icmp_types_dict:
                self._icmp_type = icmp_types_dict[new_icmp_type]
            else:
                raise ParameterError(
                    "Invalid ICMP Type {0} - valid types are: {1}".format(
                        new_icmp_type, ", ".join(icmp_types_dict)
                    )
                )
        else:
            self._icmp_type = new_icmp_type

    @property
    def ethertype(self):
        """
        Getter for ethertype attribute

        :return: Ethertype value, integer or string
        """
        return self._ethertype if hasattr(self, "_ethertype") else None

    @ethertype.setter
    def ethertype(self, new_ethertype):
        """
        Setter for ethertype attribute
        """
        if isinstance(new_ethertype, str):
            if new_ethertype in utils.ethertypes:
                self._ethertype = utils.ethertypes[new_ethertype]
            else:
                raise ParameterError(
                    "Unknown Ethertype {0} - valid ethertypes are: {1}".format(
                        new_ethertype, ", ".join(utils.ethertypes)
                    )
                )
        else:
            self._ethertype = new_ethertype

    @property
    def src_l4_port_min(self):
        """
        Getter for src_l4_port_min attribute

        :return: Source minimum L4 port
        """
        return (
            self._src_l4_port_min
            if hasattr(self, "_src_l4_port_min")
            else None
        )

    @src_l4_port_min.setter
    def src_l4_port_min(self, new_l4_port):
        """
        Setter for src_l4_port_min attribute
        """
        if isinstance(new_l4_port, str):
            if new_l4_port in utils.l4_ports:
                self._src_l4_port_min = utils.l4_ports[new_l4_port]
            else:
                raise ParameterError(
                    "Unknown L4 port {0}, valid ports are: {1}".format(
                        new_l4_port, ", ".join(utils.l4_ports)
                    )
                )
        else:
            self._src_l4_port_min = new_l4_port

    @property
    def src_l4_port_max(self):
        """
        Getter for src_l4_port_max attribute

        :return: Source maximum L4 port
        """
        return (
            self._src_l4_port_max
            if hasattr(self, "_src_l4_port_max")
            else None
        )

    @src_l4_port_max.setter
    def src_l4_port_max(self, new_l4_port):
        """
        Setter for src_l4_port_max attribute
        """
        if isinstance(new_l4_port, str):
            if new_l4_port in utils.l4_ports:
                self._src_l4_port_max = utils.l4_ports[new_l4_port]
            else:
                raise ParameterError(
                    "Unknown L4 port {0}, valid ports are: {1}".format(
                        new_l4_port, ", ".join(utils.l4_ports)
                    )
                )
        else:
            self._src_l4_port_max = new_l4_port

    @property
    def dst_l4_port_min(self):
        """
        Getter for dst_l4_port_min attribute

        :return: Destination minimum L4 port
        """
        return (
            self._dst_l4_port_min
            if hasattr(self, "_dst_l4_port_min")
            else None
        )

    @dst_l4_port_min.setter
    def dst_l4_port_min(self, new_l4_port):
        """
        Setter for dst_l4_port_min attribute
        """
        if isinstance(new_l4_port, str):
            if new_l4_port in utils.l4_ports:
                self._dst_l4_port_min = utils.l4_ports[new_l4_port]
            else:
                raise ParameterError(
                    "Unknown L4 port {0}, valid ports are: {1}".format(
                        new_l4_port, ", ".join(utils.l4_ports)
                    )
                )
        else:
            self._dst_l4_port_min = new_l4_port

    @property
    def dst_l4_port_max(self):
        """
        Getter for dst_l4_port_max attribute

        :return: Destination maximum L4 port
        """
        return (
            self._dst_l4_port_max
            if hasattr(self, "_dst_l4_port_max")
            else None
        )

    @dst_l4_port_max.setter
    def dst_l4_port_max(self, new_l4_port):
        """
        Setter for src_l4_port_max attribute
        """
        if isinstance(new_l4_port, str):
            if new_l4_port in utils.l4_ports:
                self._dst_l4_port_max = utils.l4_ports[new_l4_port]
            else:
                raise ParameterError(
                    "Unknown L4 port {0}, valid ports are: {1}".format(
                        new_l4_port, ", ".join(utils.l4_ports)
                    )
                )
        else:
            self._dst_l4_port_max = new_l4_port
