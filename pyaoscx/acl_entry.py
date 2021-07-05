# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.pyaoscx_module import PyaoscxModule


import json
import logging
import re
import pyaoscx.utils.util as utils


class AclEntry(PyaoscxModule):
    '''
    Provide configuration management for ACL Entry on AOS-CX devices.
    '''

    indices = ['sequence_number']
    resource_uri_name = 'cfg_aces'

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
        "udp": 17
    }

    def __init__(self,
                 session,
                 sequence_number,
                 parent_acl,
                 uri=None,
                 **kwargs):

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
        '''
        Set parent Acl object as an attribute for the AclEntry object
        :param parent_acl: a Acl object
        '''

        # Set parent acl
        self.__parent_acl = parent_acl

        # Set URI
        self.base_uri = '{base_acl_uri}/{id1}{separator}{id2}/cfg_aces'.format(
            base_acl_uri=self.__parent_acl.base_uri,
            id1=self.__parent_acl.name,
            separator=self.session.api_version.compound_index_separator,
            id2=self.__parent_acl.list_type)

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
        '''
        Perform a GET call to retrieve data for an ACL Entry table entry and
        fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        '''
        logging.info("Retrieving the switch ACL Entries")

        depth = self.session.api_version.default_depth \
            if depth is None else depth
        selector = self.session.api_version.default_selector \
            if selector is None else selector

        if not self.session.api_version.valid_depth(depth):
            depths = self.session.api_version.valid_depths
            raise Exception("ERROR: Depth should be {}".format(depths))

        if selector not in self.session.api_version.valid_selectors:
            selectors = ' '.join(self.session.api_version.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {}".format(selectors))

        payload = {"depth": depth, "selector": selector}

        uri = "{base_url}{class_uri}/{sequence_number}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            sequence_number=self.sequence_number)

        try:
            response = self.session.s.get(uri,
                                          verify=False,
                                          params=payload,
                                          proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the ACL Entry is configurable
        if selector in self.session.api_version.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, 'config_attrs',
                                   ['sequence_number'])

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if 'sequence_number' in self.__original_attributes:
            self.__original_attributes.pop('sequence_number')

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_acl):
        '''
        Perform a GET call to retrieve all system ACL Entries inside an ACL,
        and create a dictionary containing them
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_acl: parent Acl object where ACL Entry is stored
        :return acl_entry_dict: Dictionary containing ACL Entry IDs as keys
            and an ACL Entry objects as values
        '''

        logging.info("Retrieving all ACL entries within switch for ACL")
        # Set URI
        base_uri = '{base_acl_uri}/{id1}{separator}{id2}/cfg_aces'.format(
            base_acl_uri=parent_acl.base_uri,
            id1=parent_acl.name,
            separator=session.api_version.compound_index_separator,
            id2=parent_acl.list_type)

        uri = '{base_url}{class_uri}'.format(base_url=session.base_url,
                                             class_uri=base_uri)

        try:
            response = session.s.get(uri, verify=False, proxies=session.proxy)
        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        acl_entry_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api_version.get_uri_from_data(data)

        for uri in uri_list:
            # Create a AclEntry object and adds it to parent acl list
            sequence_number, acl_entry = AclEntry.from_uri(
                session, parent_acl, uri)
            # Load all acl_entry data from within the Switch
            acl_entry.get()
            acl_entry_dict[sequence_number] = acl_entry

        return acl_entry_dict

    @PyaoscxModule.connected
    def apply(self):
        '''
        Main method used to either create a new ACL Entry or update an existing
        AclEntry.
        Checks whether the ACL Entry exists in the switch
        Calls self.update() if ACL Entry being updated
        Calls self.create() if a new ACL Entry is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        '''
        if not self.__parent_acl.materialized:
            self.__parent_acl.apply()

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
        '''
        Perform a PUT call to apply changes to an existing ACL Entry

        :return modified: True if Object was modified and a PUT request
            was made. False otherwise
        '''
        # Variable returned
        modified = False

        acl_entry_data = {}
        acl_entry_data = utils.get_attrs(self, self.config_attrs)

        uri = "{base_url}{class_uri}/{sequence_number}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            sequence_number=self.sequence_number)

        # Compare dictionaries
        if acl_entry_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(acl_entry_data, sort_keys=True, indent=4)

            try:
                response = self.session.s.put(uri,
                                              verify=False,
                                              data=post_data,
                                              proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError('PUT', e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(response.text,
                                            response.status_code)

            else:
                logging.info(
                    "SUCCESS: Update ACL Entry table entry {} succeeded\
                    ".format(self.sequence_number))
            # Set new original attributes
            self.__original_attributes = acl_entry_data

            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        '''
        Perform a POST call to create a new ACL Entry.
        Only returns if an exception is not raise

        :return modified: Boolean, True if entry was created

        '''

        acl_entry_data = {}

        acl_entry_data = utils.get_attrs(self, self.config_attrs)
        acl_entry_data['sequence_number'] = self.sequence_number

        uri = "{base_url}{class_uri}".format(base_url=self.session.base_url,
                                             class_uri=self.base_uri)

        # Try to get protocol number
        try:
            if isinstance(self.protocol, str):
                if self.protocol == 'any' or self.protocol == '':
                    acl_entry_data.pop('protocol')
                else:
                    protocol_num = self.protocol_dict[self.protocol]
                    acl_entry_data['protocol'] = protocol_num
            elif isinstance(self.protocol, int):
                acl_entry_data['protocol'] = self.protocol
        except Exception:
            pass
        post_data = json.dumps(acl_entry_data, sort_keys=True, indent=4)

        try:
            response = self.session.s.post(uri,
                                           verify=False,
                                           data=post_data,
                                           proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('POST', e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Adding ACL Entry table entry {} succeeded\
                ".format(self.sequence_number))

        # Get all object's data
        self.get()

        # Object was created, means modified
        return True

    @PyaoscxModule.connected
    def delete(self):
        '''
        Perform DELETE call to delete ACL Entry from parent ACL on the switch.

        '''

        uri = "{base_url}{class_uri}/{sequence_number}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            sequence_number=self.sequence_number)

        try:
            response = self.session.s.delete(uri,
                                             verify=False,
                                             proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('DELETE', e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info(
                "SUCCESS: Delete ACL Entry table entry {} succeeded".format(
                    self.sequence_number))

        # Delete back reference from ACL
        for acl_entry in self.__parent_acl.cfg_aces:
            if acl_entry.sequence_number == self.sequence_number:
                self.__parent_acl.cfg_aces.remove(acl_entry)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_acl, response_data):
        '''
        Create a AclEntry object given a response_data related to the ACL Entry
            sequence_number object
        :param cls: Class calling the method
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_acl: parent Acl object where ACL Entry is stored
        :param response_data: The response can be either a
            dictionary: {
                    sequence_number: "/rest/v10.04/system/acls/cfg_aces/
                        sequence_number"
                }
            or a
            string: "/rest/v10.04/system/acls/cfg_aces/sequence_number"
        :return: AclEntry object
        '''
        acl_entry_arr = session.api_version.get_keys(
            response_data, AclEntry.resource_uri_name)
        sequence_number = acl_entry_arr[0]
        return AclEntry(session, sequence_number, parent_acl)

    @classmethod
    def from_uri(cls, session, parent_acl, uri):
        '''
        Create a AclEntry object given a URI
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_acl: parent Acl object where ACL Entry is stored
        :param uri: a String with a URI

        :return index, acl_entry_obj: tuple containing both the AclEntry
            object and the acl_entry's sequence_number
        '''
        # Obtain ID from URI
        index_pattern = re.compile(r'(.*)cfg_aces/(?P<index>.+)')
        index = index_pattern.match(uri).group('index')

        # Create AclEntry object
        acl_entry_obj = AclEntry(session, index, parent_acl, uri=uri)

        return index, acl_entry_obj

    def __str__(self):
        return "ACL Entry ID {}".format(self.sequence_number)

    def get_uri(self):
        '''
        Method used to obtain the specific ACL Entry URI
        return: AclEntry object's URI
        '''

        if self._uri is None:
            self._uri = (
                '{resource_prefix}{class_uri}/{sequence_number}'.format(
                    resource_prefix=self.session.resource_prefix,
                    class_uri=self.base_uri,
                    sequence_number=self.sequence_number))

        return self._uri

    def get_info_format(self):
        '''
        Method used to obtain correct object format for referencing inside
        other objects
        return: AclEntry object format depending on the API Version
        '''
        return self.session.api_version.get_index(self)

    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified,
            False otherwise.
        """

        return self.__modified

    ####################################################################
    # IMPERATIVES FUNCTIONS
    ####################################################################

    def modify(self,
               action=None,
               count=None,
               src_ip=None,
               dst_ip=None,
               dst_l4_port_min=None,
               dst_l4_port_max=None,
               src_mac=None,
               dst_mac=None,
               ethertype=None):
        """
        Create an AclEntry object, ACL Entry already exists, value passed
        won't update the entry

        :param action: Action should be either "permit" or "deny"
        :param count: Optional boolean flag that when true, will make entry
            increment hit count for matched packets
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
        :return: True if object was changed

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
