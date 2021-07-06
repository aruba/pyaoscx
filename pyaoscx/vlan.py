# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.pyaoscx_module import PyaoscxModule

import json
import logging
import re
import pyaoscx.utils.util as utils


class Vlan(PyaoscxModule):
    '''
    Provide configuration management for VLANs on AOS-CX devices.
    '''

    base_uri = 'system/vlans'
    resource_uri_name = 'vlans'
    indices = ['id']

    def __init__(self, session, vlan_id, uri=None, **kwargs):

        self.session = session
        self._uri = uri
        self.id = vlan_id
        # List used to determine attributes related to the VLAN configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        '''
        Perform a GET call to retrieve data for a VLAN table entry and fill
        the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        '''
        logging.info("Retrieving the switch VLANs")

        depth = self.session.api.default_depth if depth is None \
            else depth
        selector = self.session.api.default_selector if selector \
            is None else selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {}".format(depths))

        if selector not in self.session.api.valid_selectors:
            selectors = ' '.join(self.session.api.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {}".format(selectors))

        payload = {
            "depth": depth,
            "selector": selector
        }

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=Vlan.base_uri,
            id=self.id
        )

        try:
            response = self.session.s.get(
                uri, verify=False, params=payload,
                proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(
                response.text, response.status_code, "GET VLAN")

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the VLAN is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, 'config_attrs', ['id'])

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if 'id' in self.__original_attributes:
            self.__original_attributes.pop('id')

        # Set all ACLs
        from pyaoscx.acl import ACL
        if hasattr(self, 'aclmac_in_cfg') and self.aclmac_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclmac_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclmac_in_cfg = acl

        if hasattr(self, 'aclv4_in_cfg') and self.aclv4_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv4_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv4_in_cfg = acl

        if hasattr(self, 'aclv6_in_cfg') and self.aclv6_in_cfg is not None:
            # Create Acl object
            acl = ACL.from_response(self.session, self.aclv6_in_cfg)
            # Materialize Acl object
            acl.get()
            self.aclv6_in_cfg = acl

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        '''
        Perform a GET call to retrieve all system VLAN and create a dictionary
        containing each respective VLAN
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :return: Dictionary containing VLAN IDs as keys and a Vlan object as
            value
        '''

        logging.info("Retrieving the switch VLANs")

        uri = '{base_url}{class_uri}'.format(
            base_url=session.base_url,
            class_uri=Vlan.base_uri)

        try:
            response = session.s.get(uri, verify=False, proxies=session.proxy)
        except Exception as e:
            raise ResponseError('GET', e)

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
        '''
        Main method used to either create or update an existing
        VLAN table entry.
        Checks whether the VLAN exists in the switch
        Calls self.update() if VLAN is being updated
        Calls self.create() if a new VLAN is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        '''
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
        Perform a PUT call to apply changes to an existing VLAN table entry

        :return modified: True if Object was modified and a PUT request was made.
            False otherwise

        '''
        # Variable returned
        modified = False

        vlan_data = {}

        vlan_data = utils.get_attrs(self, self.config_attrs)

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=Vlan.base_uri,
            id=self.id
        )

        # Set all ACLs
        if "aclmac_in_cfg" in vlan_data and self.aclmac_in_cfg is not None:
            # Set values in correct form
            vlan_data["aclmac_in_cfg"] = \
                self.aclmac_in_cfg.get_info_format()

        if "aclv4_in_cfg" in vlan_data and self.aclv4_in_cfg is not None:
            # Set values in correct form
            vlan_data["aclv4_in_cfg"] = self.aclv4_in_cfg.get_info_format()

        if "aclv6_in_cfg" in vlan_data and self.aclv6_in_cfg is not None:
            # Set values in correct form
            vlan_data["aclv6_in_cfg"] = self.aclv6_in_cfg.get_info_format()

        # Compare dictionaries
        if vlan_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:

            post_data = json.dumps(vlan_data, sort_keys=True, indent=4)

            try:
                response = self.session.s.put(
                    uri, verify=False, data=post_data,
                    proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError('PUT', e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code, "UPDATE VLAN")

            else:
                logging.info("SUCCESS: Adding VLAN table entry '{}' \
                    succeeded".format(self.id))
            # Set new original attributes
            self.__original_attributes = vlan_data

            # Object was modified, returns True
            modified = True

        return modified

    @PyaoscxModule.connected
    def create(self):
        '''
        Perform a POST call to create a new VLAN using the object's attributes
        as POST body. Exception is raised if object is unable to be created

        :return modified: Boolean, True if entry was created
        '''

        vlan_data = {}

        # Get all VLAN data given by the user
        vlan_data = utils.get_attrs(self, self.config_attrs)
        if isinstance(self.id, str):
            self.id = int(self.id)
        vlan_data['id'] = self.id

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=Vlan.base_uri
        )

        post_data = json.dumps(vlan_data, sort_keys=True, indent=4)

        try:
            response = self.session.s.post(
                uri, verify=False, data=post_data, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('POST', e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Adding VLAN table entry '{}' \
                succeeded".format(self.id))

        # Get all objects data
        self.get()

        return True

    @PyaoscxModule.connected
    def delete(self):
        '''
        Perform DELETE call to delete VLAN table entry.

        '''

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=Vlan.base_uri,
            id=self.id
        )

        try:
            response = self.session.s.delete(
                uri, verify=False, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('DELETE', e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(
                response.text, response.status_code, "DELETE VLAN")

        else:
            logging.info("SUCCESS: Delete VLAN table entry '{}'\
                succeeded".format(self.id))

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        '''
        Create a Vlan object given a response_data related to the Vlan object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param response_data: The response can be either a
            dictionary: {
                    1: "/rest/v10.04/system/vlans/1"
                }
            or a
            string: "/rest/v1/system/vlans/1"
        :return: Vlan Object
        '''
        vlan_id_arr = session.api.get_keys(
            response_data, Vlan.resource_uri_name)
        vlan_id = vlan_id_arr[0]
        return Vlan(session, vlan_id)

    @classmethod
    def from_uri(cls, session, uri):
        '''
        Create a Vlan object given a VLAN URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param uri: a String with a URI

        :return vlan_id, vlan: tuple containing both the Vlan object and the VLAN's
            ID
        '''
        # Obtain ID from URI
        index_pattern = re.compile(r'(.*)vlans/(?P<index>.+)')
        index_str = index_pattern.match(uri).group('index')
        vlan_id = int(index_str)
        # Create Vlan object
        vlan_obj = Vlan(session, vlan_id, uri=uri)

        return vlan_id, vlan_obj

    @classmethod
    def get_facts(cls, session):
        '''
        Modify this to Perform a GET call to retrieve all VLANs and their respective data
        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device

        :return facts: Dictionary containing VLAN IDs as keys and Vlan objects as values

        '''
        # Log
        logging.info("Retrieving switch VLANs facts")

        # Set VLAN facts depth
        vlan_depth = session.api.default_facts_depth

        # Build URI
        uri = '{base_url}{class_uri}?depth={depth}'.format(
            base_url=session.base_url,
            class_uri=Vlan.base_uri,
            depth=vlan_depth
        )

        try:
            # Try to get facts data via GET method
            response = session.s.get(
                uri,
                verify=False,
                proxies=session.proxy
            )

        except Exception as e:
            raise ResponseError('GET', e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(
                response.text,
                response.status_code)

        # Load response text into json format
        facts = json.loads(response.text)

        # Delete internal VLANs
        internal_vlan_list = []
        for vlan in facts.keys():
            if 'type' in facts[vlan].keys():
                if facts[vlan]['type'] == 'internal':
                    internal_vlan_list.append(vlan)

        for vlan in internal_vlan_list:
            facts.pop(vlan)

        return facts

    def __str__(self):
        try:
            return "Vlan, name: '{}' ID: '{}' and description: '{}'"\
                .format(self.name, self.id, self.description)
        except Exception:
            return "Vlan, ID: '{}'".format(self.id)

    def get_uri(self):
        '''
        Method used to obtain the specific VLAN URI
        return: Object's URI
        '''

        if self._uri is None:
            self._uri = '{resource_prefix}{class_uri}/{id}'.format(
                resource_prefix=self.session.resource_prefix,
                class_uri=Vlan.base_uri,
                id=self.id
            )

        return self._uri

    def get_info_format(self):
        '''
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
        '''
        return self.session.api.get_index(self)

    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified, False otherwise.
        """

        return self.__modified

    ####################################################################
    # IMPERATIVES FUNCTIONS
    ####################################################################

    def modify(self, vlan_name=None, vlan_desc=None, admin_conf_state=None):
        """
        Perform a PUT calls to modify an existing VLAN.

        :param vlan_name: Optional Alphanumeric name of VLAN. Won't be
            modified if not specified.
        :param vlan_desc: Optional description to add to VLAN. Won't be
            modified if not specified.
        :param admin_conf_state: Optional administratively-configured state of
            VLAN. Won't be modified if not specified.
            Only configurable for static VLANs.
        :return: True if object was changed, False otherwise
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
        Update ACL IN values inside a Vlan object

        :param acl_name: Alphanumeric String that is the name of the ACL
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to
            specify the type of ACL
        :return: True if object was changed, False otherwise

        """
        import random

        # Create Acl object
        acl_obj = self.session.api.get_module(
            self.session, 'ACL', index_id=acl_name, list_type=list_type)

        if list_type == "ipv6":
            self.aclv6_in_cfg = acl_obj
            if self.aclv6_in_cfg_version is None:
                self.aclv6_in_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991)
        if list_type == "ipv4":
            self.aclv4_in_cfg = acl_obj
            if self.aclv4_in_cfg_version is None:
                self.aclv4_in_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991)
        if list_type == "mac":
            self.aclmac_in_cfg = acl_obj
            if self.aclmac_in_cfg_version is None:
                self.aclmac_in_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991)

        # Apply changes
        return self.apply()

    def attach_acl_out(self, acl_name, list_type):
        """
        Update ACL OUT values inside a Vlan object

        :param acl_name: Alphanumeric String that is the name of the ACL
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to
            specify the type of ACL
        :return: True if object was changed, False otherwise

        """
        import random

        # Create Acl object
        acl_obj = self.session.api.get_module(
            self.session, 'ACL', index_id=acl_name, list_type=list_type)

        if list_type == "ipv6":
            self.aclv6_out_cfg = acl_obj
            if self.aclv6_out_cfg_version is None:
                self.aclv6_out_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991)
        if list_type == "ipv4":
            self.aclv4_out_cfg = acl_obj
            if self.aclv4_out_cfg_version is None:
                self.aclv4_out_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991)
        if list_type == "mac":
            self.aclmac_out_cfg = acl_obj
            if self.aclmac_out_cfg_version is None:
                self.aclmac_out_cfg_version = random.randint(
                    -9007199254740991, 9007199254740991)

        # Apply changes
        return self.apply()

    def detach_acl_in(self, acl_name, list_type):
        """
        Detach an ACL from a VLAN

        :param acl_name: Alphanumeric String that is the name of the ACL
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to
            specify the type of ACL
        :return: True if object was changed, False otherwise

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
        Detach an ACL from a VLAN

        :param acl_name: Alphanumeric String that is the name of the ACL
        :param list_type: Alphanumeric String of ipv4, ipv6, or mac to
            specify the type of ACL
        :return: True if object was changed, False otherwise

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
