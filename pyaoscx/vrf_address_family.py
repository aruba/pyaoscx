# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.pyaoscx_module import PyaoscxModule


import json
import logging
import re
import pyaoscx.utils.util as utils


class VrfAddressFamily(PyaoscxModule):
    '''
    Provide configuration management for Address Family settings on AOS-CX
        devices.
    '''

    indices = ['address_family']
    resource_uri_name = 'vrf_address_families'

    def __init__(self, session, address_family, parent_vrf, uri=None,
                 **kwargs):

        self.session = session
        # Assign ID
        self.address_family = address_family
        # Assign parent Vrf object
        self.__set_vrf(parent_vrf)
        self._uri = uri
        # List used to determine attributes related to the VRF Address Family
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

    def __set_vrf(self, parent_vrf):
        '''
        Set parent VRF as an attribute for the VrfAddressFamily object
        :param parent_vrf: a Vrf object
        '''

        # Set parent_vrf
        self.__parent_vrf = parent_vrf

        # Set URI
        self.base_uri = '{0}/{1}/vrf_address_families'.format(
            self.__parent_vrf.base_uri, self.__parent_vrf.name
        )

        # Verify VRF Address Family  doesn't exist already inside VRF
        for vrf_address_family in self.__parent_vrf.address_families:
            if vrf_address_family.address_family == self.address_family:
                # Make list element point to current object
                vrf_address_family = self
            else:
                # Add self to vrf_address_families list in parent_vrf
                self.__parent_vrf.address_families.append(self)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        '''
        Perform a GET call to retrieve data for a VRF Address Family table
        entry and fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        '''
        logging.info("Retrieving the switch VRF Address families")

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

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

        uri = "{base_url}{class_uri}/{address_family}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            address_family=self.address_family
        )

        try:
            response = self.session.s.get(
                uri, verify=False, params=payload, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the VrfAddressFamily object is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, 'config_attrs', ['address_family'])

        # Set original attributes
        self.__original_attributes = data

        # Remove ID
        if 'address_family' in self.__original_attributes:
            self.__original_attributes.pop('address_family')

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_vrf):
        '''
        Perform a GET call to retrieve all system VRF Address Families inside a
        VRF, and create a dictionary containing them
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent Vrf object where VRF Address Family is stored
        :return: Dictionary containing VRF Address Family IDs as keys and a
            VrfAddressFamily objects as values
        '''

        logging.info("Retrieving the switch VRF Address Family")

        base_uri = '{base_vrf_uri}/{vrf_name}/vrf_address_families'.format(
            base_vrf_uri=parent_vrf.base_uri,
            vrf_name=parent_vrf.name)

        uri = '{base_url}{class_uri}'.format(
            base_url=session.base_url,
            class_uri=base_uri)

        try:
            response = session.s.get(uri, verify=False, proxies=session.proxy)
        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        vrf_address_family_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a VrfAddressFamily object and adds it to parent
            # VRF list
            address_family, vrf_address_family = VrfAddressFamily.from_uri(
                session, parent_vrf, uri)
            # Load all VRF Address Families data from within the Switch
            vrf_address_family.get()
            vrf_address_family_dict[address_family] = vrf_address_family

        return vrf_address_family_dict

    @PyaoscxModule.connected
    def apply(self):
        '''
        Main method used to either create or update
        an existing VrfAddressFamily object
        Checks whether the VRF Address Family exists in the switch
        Calls self.update() if VRF Address Family being updated
        Calls self.create() if a new VRF Address Family is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        '''
        if not self.__parent_vrf.materialized:
            self.__parent_vrf.apply()

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
        Perform a PUT call to apply changes to an existing VRF Address Family
            table entry.
        :return modified: True if Object was modified and a PUT request was
            made. False otherwise.
        '''
        vrf_address_family_data = utils.get_attrs(self, self.config_attrs)

        uri = "{base_url}{class_uri}/{address_family}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            address_family=self.address_family
        )

        # Compare dictionaries
        if vrf_address_family_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(vrf_address_family_data)

            try:
                response = self.session.s.put(
                    uri,
                    verify=False,
                    data=post_data,
                    proxies=self.session.proxy
                )

            except Exception as e:
                raise ResponseError('PUT', e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code)

            logging.info("SUCCESS: Updating %s", self)

            # Set new original attributes
            self.__original_attributes = vrf_address_family_data
            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        '''
        Perform a POST call to create a new VRF Address Family table entry
        Only returns if an exception is not raise
        return: True if entry was created
        '''
        vrf_address_family_data = utils.get_attrs(self, self.config_attrs)
        vrf_address_family_data['address_family'] = self.address_family

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri
        )
        post_data = json.dumps(vrf_address_family_data)

        try:
            response = self.session.s.post(
                uri, verify=False, data=post_data, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('POST', e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all object's data
        self.get()
        # Object was modified
        return True

    @PyaoscxModule.connected
    def delete(self):
        '''
        Perform DELETE call to delete VRF Address Family table entry

        '''

        uri = "{base_url}{class_uri}/{address_family}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            address_family=self.address_family
        )

        try:
            response = self.session.s.delete(
                uri, verify=False, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('DELETE', e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

        # Delete back reference from VRF
        for vrf_address_family in self.__parent_vrf.address_families:
            if vrf_address_family.address_family == self.address_family:
                self.__parent_vrf.address_families.remove(vrf_address_family)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vrf, response_data):
        '''
        Create a VrfAddressFamily object given a response_data related to
            the VRF Address Family's address_family
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a
            logical connection to the device
        :param parent_vrf: parent Vrf object where VrfAddressFamlily object is
            stored.
        :param response_data: The response can be either a dictionary:
            {
                addr_fam: <URL>
            }
            with URL: "/rest/v10.04/system/vrfs/vrf_address_families/addr_fam"
            or a string with just the URL
        :return: VrfAddressFamily object
        '''
        vrf_address_family_arr = session.api.get_keys(
            response_data, VrfAddressFamily.resource_uri_name)
        address_family = vrf_address_family_arr[0]
        return VrfAddressFamily(session, address_family, parent_vrf)

    @classmethod
    def from_uri(cls, session, parent_vrf, uri):
        '''
        Create a VrfAddressFamily object given a URI and a specified parent VRF
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_vrf: parent vrf class where VRF Address Family is stored
        :param uri: a String with a URI

        :return index, vrf_address_family_obj: tuple containing both the VRF
            Address Family object and the VRF Address Family's address_family
        '''
        # Obtain ID from URI
        index_pattern = re.compile(r'(.*)vrf_address_families/(?P<index>.+)')
        index = index_pattern.match(uri).group('index')
        # Create VrfAddressFamily object
        vrf_address_family_obj = VrfAddressFamily(
            session, index, parent_vrf, uri=uri)

        return index, vrf_address_family_obj

    def __str__(self):
        return "VRF Address Family ID {}".format(self.address_family)

    @PyaoscxModule.deprecated
    def get_uri(self):
        '''
        Method used to obtain the specific VRF Address Family URI
        return: Object's URI
        '''

        if self._uri is None:
            self._uri = '{resource_prefix}{class_uri}/{address_family}'.format(
                resource_prefix=self.session.resource_prefix,
                class_uri=self.base_uri,
                address_family=self.address_family
            )

        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        '''
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
        '''
        return self.session.api.get_index(self)

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified
        """
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified, False
            otherwise.
        """
        return self.modified
