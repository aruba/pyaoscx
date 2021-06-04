# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.pyaoscx_module import PyaoscxModule
from pyaoscx.utils.connection import connected

import json
import logging
import re
import pyaoscx.utils.util as utils


class OspfInterface(PyaoscxModule):
    '''
    Provide configuration management for OSPF Interface on AOS-CX devices.
    '''

    indices = ['interface_name']
    resource_uri_name = 'ospf_interfaces'

    def __init__(self, session, interface_name, parent_ospf_area, uri=None,
                 **kwargs):

        self.session = session
        # Assign ID
        self.interface_name = interface_name
        # Assign parent OspfArea object
        self.__set_ospf_area(parent_ospf_area)
        self._uri = uri
        # List used to determine attributes related to the OSPF Interface
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

    def __set_ospf_area(self, parent_ospf_area):
        '''
        Set parent OspfArea object as an attribute for the OspfInterface object
        :param parent_ospf_area: a OspfArea object
        '''

        # Set parent OspfArea object
        self.__parent_ospf_area = parent_ospf_area

        # Set URI
        self.base_uri = \
            '{base_ospf_area_uri}/{ospf_area_area_id}/ospf_interfaces'.format(
                base_ospf_area_uri=self.__parent_ospf_area.base_uri,
                ospf_area_area_id=self.__parent_ospf_area.area_id
            )

        for ospf_interface in self.__parent_ospf_area.ospf_interfaces:
            if ospf_interface.interface_name == self.interface_name:
                # Make list element point to current object
                ospf_interface = self
            else:
                # Add self to OspfInterface objects list in parent OspfArea object
                self.__parent_ospf_area.ospf_interfaces.append(self)

    @connected
    def get(self, depth=None, selector=None):
        '''
        Perform a GET call to retrieve data for a OSPF Interfaces table entry
        and fill the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        '''
        logging.info("Retrieving the switch OSPF Interface table entries")

        depth = self.session.api_version.default_depth if depth is None \
            else depth
        selector = self.session.api_version.default_selector if selector is \
            None else selector

        if not self.session.api_version.valid_depth(depth):
            depths = self.session.api_version.valid_depths
            raise Exception("ERROR: Depth should be {}".format(depths))

        if selector not in self.session.api_version.valid_selectors:
            selectors = ' '.join(self.session.api_version.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {}".format(selectors))

        payload = {
            "depth": depth,
            "selector": selector
        }

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id=self.interface_name
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

        # Determines if the OSPF Interfaces is configurable
        if selector in self.session.api_version.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(
                self, data, 'config_attrs', ['interface_name'])

        # Set original attributes
        self.__original_attributes = data

        # Remove ID
        if 'interface_name' in self.__original_attributes:
            self.__original_attributes.pop('interface_name')

        # If the OSPF Interface has a port inside the switch
        if hasattr(self, 'port') and \
                self.port is not None:
            port_response = self.port
            interface_cls = self.session.api_version.get_module(
                self.session, 'Interface', '')
            # Set port as a Interface Object
            self.port = interface_cls.from_response(
                self.session, port_response)
            self.port.get()

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_ospf_area):
        '''
        Perform a GET call to retrieve all system OSPF Interfaces inside a
        OSPF Area, and create a dictionary containing them as OspfInterface
        objects
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_ospf_area: parent OspfArea object where OspfInterface object
            is stored
        :return: Dictionary containing OSPF Interface IDs as keys and a
            OspfInterface objects as values
        '''

        logging.info("Retrieving the switch OSPF Interfaces of an OSPF area")

        base_uri = '{base_ospf_area_uri}/{ospf_area_area_id}/ospf_interfaces'.format(
            base_ospf_area_uri=parent_ospf_area.base_uri,
            ospf_area_area_id=parent_ospf_area.area_id)

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

        ospf_interface_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api_version.get_uri_from_data(data)

        for uri in uri_list:
            # Create a OspfInterface object
            interface_name, ospf_interface = OspfInterface.from_uri(
                session, parent_ospf_area, uri)
            # Load all OSPF Interfaces data from within the Switch
            ospf_interface.get()
            ospf_interface_dict[interface_name] = ospf_interface

        return ospf_interface_dict

    @connected
    def apply(self):
        '''
        Main method used to either create or update an existing
        OSPF Interface table entry.
        Checks whether the OSPF Interface exists in the switch
        Calls self.update() if OSPF Interface being updated
        Calls self.create() if a new OSPF Interface is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        '''
        if not self.__parent_ospf_area.materialized:
            self.__parent_ospf_area.apply()

        modified = False

        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        # Set internal attribute
        self.__modified = modified
        return modified

    @connected
    def update(self):
        '''
        Perform a PUT call to apply changes to an existing OSPF Interface table entry

        :return modified: True if Object was modified and a PUT request was made.
            False otherwise
        '''
        # Modified variable
        modified = False

        ospf_interface_data = {}

        ospf_interface_data = utils.get_attrs(self, self.config_attrs)

        # Get port uri
        if self.port is not None:
            ospf_interface_data["port"] = \
                self.port.get_info_format()

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id=self.interface_name
        )

        # Compare dictionaries
        if ospf_interface_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:

            post_data = json.dumps(
                ospf_interface_data, sort_keys=True, indent=4)

            try:
                response = self.session.s.put(
                    uri, verify=False, data=post_data, proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError('PUT', e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code)

            else:
                logging.info(
                    "SUCCESS: Update OSPF Interface table entry {} succeeded".format(
                        self.interface_name))
            # Set new original attributes
            self.__original_attributes = ospf_interface_data
            # Object was modified
            modified = True
        return modified

    @connected
    def create(self):
        '''
        Perform a POST call to create a new OSPF Interface table entry
        Only returns if an exception is not raise
        :return: True if OSPF Interface table entry was added
        '''

        ospf_interface_data = {}

        ospf_interface_data = utils.get_attrs(self, self.config_attrs)
        ospf_interface_data['interface_name'] = self.interface_name

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri
        )
        post_data = json.dumps(ospf_interface_data, sort_keys=True, indent=4)

        try:
            response = self.session.s.post(
                uri, verify=False, data=post_data, proxies=self.session.proxy)
        except Exception as e:
            raise ResponseError('POST', e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info(
                "SUCCESS: Adding OSPF Interface table entry {} succeeded".format(
                    self.interface_name))

        # Get all object's data
        self.get()
        # Object was modified
        return True

    @connected
    def delete(self):
        '''
        Perform DELETE call to delete OSPF Interface

        '''

        uri = "{base_url}{class_uri}/{id}".format(
            base_url=self.session.base_url,
            class_uri=self.base_uri,
            id=self.interface_name
        )

        try:
            response = self.session.s.delete(
                uri, verify=False, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('DELETE', e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Delete OSPF Interface table\
                         entry {} succeeded".format(self.interface_name))

        # Delete back reference from ospf_areas
        for ospf_interface in self.__parent_ospf_area.ospf_interfaces:
            if ospf_interface.interface_name == self.interface_name:
                self.__parent_ospf_area.ospf_interfaces.remove(ospf_interface)

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_ospf_area, response_data):
        '''
        Create a OspfInterface object given a response_data related to the
        OSPF Area ID object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_ospf_area: parent OspfArea object where OspfInterface
            object is stored
        :param response_data: The response can be either a
            dictionary: {
                    id: "/rest/v10.04/system/vrfs/<vrf_name>/ospf_routers/
                    instance_tag/areas/area_id/ospf_interfaces/id"
                }
            or a
            string: "/rest/v10.04/system/vrfs/<vrf_name>/ospf_routers/instance_tag/
                areas/area_id/ospf_interfaces/id"
        :return: OspfInterface object
        '''
        ospf_interface_arr = session.api_version.get_keys(
            response_data, OspfInterface.resource_uri_name)
        ospf_interface_name = ospf_interface_arr[0]
        return OspfInterface(session, ospf_interface_name, parent_ospf_area)

    @classmethod
    def from_uri(cls, session, parent_ospf_area, uri):
        '''
        Create a OspfInterface object given a URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_ospf_area: parent OspfArea object where OspfInterface
            object is stored

        :return index, ospf_interface_obj: tuple containing both the
            OspfInterface object and the OSPF Interface's ID
        '''
        # Obtain ID from URI
        index_pattern = re.compile(r'(.*)ospf_interfaces/(?P<index>.+)')
        index = index_pattern.match(uri).group('index')

        # Create OspfInterface object
        ospf_interface_obj = OspfInterface(
            session, index, parent_ospf_area, uri=uri)

        return index, ospf_interface_obj

    def __str__(self):
        return "OSPF Interface ID {}".format(self.interface_name)

    def get_uri(self):
        '''
        Method used to obtain the specific OSPF Interface uri
        return: Object's URI
        '''

        if self._uri is None:
            self._uri = '{resource_prefix}{class_uri}/{id}'.format(
                resource_prefix=self.session.resource_prefix,
                class_uri=self.base_uri,
                id=self.interface_name
            )

        return self._uri

    def get_info_format(self):
        '''
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
        '''
        return self.session.api_version.get_index(self)

    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified, False otherwise.
        """

        return self.__modified
