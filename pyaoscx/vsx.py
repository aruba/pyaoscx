# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.verification_error import VerificationError


from pyaoscx.pyaoscx_module import PyaoscxModule
from pyaoscx.vrf import Vrf
from pyaoscx.utils.connection import connected

import json
import logging
import pyaoscx.utils.util as utils


class Vsx(PyaoscxModule):
    '''
    Provide configuration management for VSX protocol on AOS-CX devices.
    '''

    base_uri = 'system/vsx'

    def __init__(self, session, uri=None, **kwargs):

        self.session = session
        self._uri = uri
        # List used to determine attributes related to the VSX configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    @connected
    def get(self, depth=None, selector=None):
        '''
        Perform a GET call to retrieve data for a VSX table entry and fill the
        class with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        '''
        logging.info("Retrieving the switch VSX configuration")

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
                "ERROR: Selector should be one of %s" % selectors)

        payload = {
            "depth": depth,
            "selector": selector
        }

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=Vsx.base_uri
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

        # Determines if VSX is configurable
        if selector in self.session.api_version.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, 'config_attrs')

        # Set original attributes
        self.__original_attributes = data

        # If the VSX has a isl_port inside the switch and a new one is not
        # being added
        if hasattr(self, 'isl_port') and self.isl_port is not None:
            isl_port_response = self.isl_port
            interface_cls = self.session.api_version.get_module(
                self.session, 'Interface', '')
            # Set port as a Interface Object
            self.isl_port = interface_cls.from_response(
                self.session, isl_port_response)
            self.isl_port.get()
        # If the VSX has a keepalive_vrf inside the switch and a new one is
        # not being added
        if hasattr(self, 'keepalive_vrf') and self.keepalive_vrf is not None:

            # Set keepalive VRF as a Vrf object
            self.keepalive_vrf = Vrf.from_response(
                self.session, self.keepalive_vrf)
            self.keepalive_vrf.get()

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        pass

    @classmethod
    def from_uri(cls, session, uri):
        '''
        Create a Vsx object given a VSX URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param uri: a String with a URI

        :return Vsx object
        '''
        # Create Vsx object
        vsx_obj = Vsx(session, uri=uri)

        return vsx_obj

    @connected
    def apply(self):
        '''
        Main method used to either create or update an existing VSX configuration.
        Checks whether the VSX configuration exists in the switch
        Calls self.update() if VSX configuration being updated
        Calls self.create() if a new VSX configuration is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        '''

        # Verify ISL port is materialized inside switch and has NO-routing
        # status
        if not self.isl_port.materialized or self.isl_port.routing:
            raise VerificationError(
                'Interface', 'Object not materialized--or--routing enabled')
        # Verify that VRF is materialized inside switch
        if not self.keepalive_vrf.materialized:
            raise VerificationError('VRF', 'Object not materialized')

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
        Perform a PUT call to apply changes to an existing VSX inside the switch

        :return modified: True if Object was modified and a PUT request
            was made. False otherwise

        '''

        vsx_data = {}
        vsx_data = utils.get_attrs(self, self.config_attrs)

        # Get VRF uri
        vsx_data["keepalive_vrf"] = self.keepalive_vrf.get_info_format()
        # Get ISL port uri
        vsx_data["isl_port"] = self.isl_port.get_info_format()

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=Vsx.base_uri
        )

        # Compare dictionaries
        if vsx_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(vsx_data, sort_keys=True, indent=4)

            try:
                response = self.session.s.put(
                    uri, verify=False, data=post_data, proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError('PUT', e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code)

            else:
                logging.info("SUCCESS: Adding VSX configuration")
            # Set new original attributes
            self.__original_attributes = vsx_data
            # Object was modified
            modified = True
        return modified

    @connected
    def create(self):
        '''
        Perform a POST call to create a new VSX
        Only returns if an exception is not raise

        return: True if entry was created
        '''

        vsx_data = {}
        vsx_data = utils.get_attrs(self, self.config_attrs)

        # Verify Keepalive is created
        if hasattr(self, 'keepalive_vrf'):
            if not self.keepalive_vrf.materialized:
                raise VerificationError(
                    'Keepalive Vrf', 'Object not materialized')

            # Get VRF uri
            vsx_data["keepalive_vrf"] = self.keepalive_vrf.get_info_format()

        if hasattr(self, 'isl_port'):
            if not self.isl_port.materialized:
                raise VerificationError('Isl Port ', 'Object not materialized')

            # Get ISL port uri
            vsx_data["isl_port"] = self.isl_port.get_info_format()

        if hasattr(self, 'keepalive_peer') and \
                hasattr(self, 'keepalive_src') and \
                self.keepalive_src is not None and \
                self.keepalive_src is not None:

            ip_src_subnet = self.keepalive_src.find('/')
            ip_peer_subnet = self.keepalive_peer.find('/')

            if ip_src_subnet >= 0:
                self.keepalive_src = self.keepalive_src[0:ip_src_subnet]

            if ip_peer_subnet >= 0:
                self.keepalive_peer = self.keepalive_peer[0:ip_peer_subnet]

            vsx_data["keepalive_peer_ip"] = self.keepalive_peer
            vsx_data["keepalive_src_ip"] = self.keepalive_src

        if hasattr(self, 'system_mac') and self.system_mac is not None:
            vsx_data["system_mac"] = self.system_mac

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=Vsx.base_uri
        )

        post_data = json.dumps(vsx_data, sort_keys=True, indent=4)

        try:
            response = self.session.s.post(
                uri, verify=False, data=post_data, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('POST', e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Adding VSX table entry succeeded")

        # Get all objects data
        self.get()
        # Object was modified
        return True

    @connected
    def delete(self):
        '''
        Perform DELETE call to delete VSX configuration.

        '''

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=Vsx.base_uri
        )

        try:
            response = self.session.s.delete(
                uri, verify=False, proxies=self.session.proxy)
        except Exception as e:
            raise ResponseError('DELETE', e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        else:
            logging.info("SUCCESS: Delete VSX configuration succeeded")

    def get_uri(self):
        '''
        Method used to obtain the specific VSX URI
        return: Object's URI
        '''
        if self._uri is None:
            self._uri = '{resource_prefix}{class_uri}'.format(
                resource_prefix=self.session.resource_prefix,
                class_uri=Vsx.base_uri
            )
        return self._uri

    def get_info_format(self):
        '''
        Not applicable for VSX
        '''
        pass

    def was_modified(self):
        """
        Getter method for the __modified attribute
        :return: Boolean True if the object was recently modified, False otherwise.
        """

        return self.__modified
