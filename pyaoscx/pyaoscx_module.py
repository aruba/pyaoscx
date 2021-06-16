# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import functools
import pyaoscx.utils.util as utils
from abc import ABC, abstractmethod
from pyaoscx.exceptions.verification_error import VerificationError
from pyaoscx.utils.connection import connected
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError


class PyaoscxModule(ABC):
    '''
    Provide an Interface class for pyaoscx Modules
    '''

    def connected(fnct):
        '''
        Function used as a decorator to ensure the module has a established
        connection

        :param fnct: function which behavior is modified
        :return ensure_connected: Function
        '''
        @functools.wraps(fnct)
        def ensure_connected(self, *args):
            if not self.session.connected:
                self.session.open()
            return fnct(self, *args)
        return ensure_connected

    def materialized(fnct):
        """
        Function used as a decorator to verify if the object is materialized.

        :para fnct: function which behavior is modified
        :return is_materialized: Function
        """
        @functools.wraps(fnct)
        def is_materialized(self, *args):
            if not self.materialized:
                raise VerificationError("Object {}".format(self),
                                        " not materialized")
            return fnct(self, *args)
        return is_materialized

    base_uri = ""
    indices = []

    @abstractmethod
    @connected
    def get(self, depth=None, selector=None):
        '''
        Perform a GET call to retrieve data for a table entry and fill
        the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        '''
        pass

    @abstractmethod
    def get_all(cls, session):
        '''
        Perform a GET call to retrieve all system <pyaoscx_module_type> and create a dictionary
        of each object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :return: Dictionary containing object IDs as keys their respective objects as
            values
        '''
        pass

    @abstractmethod
    @connected
    def apply(self):
        '''
        Main method used to either create or update an existing
        <pyaoscx_module_type>.
        Checks whether the <pyaoscx_module_type> exists in the switch
        Calls self.update() if object being updated
        Calls self.create() if a new <pyaoscx_module_type> is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        '''
        pass

    @abstractmethod
    @connected
    def update(self):
        '''
        Perform a PUT call to apply changes to an existing
        <pyaoscx_module_type> table entry

        :return modified: True if Object was modified and a PUT request was made.
            False otherwise

        '''
        pass

    @abstractmethod
    @connected
    def create(self):
        '''
        Perform a POST call to create a new <pyaoscx_module_type>
        Only returns if an exception is not raise

        :return modified: Boolean, True if entry was created

        '''
        pass

    @abstractmethod
    @connected
    def delete(self):
        '''
        Perform DELETE call to delete <pyaoscx_module_type> table entry.

        '''
        pass

    def get_uri(self):
        '''
        Method used to obtain the specific <pyaoscx_module_type> URI
        return: Object's URI
        '''
        pass

    def get_info_format(self):
        '''
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
        '''
        pass

    @abstractmethod
    def from_uri(cls, session, uri):
        '''
        Create a <pyaoscx_module_type> object given a <pyaoscx_module_type> URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param uri: a String with a URI

        :return index, <pyaoscx_module_type>: tuple containing both the <pyaoscx_module_type> object and the
            <pyaoscx_module_type>'s ID
        '''
        pass

    def _get_data(self, depth, selector):
        """
        Perform a GET call to retrieve data from a switch.

        :param depth: Integer deciding how many levels into the API JSON
            that references will be retrieved from the switch
        :param selector: Alphanumeric option to select specific information
            to return.
        :return: Retrieved data from the switch.
        """

        depth = self.session.api.default_depth \
            if depth is None else depth
        selector = self.session.api.default_selector \
            if selector is None else selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be one of {}".format(depths))

        if selector not in self.session.api.valid_selectors:
            selectors = ' '.join(self.session.api.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {}".format(selectors))

        payload = {
            "depth": depth,
            "selector": selector
        }

        try:
            response = self.session.request("GET", self.path, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        return json.loads(response.text)

    def _put_data(self, data):
        """
        Perform a PUT request to the switch.

        :param data: data to send.
        :return: True if the object was modified
        """

        if data == self._original_attributes:
            return False

        self._send_data(self.path, data, "PUT", "Update")
        # Set new original attributes
        self._original_attributes = data
        # Object was modified
        return True

    def _post_data(self, data):
        """
        Perform a POST request to the switch

        :param data: data to send
        """

        self._send_data(self.base_uri, data, "POST", "Adding")
        # Get the data from the created object
        self.get()
        return True

    def _send_data(self, path, data, http_verb, display_verb):
        """
        Perform either PUT or POST operation to the switch.

        :param path: path of the resource for the request. This could
            the base URI if this was called in a create method, or
            the VLAN URI if this was called in an update method.
        :param data: data to send
        :param hrrp_verb: HTTP operation to perfrom
        :display_module_name: Module to display in logs
        :display_verb: verb to display in logs
        """

        send_data = json.dumps(data, sort_keys=True, indent=4)

        try:
            response = self.session.request(
                http_verb, path, data=send_data)

        except Exception as e:
            raise ResponseError(http_verb, e)

        if not utils._response_ok(response, http_verb):
            raise GenericOperationError(
                response.text, response.status_code)

        else:
            logging.info(
                "SUCCESS: {0} {1} table entry succeeded\
                ".format(
                    display_verb,
                    type(self).__name__))
