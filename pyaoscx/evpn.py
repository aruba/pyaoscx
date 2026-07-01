# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import logging

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class Evpn(PyaoscxModule):
    """
    Provide configuration management for the global EVPN (Ethernet VPN)
        settings on AOS-CX devices. This is a singleton resource located at
        system/evpn.
    """

    base_uri = "system/evpn"
    path = "system/evpn"

    def __init__(self, session, uri=None, **kwargs):
        self.session = session
        # List used to determine attributes related to the EVPN configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for the EVPN configuration and
            fill the class with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        # this is common for all PyaoscxModule derived classes
        self._get_and_copy_data(depth, selector)
        # Sets object as materialized
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Not applicable for EVPN, it is a singleton resource.
        """

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an Evpn object given an EVPN URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Evpn object.
        """
        return cls(session, uri=uri)

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to update the global EVPN configuration. Since EVPN
            is a singleton it always exists, so this calls update().

        :return: True if object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to the EVPN configuration.

        :return: True if Object was modified and a PUT request was made.
        """
        put_data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(put_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to set the EVPN configuration. Only returns if no
            exception is raised.

        :return: True if entry was created.
        """
        post_data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._post_data(post_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to reset the EVPN configuration.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific EVPN URI.

        :return: Object's URI.
        """
        return self.path

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Not applicable for EVPN.
        """

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.

        :return: True if the object was recently modified.
        """
        return self.modified
