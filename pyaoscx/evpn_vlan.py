# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class EvpnVlan(PyaoscxModule):
    """
    Provide configuration management for per-VLAN EVPN settings on AOS-CX
        devices. These resources live under system/evpn/evpn_vlans and are
        indexed by the VLAN ID. The VLAN must already exist.
    """

    collection_uri = "system/evpn/evpn_vlans"
    object_uri = collection_uri + "/{vlan}"

    indices = ["vlan"]
    resource_uri_name = "evpn_vlans"

    def __init__(self, session, vlan, **kwargs):
        self.session = session
        self.vlan = vlan
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(vlan=self.vlan)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a per-VLAN EVPN table entry
            and fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        # The vlan attribute is a reference on the switch, keep the VLAN ID
        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all per-VLAN EVPN entries and create a
            dictionary containing each respective entry.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing VLAN IDs as keys and EvpnVlan objects
            as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.collection_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        collection = {}
        for uri in data.values():
            vlan, evpn_vlan = cls.from_uri(session, uri)
            collection[vlan] = evpn_vlan

        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an EvpnVlan object given a per-VLAN EVPN URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the VLAN ID and the EvpnVlan object.
        """
        # The URI ends with the VLAN ID, e.g. system/evpn/evpn_vlans/190
        vlan = int(uri.rstrip("/").split("/")[-1])
        return vlan, cls(session, vlan)

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update a per-VLAN EVPN table
            entry.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing per-VLAN EVPN
            entry.

        :return: True if object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new per-VLAN EVPN entry. Exception is
            raised if the object is unable to be created.

        :return: Boolean, True if entry was created.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data["vlan"] = "{0}system/vlans/{1}".format(
            self.session.resource_prefix, self.vlan
        )
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the per-VLAN EVPN table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific per-VLAN EVPN URI.

        :return: Object's URI.
        """
        return self.path

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.

        :return: True if the object was recently modified.
        """
        return self.modified
