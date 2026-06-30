# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class EvpnVlanAwareBundle(PyaoscxModule):
    """
    Provide configuration management for EVPN VLAN-aware bundles on AOS-CX
        devices. These resources live under
        system/evpn/evpn_vlan_aware_bundles and are indexed by the bundle name.
        A bundle groups several VLANs (mapped through vlan_ethernet_tags) under
        a single EVPN instance sharing the same route distinguisher and route
        targets.
    """

    collection_uri = "system/evpn/evpn_vlan_aware_bundles"
    object_uri = collection_uri + "/{bundle_name}"

    indices = ["bundle_name"]
    resource_uri_name = "evpn_vlan_aware_bundles"

    def __init__(self, session, bundle_name, **kwargs):
        self.session = session
        self.bundle_name = bundle_name
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(bundle_name=self.bundle_name)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an EVPN VLAN-aware bundle table
            entry and fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all EVPN VLAN-aware bundle entries and
            create a dictionary containing each respective bundle.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing bundle names as keys and
            EvpnVlanAwareBundle objects as values.
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
            name, bundle = cls.from_uri(session, uri)
            collection[name] = bundle

        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an EvpnVlanAwareBundle object given a bundle URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the bundle name and the EvpnVlanAwareBundle object.
        """
        # The URI ends with the bundle name, e.g.
        # system/evpn/evpn_vlan_aware_bundles/my-bundle
        name = uri.rstrip("/").split("/")[-1]
        bundle = cls(session, name)
        return name, bundle

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an EVPN VLAN-aware bundle
            table entry.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing EVPN VLAN-aware
            bundle entry.

        :return: True if object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new EVPN VLAN-aware bundle entry. Only
            the bundle name is configurable at creation time; the remaining
            attributes are applied through update(). Exception is raised if the
            object is unable to be created.

        :return: Boolean, True if entry was created.
        """
        data = {"bundle_name": self.bundle_name}
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the EVPN VLAN-aware bundle table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific EVPN VLAN-aware bundle URI.

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
