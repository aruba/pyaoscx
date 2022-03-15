# (C) Copyright 2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from copy import deepcopy

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class Vni(PyaoscxModule):
    """
    Provide configuration management for Virtual Network IDs on
        AOS-CX devices
    """

    collection_uri = "system/virtual_network_ids"
    object_uri = collection_uri + "/{type},{id}"

    indices = ["type", "id"]
    resource_uri_name = "virtual_network_ids"

    def __init__(
        self, session, vni_id, interface, vni_type="vxlan_vni", **kwargs
    ):
        self.session = session
        self.id = vni_id
        self.type = vni_type
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        self.interface = interface
        utils.create_attrs(self, kwargs)
        uri_indices = {
            "type": self.type,
            "id": self.id,
        }
        self.__modified = False
        self.materialized = False
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(**uri_indices)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for VNI table entry and fill
            the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        """
        logging.info("Retrieving %s from switch", self)
        # this is common for all PyaoscxModule derived classes
        self._get_and_copy_data(depth, selector, self.indices)
        selector = selector or self.session.api.default_selector
        data = self._get_data(depth, selector)

        for key, val in data.items():
            if key == "interface":
                continue
            setattr(self, key, val)

        Interface = self.session.api.get_module_class(
            self.session, "Interface"
        )

        intf = data["interface"]
        _, intf = Interface.from_uri(self.session, intf[next(iter(intf))])
        self.interface = intf

        self._original_attributes = deepcopy(data)

        if selector in self.session.api.configurable_selectors:
            setattr(
                self,
                "config_attrs",
                list(set(data.keys()) - set(self.indices)),
            )
        self.materialized = True

        if hasattr(self, "vrf") and self.vrf:
            Vrf = self.session.api.get_module_class(self.session, "Vrf")
            vrf_urls = self.vrf
            vrf_url = vrf_urls[next(iter(vrf_urls))]
            _, vrf = Vrf.from_uri(self.session, vrf_url)
            self.vrf = vrf
        if hasattr(self, "vlan") and self.vlan:
            Vlan = self.session.api.get_module_class(self.session, "Vlan")
            vlan_urls = self.vlan
            vlan_url = vlan_urls[next(iter(vlan_urls))]
            _, vlan = Vlan.from_uri(self.session, vlan_url)
            self.vlan = vlan
        return True

    @classmethod
    def get_all(cls, session, parent_intf):
        """
        Perform a GET call to retrieve all system VNI and create a dictionary
            containing each respective VNI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch
        :param parent_intf: Interface attached to this tunnel
        :return: Dictionary containing VNI IDs and a VNI object as value
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.collection_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        vni_collection = {}
        for uri in data.values():
            vni_id, vni = cls.from_uri(session, parent_intf, uri)
            vni_collection[vni_id] = vni

        return vni_collection

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update a
            VNI table entry
        :return: True if the object was modified
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing VNI table entry
        :return modified: True if object was modified and a PUT request was
            made. False otherwise
        """
        vni_data = utils.get_attrs(self, self.config_attrs)
        vni_data["interface"] = self.__interface.get_info_format()
        if hasattr(self, "routing"):
            vni_data["routing"] = self.routing
        if hasattr(self, "vrf") and self.vrf:
            vni_data["vrf"] = self.vrf.get_info_format()
        if hasattr(self, "vlan") and self.vlan:
            vni_data["vlan"] = self.vlan.get_info_format()
        self.__modified = self._put_data(vni_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new VNI using the object's
            attributes as POST body. Exception is raised if object is unable
            to be created
        :return modified: Boolean, True if entry was created
        """
        vni_data = utils.get_attrs(self, self.config_attrs)
        vni_data["id"] = self.id
        vni_data["interface"] = self.__interface.get_info_format()
        vni_data["type"] = self.type
        if hasattr(self, "routing"):
            vni_data["routing"] = self.routing
        if hasattr(self, "vrf") and self.vrf:
            vni_data["vrf"] = self.vrf.get_info_format()
        if hasattr(self, "vlan") and self.vlan:
            vni_data["vlan"] = self.vlan.get_info_format()
        self.__modified = self._post_data(vni_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the VNI table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_intf, response_data):
        """
        Create a VNI object given a response_data related to a VNI object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_intf: Interface attached to this tunnel
        :param response_data: The response must be a dictionary of the form:
            {id: URL}
        :return: VNI object
        """
        uri = list(response_data.values())[0]

        return cls.from_uri(session, parent_intf, uri)

    @classmethod
    def from_uri(cls, session, parent_intf, uri):
        """
        Create a Vni object given a VNI URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param parent_intf: Interface attached to this tunnel
        :param uri: A String with a URI
        :return VNI_ids, Vni: tuple containing the VNI ids (type, and actual
            ID) and the VNI object.
        """
        index_pattern = re.compile(
            r"(.*)virtual_network_ids/(?P<vni_type>.+),(?P<vni_id>.+)"
        )
        pattern_match = index_pattern.match(uri)
        vni_id = pattern_match.group("vni_id")
        vni_type = pattern_match.group("vni_type")
        vni_key = "{0},{1}".format(vni_type, vni_id)
        vni = cls(session, vni_id, parent_intf, vni_type=vni_type)
        return vni_key, vni

    def __str__(self):
        return "VNI {0}, type {1}".format(self.id, self.type)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific VNI URI
        :return: Object's URI
        """
        uri = "{0}{1}".format(self.session.resource_prefix, self.path)
        return uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method to obtain correct object format for referencing inside
            other objects
        return: Object format depending on the API Version
        """
        return self.session.api.get_index(self)

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    @property
    def interface(self):
        return self.__interface

    @interface.setter
    def interface(self, new_interface):
        if self.type == "vxlan_vni" and new_interface.type != "vxlan":
            raise VerificationError(
                "Incompatible VNI and Interface types: "
                "{0} and {1}".format(self.type, new_interface.type)
            )
        self.__interface = new_interface
