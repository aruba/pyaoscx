# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class OspfVlink(PyaoscxModule):
    """
    Provide configuration management for OSPF VLink instance on AOS-CX devices.
    """

    collection_uri = (
        "system/vrfs/{name}/ospf{version}_routers/"
        "{instance_tag}/areas/{area_id}/ospf_vlinks"
    )
    object_uri = collection_uri + "/{peer_router_id}"

    resource_uri_name = "ospf_vlinks"

    def __init__(self, session, peer_router_id, parent_ospf_area, **kwargs):
        self.session = session
        self.__parent_ospf_area = parent_ospf_area
        self.__peer_router_id = peer_router_id
        # List used to determine attributes related to the OPSF configuration
        self.config_attrs = []
        self.materialized = False
        # Dictionary used to manage original data obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False
        self.base_uri = self.__parent_ospf_area.path + "/ospf_vlinks"
        self.path = "{0}/{1}".format(self.base_uri, self.__peer_router_id)

    @property
    def peer_router_id(self):
        """
        Return this object's identifier.
        """
        return self.__peer_router_id

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    def _get_indices(self):
        """
        Get indices to retrieve collection of this object's instances.
        :return: a dictionary with each key in the collection_uri, and its
            respective value to perform a GET request, or empty dictionary
            if the collection_uri has no indices.
        """
        indices = {"area_id": self.__parent_ospf_area.area_id}
        indices.update(self.__parent_ospf_area._get_indices())
        return indices

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET request to retrieve data for an OSPF VLink table entry
            and fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Set original attributes
        self._original_attributes = data

        # Sets object as materialized
        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session, parent_ospf_area):
        """
        Perform a GET request to retrieve all system OSPF Virtual Links inside
            a OPSF Router, and create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_ospf_area: parent OPSF Area object where OPSF VLink
            is stored.
        :return: Dictionary containing OSPF Virtual Link IDs as keys and a OSPF
            Virtual Link objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)
        uri_indices = {"area_id": parent_ospf_area.area_id}
        uri_indices.update(parent_ospf_area._get_indices())
        uri = cls.collection_uri.format(uri_indices)
        try:
            response = session.request("GET", uri)
        except Exception as exc:
            raise ResponseError("GET", exc) from exc
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        ospf_vlink_dict = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            peer_router_id, vlink = cls.from_uri(
                session, uri, parent_ospf_area
            )
            vlink.get()
            ospf_vlink_dict[peer_router_id] = vlink

        return ospf_vlink_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Ospf Virtual
            Link. Checks whether the OSPF Virtual Link exists in the switch.
            Calls self.update() if OSPF Virtual Link is being updated. Calls
            self.create() if a new OSPF Virtual Link is being created.
        :return modified: Boolean, True if object was created or modified.
        """
        if not self.__parent_ospf_area.materialized:
            self.__parent_ospf_area.apply()

        if self.materialized:
            self.__modified = self.update()
        else:
            self.__modified = self.create()
        return self.__modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT request to apply changes to an existing OSPF VLink.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        ospf_vlink_data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(ospf_vlink_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST request to create a new OSPF Virtual Link. Only returns
            if an exception is not raised.
        :return modified: Boolean, True if object was created.
        """
        ospf_vlink_data = utils.get_attrs(self, self.config_attrs)
        ospf_vlink_data["peer_router_id"] = self.__peer_router_id

        self.__modified = self._post_data(ospf_vlink_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete OSPF Virtual Link table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri, parent_ospf_area=None):
        """
        Create an OspfVlink object given a URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_ospf_area: parent OspfArea object where OspfVlink object
            is stored.
        :param uri: an OSPF VLink URI with its index (a peer_router_id).
        :return peer_router_id, ospf_vlink: tuple with the OspfVlink ID, and
            the object.
        """
        if parent_ospf_area is None:
            raise ParameterError(
                "{0} requires parent_ospf_area instance".format(cls.__name__)
            )
        # Obtain ID from URI of the form '.../ospf_vlinks/{peer_router_id}'
        peer_router_id = uri.split("/")[-1]
        vlink = cls(session, peer_router_id, parent_ospf_area)
        return peer_router_id, vlink

    def __str__(self):
        return "OSPF Virtual Link ID {0}".format(self.__peer_router_id)

    def get_uri(self):
        """
        Method used to obtain the specific OSPF Virtual Link URI.
        return: Object's URI.
        """
        # PyaoscxModule uses the uri with the name self.path
        # so it needs to have that name
        return self.path

    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified
