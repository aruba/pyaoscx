# (C) Copyright 2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class TunnelEndpoint(PyaoscxModule):
    """
    Provide configuration for Tunnel Endpoints (TEP) on AOS-CX devices.
    """

    collection_uri = "system/interfaces/{intf_name}/tunnel_endpoints"
    object_uri = collection_uri + "/{vrf_name},{origin},{destination}"

    indices = ["vrf_name", "origin", "destination"]
    resource_uri_name = "tunnel_endpoints"

    def __init__(
        self,
        session,
        interface,
        network_id,
        destination,
        origin="static",
        vrf=None,
        **kwargs
    ):

        self.session = session
        if vrf is None:
            vrf = session.api.get_module(session, "Vrf", "default")
        self.vrf = vrf
        self.vrf_name = vrf.name
        self.network_id = network_id
        self.destination = destination
        self.origin = origin
        self.interface = interface
        self.tep_id = "{0},{1},{2}".format(
            self.vrf_name, self.origin, self.destination
        )
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        uri_indices = {
            "intf_name": self.interface.percents_name,
            "vrf_name": self.vrf_name,
            "origin": self.origin,
            "destination": self.destination,
        }
        self.base_uri = self.collection_uri.format(**uri_indices)
        self.path = self.object_uri.format(**uri_indices)
        self.__modified = False

    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a TEP table entry and fill the
            object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)
        # this is common for all PyaoscxModule derived classes
        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        vni_urls = self.network_id
        vni_url = vni_urls[next(iter(vni_urls))]
        Vni = self.session.api.get_module_class(self.session, "Vni")
        _, vni = Vni.from_uri(self.session, self.interface, vni_url)
        self.network_id = vni
        return True

    @classmethod
    def get_all(cls, session, parent_interface):
        """
        Perform a GET call to retrieve all Tunnel Endpoints and create a
            dictionary containing each respective TEP.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_interface: Interface attached to this tunnel
        :return: Dictionary containing TEP IDs as keys and a TEP object as
            value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)
        uri_indices = {"intf_name": parent_interface.percents_name}
        uri = cls.collection_uri.format(**uri_indices)
        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        tep_collection = {}
        data = json.loads(response.text)
        for uri in data.values():
            tep_id, tep = cls.from_uri(session, uri)
            tep_collection[tep_id] = tep

        return tep_collection

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create a TEP, or update an existing one.
            Checks whether the TEP exists in the switch. Calls self.update()
            if TEP is being updated. Calls self.create() if the TEP doesn't
            exist in the switch.
        :return modified: Boolean, True if object was created or modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing TEP table entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        tep_data = {}
        tep_data["network_id"] = self.network_id.get_info_format()
        self.__modified = self._put_data(tep_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new TEP using the object's attributes
            as POST body. Exception is raised if object is unable to be
            created.
        :return modified: Boolean, True if TEP was created.
        """
        tep_data = {}
        tep_data["destination"] = self.destination
        tep_data["interface"] = self.interface.get_info_format()
        tep_data["network_id"] = self.network_id.get_info_format()
        tep_data["origin"] = self.origin
        tep_data["vrf"] = self.vrf.get_info_format()

        self.__modified = self._post_data(tep_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        self._send_data(self.path, None, "DELETE", "Delete")
        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a TEP object given a response_dat
        """
        if isinstance(response_data, dict):
            uri = list(response_data.values())[0]
        else:
            uri = response_data

        return cls.from_uri(session, uri)

    def __str__(self):
        tep_str = "Tunnel {0},{1},{2} for interface {3}".format(
            self.vrf.name, self.origin, self.destination, self.interface.name
        )
        return tep_str

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a TEP object given a TEP URI.
        """
        # Obtain ID from URI like:
        # system/interfaces/{intf_name}/tunnel_endpoints/{vrf_name},{origin},{destination}
        index_pattern = re.compile(
            r"(.*)interfaces/(?P<intf>.+)/tunnel_endpoints/(?P<vrf>.+),(?P<origin>.+),(?P<dest>.+)"  # NOQA
        )
        pattern_match = index_pattern.match(uri)
        intf_name = pattern_match.group("intf")
        vrf_name = pattern_match.group("vrf")
        origin = pattern_match.group("origin")
        destination = pattern_match.group("dest")

        interface = session.api.get_module(session, "Interface", intf_name)
        vrf = session.api.get_module(session, "Vrf", vrf_name)
        tep = cls(
            session,
            interface=interface,
            network_id=None,
            destination=destination,
            origin=origin,
            vrf=vrf,
        )

        return tep.tep_id, tep

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific TEP URI.
        return: Object's URI.
        """
        uri = "{0}{1}".format(self.session.resource_prefix, self.path)
        return uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: Object format depending on the API Version.
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
