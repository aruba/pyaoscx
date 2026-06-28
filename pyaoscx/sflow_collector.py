# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class SFlowCollector(PyaoscxModule):
    """
    Provide configuration management for sFlow collectors on AOS-CX devices.
        A collector is a nested resource under an sFlow instance
        (system/sflows/{name}/collectors) and is identified by the compound
        index (vrf, ip_address, udp_port). The collector has no writable
        attributes beyond its index, so it only supports create and delete.
    """

    resource_uri_name = "collectors"

    indices = ["vrf", "ip_address", "udp_port"]

    def __init__(
        self, session, vrf, ip_address, udp_port, parent_sflow, **kwargs
    ):
        self.session = session
        # Compound index: a Vrf object, an IP string and a UDP port integer
        self.vrf = vrf
        self.ip_address = ip_address
        self.udp_port = udp_port
        # Parent sFlow instance the collector belongs to
        self.__parent_sflow = parent_sflow
        self._uri = None
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.base_uri = "{0}/collectors".format(parent_sflow.path)
        self.path = "{0}/{1}".format(self.base_uri, self._index_key())
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    def _index_key(self):
        """
        Build the compound index key used in the resource URI.

        :return: String "vrf,ip_address,udp_port".
        """
        sep = self.session.api.compound_index_separator
        return sep.join([self.vrf.name, self.ip_address, str(self.udp_port)])

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to confirm the collector exists. The collector has
            no writable attributes beyond its index.

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
    def get_all(cls, session, parent_sflow):
        """
        Perform a GET call to retrieve all collectors of a given sFlow
            instance and create a dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :param parent_sflow: SFlow object the collectors belong to.
        :return: Dictionary containing the compound index keys as keys and
            SFlowCollector objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/collectors".format(parent_sflow.path)
        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        collection = {}
        for key, value in data.items():
            collection[key] = cls.from_uri(session, value, parent_sflow)[1]

        return collection

    @classmethod
    def from_uri(cls, session, uri, parent_sflow):
        """
        Create an SFlowCollector object given a collector URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :param parent_sflow: SFlow object the collector belongs to.
        :return: Tuple with the compound index key and the SFlowCollector.
        """
        key = uri.rstrip("/").split("/")[-1]
        sep = session.api.compound_index_separator
        vrf_name, ip_address, udp_port = key.split(sep)
        vrf = session.api.get_module(session, "Vrf", vrf_name)
        collector = cls(session, vrf, ip_address, int(udp_port), parent_sflow)
        return key, collector

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to create the collector if it does not exist.

        :return: True if the object was created.
        """
        if self.materialized:
            return False
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        A collector has no writable attributes beyond its index, so there is
            nothing to update. Present to satisfy the base class interface.

        :return: Always False (never modified by an update).
        """
        return False

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new collector. The compound index
            (vrf as a URI reference, ip_address and udp_port) makes up the
            POST body.

        :return: Boolean, True if entry was created.
        """
        data = {
            "vrf": "{0}system/vrfs/{1}".format(
                self.session.resource_prefix, self.vrf.name
            ),
            "ip_address": self.ip_address,
            "udp_port": self.udp_port,
        }
        self._send_data(self.base_uri, data, "POST", "Adding")
        self.materialized = True
        self.__modified = True
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the collector.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific collector URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
                self._index_key(),
            )
        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.

        :return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.

        :return: True if the object was recently modified.
        """
        return self.modified
