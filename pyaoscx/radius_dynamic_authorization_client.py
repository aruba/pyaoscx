# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class RadiusDynamicAuthorizationClient(PyaoscxModule):
    """
    Provide configuration management for RADIUS dynamic authorization clients
        (Change of Authorization clients). They live under a VRF in
        radius_dynamic_authorization_clients and are indexed by the compound
        key address and connection_type.
    """

    collection_uri = (
        "system/vrfs/{vrf}/radius_dynamic_authorization_clients"
    )

    indices = ["address", "connection_type"]

    def __init__(
        self, session, vrf, address, connection_type, uri=None, **kwargs
    ):
        self.session = session
        if hasattr(vrf, "name"):
            vrf = vrf.name
        self.__vrf = vrf
        self.address = address
        self.connection_type = connection_type
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        sep = self.session.api.compound_index_separator
        self.base_uri = self.collection_uri.format(vrf=vrf)
        self.index = "{0}{1}{2}".format(
            self.address, sep, self.connection_type
        )
        self.path = "{0}/{1}".format(self.base_uri, self.index)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a client and fill the object
            with the incoming attributes.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if selector not in self.session.api.valid_selectors:
            selectors = " ".join(self.session.api.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {0}".format(selectors)
            )

        payload = {"depth": depth, "selector": selector}

        try:
            response = self.session.request("GET", self.path, params=payload)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        for index in self.indices:
            data.pop(index, None)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", self.indices)

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, vrf):
        """
        Perform a GET call to retrieve all clients of a VRF.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        if hasattr(vrf, "name"):
            vrf = vrf.name
        base_uri = cls.collection_uri.format(vrf=vrf)

        try:
            response = session.request("GET", base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        clients = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            index, client = cls.from_uri(session, vrf, uri)
            clients[index] = client

        return clients

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing client.
        """
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing client.
        """
        client_data = utils.get_attrs(self, self.config_attrs)

        if client_data == self._original_attributes:
            return False

        try:
            response = self.session.request(
                "PUT", self.path, data=json.dumps(client_data)
            )
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = client_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new client.
        """
        client_data = utils.get_attrs(self, self.config_attrs)
        client_data["address"] = self.address
        client_data["connection_type"] = self.connection_type
        client_data["vrf"] = "{0}system/vrfs/{1}".format(
            self.session.resource_prefix, self.__vrf
        )

        try:
            response = self.session.request(
                "POST", self.base_uri, data=json.dumps(client_data)
            )
        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        self.get()
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete a client.
        """
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, vrf, uri):
        """
        Create a RadiusDynamicAuthorizationClient object given a URI.
        """
        index_pattern = re.compile(
            r"(.*)radius_dynamic_authorization_clients/(?P<index>.+)"
        )
        index = index_pattern.match(uri).group("index")
        sep = session.api.compound_index_separator
        address, connection_type = index.split(sep)
        client = cls(session, vrf, address, connection_type)
        return index, client

    def __str__(self):
        return "RADIUS Dynamic Authorization Client {0} {1}".format(
            self.address, self.connection_type
        )

    @PyaoscxModule.deprecated
    def get_uri(self):
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix, self.path
            )
        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        return self.session.api.get_index(self)

    @property
    def modified(self):
        return self.__modified
