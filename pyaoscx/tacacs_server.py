# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class TacacsServer(PyaoscxModule):
    """
    Provide configuration management for TACACS+ servers on AOS-CX devices.
        TACACS+ servers are nested under a VRF and indexed by the compound key
        address and tcp_port.
    """

    collection_uri = "system/vrfs/{name}/tacacs_servers"
    resource_uri_name = "tacacs_servers"

    indices = ["address", "tcp_port"]

    def __init__(self, session, vrf, address, tcp_port=49, uri=None, **kwargs):
        self.session = session
        # vrf is a Vrf object used as the parent in the URI path
        self.vrf = vrf
        self.address = address
        self.tcp_port = tcp_port
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = self.collection_uri.format(name=self.vrf.name)
        self.path = "{0}/{1}".format(self.base_uri, self._index_id())

    def _index_id(self):
        sep = self.session.api.compound_index_separator
        return sep.join([str(self.address), str(self.tcp_port)])

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a TACACS+ server and fill the
            object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {0}".format(depths))

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

        for index in self.indices + ["vrf"]:
            if index in data:
                data.pop(index)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(
                self, data, "config_attrs", self.indices + ["vrf"]
            )

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, vrf):
        """
        Perform a GET call to retrieve all TACACS+ servers under a VRF, and
            create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object.
        :param vrf: Vrf object the TACACS+ servers belong to.
        :return: Dictionary containing the compound indices as keys and the
            TacacsServer objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = cls.collection_uri.format(name=vrf.name)
        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        servers = {}
        uri_list = session.api.get_uri_from_data(data)
        for server_uri in uri_list:
            indices, server = cls.from_uri(session, vrf, server_uri)
            servers[indices] = server

        return servers

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing TACACS+ server.

        :return: Boolean, True if object was created or modified.
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
        Perform a PUT call to apply changes to an existing TACACS+ server.

        :return: True if Object was modified and a PUT request was made.
        """
        server_data = utils.get_attrs(self, self.config_attrs)

        if server_data == self._original_attributes:
            return False

        post_data = json.dumps(server_data)

        try:
            response = self.session.request("PUT", self.path, data=post_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = server_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new TACACS+ server. Only returns if no
            exception is raised.

        :return: Boolean, True if entry was created.
        """
        server_data = utils.get_attrs(self, self.config_attrs)
        server_data["address"] = self.address
        server_data["tcp_port"] = self.tcp_port
        server_data["vrf"] = self.vrf.get_uri()

        post_data = json.dumps(server_data)

        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
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
        Perform DELETE call to delete a TACACS+ server.
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
        Create a TacacsServer object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param vrf: Vrf object the TACACS+ server belongs to.
        :param uri: a String with a URI.
        :return: tuple containing both the compound index and the TacacsServer
            object.
        """
        index_pattern = re.compile(r"(.*)tacacs_servers/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")
        address, tcp_port = index.split(session.api.compound_index_separator)

        server = cls(session, vrf, address, int(tcp_port))
        return index, server

    def __str__(self):
        return "TacacsServer address:{0}, tcp_port:{1}".format(
            self.address, self.tcp_port
        )

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific TACACS+ server URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix, self.path
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

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified
