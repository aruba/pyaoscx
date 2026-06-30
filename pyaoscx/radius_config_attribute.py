# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class RadiusConfigAttribute(PyaoscxModule):
    """
    Provide configuration management for per-AAA-server-group RADIUS
        configuration attributes on AOS-CX devices. They live under
        system/radius_config_attributes and are indexed by the AAA server
        group they apply to. Each attribute (for example nas_id, nas_ip_addr,
        framed_ip_addr, tunnel_private_group_id) is a map keyed by service
        type.
    """

    collection_uri = "system/radius_config_attributes"
    object_uri = collection_uri + "/{server_group}"

    indices = ["server_group"]
    resource_uri_name = "radius_config_attributes"

    def __init__(self, session, server_group, server_group_uri=None, **kwargs):
        self.session = session
        self.server_group = server_group
        self._server_group_uri = server_group_uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(server_group=self.server_group)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a RADIUS config attribute entry
            and fill the object with the incoming attributes.
        """
        logging.info("Retrieving %s from switch", self)
        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all RADIUS config attribute entries.
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
            name, entry = cls.from_uri(session, uri)
            collection[name] = entry
        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a RadiusConfigAttribute object given a URI.
        """
        name = uri.rstrip("/").split("/")[-1]
        return name, cls(session, name)

    @PyaoscxModule.connected
    def apply(self):
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new entry. The server group is supplied
            as a URI reference; the remaining attributes are applied through
            update().
        """
        data = utils.get_attrs(self, self.config_attrs)
        data["server_group"] = self._server_group_uri
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        return self.path

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
