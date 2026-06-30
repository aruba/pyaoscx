# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class RadiusDynauthProxyClientGroup(PyaoscxModule):
    """
    Provide configuration management for RADIUS dynamic authorization proxy
        client groups on AOS-CX devices. They live under
        system/radius_dynauth_proxy_client_groups and are indexed by the group
        name. The ``clients`` attribute is a map of numeric ids to RADIUS
        dynamic authorization client URIs.
    """

    collection_uri = "system/radius_dynauth_proxy_client_groups"
    object_uri = collection_uri + "/{group_name}"

    indices = ["group_name"]
    resource_uri_name = "radius_dynauth_proxy_client_groups"

    def __init__(self, session, group_name, **kwargs):
        self.session = session
        self.group_name = group_name
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(group_name=self.group_name)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a proxy client group and fill
            the object with the incoming attributes.
        """
        logging.info("Retrieving %s from switch", self)
        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all proxy client groups.
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
            name, group = cls.from_uri(session, uri)
            collection[name] = group
        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a RadiusDynauthProxyClientGroup object given a URI.
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
        Perform a POST call to create a new proxy client group. Only the group
            name is configurable at creation; clients are applied through
            update().
        """
        data = {"group_name": self.group_name}
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
