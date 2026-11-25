# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class Aaa(PyaoscxModule):
    """
    Provide configuration management for the global AAA settings, exposed as
        the aaa attribute of the system resource.
    """

    base_uri = "system"
    resource_uri_name = "system"

    indices = []

    _attr = "aaa"

    def __init__(self, session, uri=None, **kwargs):
        self.session = session
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        self.aaa = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.path = self.base_uri

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve the global AAA settings.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth

        payload = {"attributes": self._attr, "depth": depth}

        try:
            response = self.session.request("GET", self.path, params=payload)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)
        value = data.get(self._attr, {})
        self.aaa = value
        if self._attr not in self.config_attrs:
            self.config_attrs.append(self._attr)
        self._original_attributes = {self._attr: dict(value)}
        self.materialized = True
        return True

    @PyaoscxModule.connected
    def apply(self):
        """
        Apply the configured values with a PUT to the system resource.
        """
        modified = self.update()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to the global AAA settings.
        """
        data = {self._attr: self.aaa}

        if data == self._original_attributes:
            return False

        try:
            response = self.session.request(
                "PUT", self.path, data=json.dumps(data)
            )
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = {self._attr: dict(self.aaa)}
        self.__modified = True
        return True

    def create(self):
        return self.update()

    def delete(self):
        pass

    @classmethod
    def get_all(cls, session):
        return {}

    @classmethod
    def from_uri(cls, session, uri):
        return cls(session, uri=uri)

    def __str__(self):
        return "AAA"

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
