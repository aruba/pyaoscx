# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class AaaAccountingAttributes(PyaoscxModule):
    """
    Provide configuration management for AAA accounting attributes on AOS-CX
        devices. They live under system/aaa_accounting_attributes and are
        indexed by session_type.
    """

    base_uri = "system/aaa_accounting_attributes"
    resource_uri_name = "aaa_accounting_attributes"

    indices = ["session_type"]

    def __init__(self, session, session_type, uri=None, **kwargs):
        self.session = session
        self.session_type = session_type
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.path = "{0}/{1}".format(self.base_uri, self.session_type)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an accounting attributes entry
            and fill the object with the incoming attributes.
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
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all accounting attribute entries.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        entries = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            index, entry = cls.from_uri(session, uri)
            entries[index] = entry

        return entries

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing entry.
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
        Perform a PUT call to apply changes to an existing entry.
        """
        entry_data = utils.get_attrs(self, self.config_attrs)

        if entry_data == self._original_attributes:
            return False

        try:
            response = self.session.request(
                "PUT", self.path, data=json.dumps(entry_data)
            )
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = entry_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Create the entry with a POST, or update it if it already exists.
        """
        pending = utils.get_attrs(self, self.config_attrs)
        try:
            self.get()
            exists = True
        except GenericOperationError:
            exists = False
        if exists:
            for key, value in pending.items():
                setattr(self, key, value)
                if key not in self.config_attrs:
                    self.config_attrs.append(key)
            return self.update()

        entry_data = dict(pending)
        entry_data["session_type"] = self.session_type
        try:
            response = self.session.request(
                "POST", self.base_uri, data=json.dumps(entry_data)
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
        Perform DELETE call to delete an entry.
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
    def from_uri(cls, session, uri):
        """
        Create an AaaAccountingAttributes object given a URI.
        """
        index_pattern = re.compile(
            r"(.*)aaa_accounting_attributes/(?P<index>.+)"
        )
        index = index_pattern.match(uri).group("index")
        entry = cls(session, index)
        return index, entry

    def __str__(self):
        return "AAA Accounting Attributes {0}".format(self.session_type)

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
