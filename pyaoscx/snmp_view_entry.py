# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class SnmpViewEntry(PyaoscxModule):
    """
    Provide configuration management for SNMP view entries on AOS-CX devices
        (system/snmp_views/{name}/snmp_view_entry), indexed by uuid. Entries
        are create/delete only; their fields are immutable once created.
    """

    resource_uri_name = "snmp_view_entry"

    indices = ["uuid"]

    def __init__(self, session, uuid, parent_view, uri=None, **kwargs):
        self.session = session
        self.uuid = uuid
        self.parent_view = parent_view
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = "{0}/snmp_view_entry".format(parent_view.path)
        self.path = "{0}/{1}".format(self.base_uri, self.uuid)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        logging.info("Retrieving %s from switch", self)
        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector
        payload = {"depth": depth, "selector": selector}
        try:
            response = self.session.request("GET", self.path, params=payload)
        except Exception as e:
            raise ResponseError("GET", e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        data.pop("uuid", None)
        utils.create_attrs(self, data)
        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", ["uuid"])
        self._original_attributes = data
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_view):
        logging.info("Retrieving all %s data from switch", cls.__name__)
        uri = "{0}/snmp_view_entry".format(parent_view.path)
        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        entries = {}
        if not data:
            return entries
        is_uri_map = all(
            isinstance(v, str) and "snmp_view_entry/" in v
            for v in data.values()
        )
        if is_uri_map:
            for entry_uri in session.api.get_uri_from_data(data):
                index, entry = cls.from_uri(session, parent_view, entry_uri)
                entries[index] = entry
        else:
            # Some firmware returns the entry attributes inline instead of a
            # reference map; build a materialized entry from them.
            index = data.get("oid_tree")
            entry = cls(session, index, parent_view)
            utils.create_attrs(entry, data)
            entry.materialized = True
            entries[index] = entry
        return entries

    @PyaoscxModule.connected
    def apply(self):
        if self.materialized:
            return False
        modified = self.create()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        # View entry fields are immutable; nothing to update.
        return False

    @PyaoscxModule.connected
    def create(self):
        entry_data = utils.get_attrs(self, self.config_attrs)
        try:
            response = self.session.request(
                "POST", self.base_uri, data=json.dumps(entry_data)
            )
        except Exception as e:
            raise ResponseError("POST", e)
        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)
        logging.info("SUCCESS: Adding %s", self)
        return True

    @PyaoscxModule.connected
    def delete(self):
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)
        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, parent_view, uri):
        index_pattern = re.compile(r"(.*)snmp_view_entry/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")
        return index, cls(session, index, parent_view)

    def __str__(self):
        return "SnmpViewEntry uuid:{0}".format(self.uuid)

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
