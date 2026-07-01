# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class SnmpTrap(PyaoscxModule):
    """
    Provide configuration management for SNMP trap receivers on AOS-CX
        devices (system/snmp_traps). Compound index of
        vrf,receiver_address,receiver_udp_port,type,version. Create/delete
        only.
    """

    base_uri = "system/snmp_traps"
    resource_uri_name = "snmp_traps"

    indices = [
        "vrf",
        "receiver_address",
        "receiver_udp_port",
        "type",
        "version",
    ]

    def __init__(
        self,
        session,
        vrf,
        receiver_address,
        receiver_udp_port,
        type,
        version,
        uri=None,
        **kwargs
    ):
        self.session = session
        # vrf is a Vrf object used both in the URI index and the POST body
        self.vrf = vrf
        self.receiver_address = receiver_address
        self.receiver_udp_port = receiver_udp_port
        self.type = type
        self.version = version
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        sep = self.session.api.compound_index_separator
        index = sep.join(
            [
                self.vrf.name,
                self.receiver_address,
                str(self.receiver_udp_port),
                self.type,
                self.version,
            ]
        )
        self.path = "{0}/{1}".format(self.base_uri, index)

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
        logging.info("Retrieving all %s data from switch", cls.__name__)
        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        return session.api.get_uri_from_data(data)

    @PyaoscxModule.connected
    def apply(self):
        if self.materialized:
            return False
        modified = self.create()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        # Trap receivers are identified by their full compound index; there
        # are no mutable attributes beyond it.
        return False

    @PyaoscxModule.connected
    def create(self):
        trap_data = utils.get_attrs(self, self.config_attrs)
        trap_data["vrf"] = self.vrf.get_uri()
        trap_data["receiver_address"] = self.receiver_address
        trap_data["receiver_udp_port"] = self.receiver_udp_port
        trap_data["type"] = self.type
        trap_data["version"] = self.version
        try:
            response = self.session.request(
                "POST", self.base_uri, data=json.dumps(trap_data)
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
    def from_uri(cls, session, uri):
        index_pattern = re.compile(r"(.*)snmp_traps/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")
        return index, uri

    def __str__(self):
        return "SnmpTrap {0}".format(self.receiver_address)

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
