# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class IpslaResponder(PyaoscxModule):
    """
    Provide configuration management for IP SLA responders on AOS-CX devices.
        A responder answers IP SLA probes (UDP echo, TCP connect, UDP jitter).
        These resources live under system/ipsla_responders and are indexed by
        name. The responder attributes are all set at creation time and cannot
        be modified afterwards, so the resource only supports create and
        delete.
    """

    base_uri = "system/ipsla_responders"
    resource_uri_name = "ipsla_responders"

    indices = ["name"]

    def __init__(self, session, name, vrf=None, **kwargs):
        self.session = session
        # The index is the responder name
        self.name = name
        # The VRF is a Vrf object serialized as a URI on creation
        self.vrf = vrf
        self._uri = None
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self.path = "{0}/{1}".format(self.base_uri, self.name)
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an IP SLA responder and fill
            the object with the incoming attributes. The configuration
            selector is used by default because the responder has no writable
            attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        selector = selector or "configuration"
        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all IP SLA responders and create a
            dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing responder names as keys and
            IpslaResponder objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        collection = {}
        for name, uri in data.items():
            collection[name] = cls.from_uri(session, uri)[1]

        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an IpslaResponder object given a responder URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the responder name and the IpslaResponder object.
        """
        name = uri.rstrip("/").split("/")[-1]
        responder = cls(session, name)
        return name, responder

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to create the responder if it does not exist.

        :return: True if the object was created.
        """
        if self.materialized:
            return False
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        The responder attributes are immutable, so there is nothing to update.
            Present to satisfy the base class interface.

        :return: Always False (never modified by an update).
        """
        return False

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new IP SLA responder using the
            object's attributes as POST body. Exception is raised if object is
            unable to be created.

        :return: Boolean, True if entry was created.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The responder name is the index and must be present in the POST body.
        data["name"] = self.name
        # The VRF is a mandatory reference serialized as a URI.
        if self.vrf is not None:
            data["vrf"] = "{0}system/vrfs/{1}".format(
                self.session.resource_prefix, self.vrf.name
            )
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the IP SLA responder.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific IP SLA responder URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
                self.name,
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
