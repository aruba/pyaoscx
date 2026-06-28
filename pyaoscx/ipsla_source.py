# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class IpslaSource(PyaoscxModule):
    """
    Provide configuration management for IP SLA sources on AOS-CX devices.
        An IP SLA source defines a probe (ICMP echo, UDP echo, HTTP, DNS, ...)
        used to measure network performance. These resources live under
        system/ipsla_sources and are indexed by name. Updates are applied with
        a PATCH request because the resource rejects a full PUT.
    """

    base_uri = "system/ipsla_sources"
    resource_uri_name = "ipsla_sources"

    indices = ["name"]

    def __init__(self, session, name, vrf=None, **kwargs):
        self.session = session
        # The index is the source name
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

    def _patch_data(self, data):
        """
        Perform a PATCH call to partially update the source. The resource
            rejects a full PUT, so only the changed attributes are sent.

        :param data: dictionary with the attributes to update.
        """
        send_data = json.dumps(data, sort_keys=True, indent=4)
        # session.request does not support PATCH, so use the underlying
        # requests.Session object with the fully-qualified resource URI.
        uri = self.session._build_uri(self.path)
        try:
            response = self.session.s.patch(
                uri, verify=False, data=send_data, proxies=self.session.proxy
            )
        except Exception as e:
            raise ResponseError("PATCH", e)
        if response.status_code not in (200, 204):
            raise GenericOperationError(response.text, response.status_code)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an IP SLA source and fill the
            object with the incoming attributes.

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
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all IP SLA sources and create a
            dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing source names as keys and IpslaSource
            objects as values.
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
        Create an IpslaSource object given a source URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the source name and the IpslaSource object.
        """
        name = uri.rstrip("/").split("/")[-1]
        source = cls(session, name)
        return name, source

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an IP SLA source.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PATCH call to apply changes to an existing IP SLA source.
            The name, type and vrf are set at creation and are never sent in
            an update.

        :return: True if object was modified and a PATCH request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        diff = {
            key: value
            for key, value in data.items()
            if self._original_attributes.get(key) != value
        }
        for key in ("name", "type", "vrf"):
            diff.pop(key, None)
        if not diff:
            self.__modified = False
            return self.__modified
        self._patch_data(diff)
        self.__modified = True
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new IP SLA source using the object's
            attributes as POST body. Exception is raised if object is unable
            to be created.

        :return: Boolean, True if entry was created.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The source name is the index and must be present in the POST body.
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
        Perform a DELETE call to erase the IP SLA source.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific IP SLA source URI.

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
