# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class MirrorEndpoint(PyaoscxModule):
    """
    Provide configuration management for remote mirror endpoints (ERSPAN
        tunnel destinations) on AOS-CX devices. These resources live under
        system/mirror_endpoints and are indexed by name.
    """

    base_uri = "system/mirror_endpoints"
    resource_uri_name = "mirror_endpoints"

    indices = ["name"]

    # Writable attributes that reference Port (Interface) resources, stored
    # as lists of Interface objects and serialized to the API's {name: uri}
    # reference form.
    port_reference_attrs = ("output_port",)

    def __init__(self, session, name, **kwargs):
        self.session = session
        # The index is the endpoint name
        self.name = name
        self._uri = None
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.path = "{0}/{1}".format(self.base_uri, self.name)
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a mirror endpoint and fill the
            object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        self._get_and_copy_data(depth, selector, self.indices)
        # The REST API returns references as {name: uri} dictionaries; turn
        # them into lists of pyaoscx objects so they are easy to manipulate.
        self._references_to_objects()
        self.materialized = True
        return True

    def _references_to_objects(self):
        """
        Convert the {name: uri} reference dictionaries returned by the API
            into lists of materialized pyaoscx objects.
        """
        for attr in self.port_reference_attrs:
            value = getattr(self, attr, None)
            if isinstance(value, dict):
                ports = [
                    self.session.api.get_module(self.session, "Interface", n)
                    for n in value
                ]
                setattr(self, attr, ports)

    def _build_data(self):
        """
        Build the request body, serializing reference attributes into the
            API's {name: uri} form.

        :return: Dictionary ready to be sent to the switch.
        """
        data = utils.get_attrs(self, self.config_attrs)
        for attr in self.port_reference_attrs:
            if attr in data:
                formatted = {}
                for obj in getattr(self, attr) or []:
                    formatted.update(obj.get_info_format())
                data[attr] = formatted
        return data

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all mirror endpoints and create a
            dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing endpoint names as keys and
            MirrorEndpoint objects as values.
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
        Create a MirrorEndpoint object given a mirror endpoint URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the endpoint name and the MirrorEndpoint object.
        """
        # The URI ends with the endpoint name, e.g. system/mirror_endpoints/e1
        name = uri.rstrip("/").split("/")[-1]
        endpoint = cls(session, name)
        return name, endpoint

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update a mirror endpoint.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing mirror endpoint.

        :return: True if object was modified and a PUT request was made.
        """
        data = self._build_data()
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new mirror endpoint using the object's
            attributes as POST body. Exception is raised if object is unable
            to be created.

        :return: Boolean, True if entry was created.
        """
        data = self._build_data()
        # The endpoint name is the index and must be present in the POST body.
        data["name"] = self.name
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the mirror endpoint.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific mirror endpoint URI.

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
