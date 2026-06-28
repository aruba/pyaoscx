# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class Mirror(PyaoscxModule):
    """
    Provide configuration management for mirror (traffic monitoring) sessions
        on AOS-CX devices. These resources live under system/mirrors and are
        indexed by the numeric session id.
    """

    base_uri = "system/mirrors"
    resource_uri_name = "mirrors"

    indices = ["id"]

    # Writable attributes that reference Port (Interface) resources. They are
    # stored as lists of Interface objects and serialized to the API's
    # {name: uri} reference form.
    port_reference_attrs = (
        "output_port",
        "select_src_port",
        "select_dst_port",
    )
    # Writable attributes that reference VLAN resources.
    vlan_reference_attrs = (
        "select_rx_vlan",
        "select_tx_vlan",
    )

    def __init__(self, session, id, **kwargs):
        self.session = session
        # The index is the numeric session id
        self.id = id
        self._uri = None
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.path = "{0}/{1}".format(self.base_uri, self.id)
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a mirror session and fill the
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
        for attr in self.vlan_reference_attrs:
            value = getattr(self, attr, None)
            if isinstance(value, dict):
                vlans = [
                    self.session.api.get_module(self.session, "Vlan", int(n))
                    for n in value
                ]
                setattr(self, attr, vlans)

    def _build_data(self):
        """
        Build the request body, serializing reference attributes into the
            API's {name: uri} form.

        :return: Dictionary ready to be sent to the switch.
        """
        data = utils.get_attrs(self, self.config_attrs)
        for attr in self.port_reference_attrs + self.vlan_reference_attrs:
            if attr in data:
                formatted = {}
                for obj in getattr(self, attr) or []:
                    formatted.update(obj.get_info_format())
                data[attr] = formatted
        return data

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all mirror sessions and create a
            dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing session ids as keys and Mirror objects
            as values.
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
        for uri in data.values():
            session_id, mirror = cls.from_uri(session, uri)
            collection[session_id] = mirror

        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Mirror object given a mirror session URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the session id and the Mirror object.
        """
        # The URI ends with the session id, e.g. system/mirrors/1
        session_id = uri.rstrip("/").split("/")[-1]
        mirror = cls(session, int(session_id))
        return session_id, mirror

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update a mirror session.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing mirror session.

        :return: True if object was modified and a PUT request was made.
        """
        data = self._build_data()
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new mirror session using the object's
            attributes as POST body. Exception is raised if object is unable
            to be created.

        :return: Boolean, True if entry was created.
        """
        data = self._build_data()
        # The session id is the index and must be present in the POST body.
        data["id"] = self.id
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the mirror session.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific mirror session URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
                self.id,
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
