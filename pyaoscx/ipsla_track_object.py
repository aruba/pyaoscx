# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class IpslaTrackObject(PyaoscxModule):
    """
    Provide configuration management for IP SLA track objects on AOS-CX
        devices. A track object follows the state of one or more IP SLA
        sessions and can be used by other features. These resources live under
        system/ipsla_track_objects and are indexed by name. The tracked
        sessions are set at creation time and cannot be modified afterwards;
        the remaining attributes are updated with a PATCH request.
    """

    base_uri = "system/ipsla_track_objects"
    resource_uri_name = "ipsla_track_objects"

    indices = ["name"]

    def __init__(self, session, name, tracked_ipsla_session=None, **kwargs):
        self.session = session
        # The index is the track object name
        self.name = name
        # List of IpslaSource objects tracked by this object (creation only)
        self.tracked_ipsla_session = tracked_ipsla_session or []
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
        Perform a PATCH call to partially update the track object. The tracked
            sessions are immutable, so only the remaining attributes are sent.

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
        Perform a GET call to retrieve data for an IP SLA track object and
            fill the object with the incoming attributes.

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
        Perform a GET call to retrieve all IP SLA track objects and create a
            dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing track object names as keys and
            IpslaTrackObject objects as values.
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
        Create an IpslaTrackObject object given a track object URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the track object name and the IpslaTrackObject.
        """
        name = uri.rstrip("/").split("/")[-1]
        track = cls(session, name)
        return name, track

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an IP SLA track object.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PATCH call to apply changes to an existing track object. The
            name and the tracked sessions are set at creation and are never
            sent in an update.

        :return: True if object was modified and a PATCH request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        diff = {
            key: value
            for key, value in data.items()
            if self._original_attributes.get(key) != value
        }
        for key in ("name", "tracked_ipsla_session"):
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
        Perform a POST call to create a new IP SLA track object using the
            object's attributes as POST body. Exception is raised if object is
            unable to be created.

        :return: Boolean, True if entry was created.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The track object name is the index and must be in the POST body.
        data["name"] = self.name
        # The tracked sessions are a list of IP SLA source URIs.
        if self.tracked_ipsla_session:
            data["tracked_ipsla_session"] = [
                "{0}system/ipsla_sources/{1}".format(
                    self.session.resource_prefix, source.name
                )
                for source in self.tracked_ipsla_session
            ]
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the IP SLA track object.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific IP SLA track object URI.

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
