# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.device import Device

from pyaoscx.pyaoscx_module import PyaoscxModule


class Qos(PyaoscxModule):
    """
    Provide configuration management for QoS on AOS-CX devices.
    """

    base_uri = "system/qos"
    resource_uri_name = "qos"

    indices = ["name"]

    def __init__(self, session, name, **kwargs):
        """
        Initialize a Qos object.
        :param session: pyaoscx.Session object used to represent logical
            connection to the device.
        :param name: String representing a user-defined name for a Qos object.
        :param uri: a String with an URI.
        """
        self.session = session
        self.__name = name
        # List used to determine attributes related to the QoS configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False
        # Build path
        self.path = "{0}/{1}".format(self.base_uri, self.name)

    @property
    def name(self):
        """
        Method used to obtain the specific name.
        :return: returns the name of this Qos object.
        """
        # This uses the @property decorator to make self.name read-only
        return self.__name

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a QoS table entry and fill the
            object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs")
        # Set original attributes
        self._original_attributes = data

        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session):
        """
        Perfom GET request to retrieve all Schedule Profiles in a switch.
        :param session: pyaoscx.Session object used to represent a logical.
        :return: Dictionary containing all system QoS configurations.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        qos_dict = {}

        data = json.loads(response.text)
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            name, qos = cls.from_uri(session, uri)
            qos_dict[name] = qos

        return qos_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Schedule
            Profile. Checks whether the QoS configuration exists in the switch.
            Calls self.update() if object is being updated. Calls self.create()
            if a new object is being created.
        :return modified: Boolean, True if object was created or modified.
        """
        if self.materialized:
            self.__modified = self.update()
        else:
            self.__modified = self.create()
        return self.__modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Schedule Profile.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        qos_data = utils.get_attrs(self, self.config_attrs)
        return self._put_data(qos_data)

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST request to create a new QoS configuration using the
            object's attributes as the request's body. An exception is raised
            if object cannot be created.
        :return modified: Boolean, True if entry was created.
        """
        qos_data = utils.get_attrs(self, self.config_attrs)
        qos_data["name"] = self.name
        return self._post_data(qos_data)

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to delete QoS table entry.
        """
        self._send_data(self.path, None, "DELETE", "delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Qos object given a response_data related to it.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
                "<QoS name>": "/rest/v10.08/system/qos/<QoS name>"
            }
        :return: Qos Object.
        """
        qos_name_arr = session.api.get_keys(
            response_data, cls.resource_uri_name
        )
        qos_name = qos_name_arr[0]
        return cls(session, qos_name)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Qos object given a QoS URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return name, qos: tuple with the name of a QoS configuration, and a
            corresponding object.
        """
        # fail if uri is not a valid QoS URI
        if cls.base_uri not in uri:
            raise ValueError("ERROR: URI must be a valid QoS URI.")

        # Extract name from uri
        name = uri.split("/")[-1]
        qos = cls(session, name)

        return name, qos

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the this instance's URI.
        :return: Object's URI.
        """
        # Parent class uses self.path internally to store the value of the URI
        return self.path

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method to check it object has been modified.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    def __str__(self):
        return "Qos {0}".format(self.name)

    @classmethod
    def set_global_trust_mode(cls, session, trust_mode):
        """
        Sets the global trust mode for the switch.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param trust_mode: A string to set the global trust mode, which can be
            one of the following: "cos", "dscp", "none", or "default".
            Use the default option to use the switch's default trust mode.
        :return: Returns True if configuration was modified.
        """
        logging.info("Setting %s as global Qos trust mode.", trust_mode)

        # Verify trust mode value
        allowed_trust_modes = ["cos", "dscp", "none", "default"]
        if trust_mode not in allowed_trust_modes:
            raise VerificationError(
                "ERROR: QoS trust mode must be one of: ", allowed_trust_modes
            )

        device = Device(session)
        if not device.materialized:
            device.get()
        # If the incoming value is the same as the current one,
        # there's no need to change it
        if device.qos_config.get("qos_trust") == trust_mode:
            return False

        modified = False
        if trust_mode == "default":
            if "qos_trust" in device.qos_config:
                modified = (
                    device.qos_config["qos_trust"]
                    != device.qos_defaults["qos_trust"]
                )
                del device.qos_config["qos_trust"]
        else:
            device.qos_config["qos_trust"] = trust_mode
            modified = True

        device.apply()
        return modified

    @classmethod
    def set_global_schedule_profile(cls, session, profile):
        """
        Sets the global schedule profile (the name of a Qos object) for the
            switch.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param profile: Name of a schedule profile (the name of a Qos object)
            to set as the global schedule profile.
        """
        logging.info("Setting global schedule profile to: %s", profile)
        device = Device(session)
        device.get()
        setattr(device, "qos_default", profile)
        return device.apply()
