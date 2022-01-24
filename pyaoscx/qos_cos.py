# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class QosCos(PyaoscxModule):
    """
    Provide configuration management for QoS COS trust mode on AOS-CX devices.
    """

    base_uri = "system/qos_cos_map_entries"
    resource_uri_name = "qos_cos_map_entries"

    indices = ["code_point"]

    def __init__(self, session, code_point, **kwargs):
        """
        Initialize a QoS COS trust mode object.
        :param session: pyaoscx.Session object used to represent logical
            connection to the device.
        :param code_point: Integer to identify a QoS COS trust mode object.
        """
        self.session = session
        self.__code_point = code_point

        # List used to determine attributes related to the QoS COS
        # configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}

        # Attribute used to know if object was changed recently
        self.__modified = False
        # Build path
        self.path = "{0}/{1}".format(self.base_uri, self.code_point)

    @property
    def code_point(self):
        """
        Method used to retrieve object's code point.
        :return: returns the code point of this QoS COS trust mode object.
        """
        # This uses the @property decorator to make self.code_point read-only
        return self.__code_point

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a QoS COS trust mode table
            entry and fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs")

        # Set original attributes
        self._original_attributes = data

        self.__color = data["color"]
        self.__description = data["description"]
        self.__local_priority = data["local_priority"]

        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system QoS COS trust mode
            configurations from of a switch.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing all system Schedule Profiles.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        qos_cos_dict = {}
        data = json.loads(response.text)
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            code_point, qos_cos = cls.from_uri(session, uri)
            qos_cos_dict[code_point] = qos_cos

        return qos_cos_dict

    @PyaoscxModule.materialized
    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to update an existing QoS COS trust mode table entry.
            Checks whether the QoS COS trust mode exists in the switch. Calls
            self.update if object is being updated.
        :return modified: Boolean, True if object was modified.
        """
        # Modify object
        self.__modified = self.update()
        return self.__modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to update an existing QoS COS trust mode object.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        qos_cos_data = utils.get_attrs(self, self.config_attrs)
        return self._put_data(qos_cos_data)

    @PyaoscxModule.connected
    def create(self):
        # TODO: Remove when abstractmethod decorator is removed from parent
        pass

    @PyaoscxModule.connected
    def delete(self):
        # TODO: Remove when abstractmethod decorator is removed from parent
        pass

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a QoS COS trust mode object given a response_data related to the
            existing QoS COS trust mode object.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
                "3" : "/rest/v10.08/system/qos_cos_map_entries/3"
            }
        :return: QoS COS trust mode object.
        """
        code_points_arr = session.api.get_keys(
            response_data, cls.resource_uri_name
        )
        code_point = code_points_arr[0]

        return cls(session, code_point)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an object given a QoS COS trust mode URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: s String with an URI.
        :return: returns identifier and object.
        """
        # Separate values from URI
        if cls.base_uri not in uri:
            raise ValueError(
                "ERROR: Invalid URI. String must be a valid QoS COS trust"
                "mode URI."
            )

        # Extract code point from URI
        code_point = uri.split("/")[-1]
        qos_cos = cls(session, code_point)

        # Return identifier and object
        return code_point, qos_cos

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain object's URI.
        :return: Object's URI.
        """
        # The self.path variable stores the URI
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
        return "QoS COS trust mode {0}".format(self.code_point)

    @property
    def color(self):
        """
        Getter method for the color property.
        """
        return self.__color

    @color.setter
    def color(self, color):
        """
        Updates the value of the color of this QoS COS instance.
        :param color: String to identify the color which may be used later in
            the pipeline in packet-drop decision points. Example: "green".
        """
        # Verify data type
        if not isinstance(color, str):
            raise ValueError("ERROR: Color value must be a string.")

        self.__color = color

    @property
    def description(self):
        """
        Getter method for the description property.
        """
        return self.__description

    @description.setter
    def description(self, description):
        """
        Updates the description of this QoS COS instance.
        :param description: String used for customer documentation.
        """
        # Verify data type
        if not isinstance(description, str):
            raise ValueError("ERROR: Description value must be a string.")

        self.__description = description

    @property
    def local_priority(self):
        """
        Getter method for the local_priority.
        """
        return self.__local_priority

    @local_priority.setter
    def local_priority(self, priority):
        """
        Updates the value of the local priority of this QoS COS instance.
        :param priority: Integer to represent an internal meta-data value that
            will be associated with the packet. This value will be used later
            to select the egress queue for the packet.
        """
        # Verify data type
        if not isinstance(priority, int):
            raise ValueError("ERROR: Priority must be an integer.")

        self.__local_priority = priority
