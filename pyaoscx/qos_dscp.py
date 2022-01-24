# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.unsupported_capability_error import (
    UnsupportedCapabilityError,
)

from pyaoscx.utils import util as utils

from pyaoscx.device import Device

from pyaoscx.pyaoscx_module import PyaoscxModule


class QosDscp(PyaoscxModule):
    """
    Provide configuration management for QoS DSCP trust mode on AOS-CX devices.
    """

    base_uri = "system/qos_dscp_map_entries"
    resource_uri_name = "qos_dscp_map_entries"

    indices = ["code_point"]

    def __init__(self, session, code_point, **kwargs):
        """
        Initialize a QoS DSCP trust mode object.
        :param session: pyaoscx.Session object used to represent logical
            connection to the device.
        :param code_point: Integer to identify a QoS DSCP configuration.
        """
        self.session = session
        self.__code_point = code_point

        # List used to determine attributes related to the QoS DSCP
        # configuration
        self.config_attrs = []
        self.materialized = False
        if "cos" in kwargs:
            self.cos = kwargs.pop("cos")
        if "priority_code_point" in kwargs:
            self.priority_code_point = kwargs.pop("priority_code_point")
        utils.set_creation_attrs(self, **kwargs)
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
        Method used to obtain the specific code point.
        :return: returns the code point of this QoS DSCP trust mode object.
        """
        # Use the @property decorator to make `self.code_point` read-only, and
        # return the actual value here
        return self.__code_point

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a QoS DSCP table entry and fill
            the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to query specific information.
        :return: Returns True if there is not an exception raised.
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

        if "cos" in data:
            self.__cos = data["cos"]
        if "color" in data:
            self.__color = data["color"]
        if "description" in data:
            self.__description = data["description"]
        if "local_priority" in data:
            self.__local_priority = data["local_priority"]
        if "priority_code_point" in data:
            self.__priority_code_point = data["priority_code_point"]

        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system QoS DSCP configurations from
            a switch.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return:  containing all system QoS.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        qos_dscp_dict = {}

        data = json.loads(response.text)
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            code_point, qos_dscp = cls.from_uri(session, uri)
            qos_dscp_dict[code_point] = qos_dscp

        return qos_dscp_dict

    @PyaoscxModule.materialized
    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to update an existing QoS table entry. Checks whether
            the QoS DSCP entry exists in the switch. Calls self.update if
            object is being updated.
        :return modified: Boolean, True if object was modified.
        """
        self.__modified = self.update()
        return self.__modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT request to update an existing QoS DSCP object.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        qos_dscp_data = utils.get_attrs(self, self.config_attrs)

        return self._put_data(qos_dscp_data)

    @PyaoscxModule.connected
    def create(self):
        # TODO: Remove once abstractmethod decorator is removed from parent
        pass

    @PyaoscxModule.connected
    def delete(self):
        # TODO: Remove once abstractmethod decorator is removed from parent
        pass

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a QoS DSCP trust mode object given a response_data related to
            the QoS DSCP trust mode object.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
                "3" : "/rest/v10.08/system/qos_dscp_map_entries/3"
            }
        :return: QoS DSCP trust mode object.
        """
        code_points_arr = session.api.get_keys(
            response_data, cls.resource_uri_name
        )

        code_point = code_points_arr[0]

        return cls(session, code_point)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a QoS DSCP object given a QoS DSCP trust mode URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: s String with a URI.
        :return: returns identifier and object.
        """
        # Separate values from URI
        if cls.base_uri not in uri:
            raise ValueError("Expected valid QoS DSCP trust mode URI.")

        # Extract code point from URI
        code_point = uri.split("/")[-1]

        qos_dscp = cls(session, code_point)

        # Return identifier and object
        return code_point, qos_dscp

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific QoS DSCP trust mode URI.
        :return: Object's URI.
        """
        # Return self.path containing the object's URI
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
        return "QoS DSCP trust mode {0}".format(self.code_point)

    @property
    def cos(self):
        """
        Getter method for the cos property.
        """
        return self.__cos

    @cos.setter
    def cos(self, cos):
        """
        Updates the value of the cos of this QoS DSCP instance.
        :param cos: Priority Code Point (PCP) that will be assigned to any IP
            packet with the specified DSCP codepoint, if that packet's ingress
            port has an effective trust mode of trust dscp. The new PCP is used
            when the packet is transmitted out a port or trunk with a VLAN tag.
            If the key is not specified, then no remark will occur.
        """
        # Verify data type
        if not isinstance(cos, int):
            raise ValueError("The value of cos must be an integer.")
        if not Device(self.session).is_capable("qos_cos_based_queueing"):
            raise UnsupportedCapabilityError(
                "This device doesn't support cos-based queueing"
            )
        self.__cos = cos

    @property
    def priority_code_point(self):
        """
        Getter method for the priority_code_point property.
        """
        return self.__priority_code_point

    @priority_code_point.setter
    def priority_code_point(self, priority_code_point):
        """
        Updates the value of the priority_code_point of this QoS DSCP instance.
        :param priority_code_point: Priority Code Point (PCP) that will be
            assigned to any IP packet with the specified DSCP codepoint, if
            that packet's ingress port has an effective trust mode of trust
            dscp. The new PCP is used when the packet is transmitted out a port
            or trunk with a VLAN tag.  If the key is not specified, then no
            remark will occur.
        """
        # Verify data type
        if not isinstance(priority_code_point, int):
            raise ValueError(
                "The value of priority_code_point must be an integer."
            )
        if not Device(self.session).is_capable("qos_dscp_map_cos_override"):
            raise UnsupportedCapabilityError(
                "This device doesn't support DSCP Map Cos Override"
            )
        self.__priority_code_point = priority_code_point

    @property
    def color(self):
        """
        Getter method for the color property.
        """
        return self.__color

    @color.setter
    def color(self, color):
        """
        Updates the value of the color of this QoS DSCP instance.
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
        Updates the description of this QoS DSCP instance.
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
        Updates the value of the local priority of this QoS DSCP instance.
        :param priority: Integer to represent an internal meta-data value that
            will be associated with the packet. This value will be used later
            to select the egress queue for the packet.
        """
        # Verify data type
        if not isinstance(priority, int):
            raise ValueError("ERROR: Priority must be an integer.")
        self.__local_priority = priority
