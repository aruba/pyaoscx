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

from pyaoscx.pyaoscx_module import PyaoscxModule

from pyaoscx.device import Device
from pyaoscx.qos import Qos


class Queue(PyaoscxModule):
    """
    Provide configuration management for Queues on AOS-CX devices.
    """

    indices = ["queue_number", "qos_name"]
    resource_uri_name = "queues"

    def __init__(self, session, qos_name, queue_number, **kwargs):
        """
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param qos_name: String with a user-defined name for a Qos object.
        :param queue_number: Integer representing a queue priority, which are
            numbered in priority order, with zero being the lowest priority.
            The maximum number of queues is hardware dependent.
        """
        self.session = session
        self.__queue_number = queue_number
        self.__qos_name = qos_name
        # this is needed for the property, this is safe
        self.__gmb_percent = None
        self.__burst = None
        # List of configuration attributes
        self.config_attrs = []

        # Get and remove burst from kwargs if given
        if "burst" in kwargs:
            self.burst = kwargs.pop("burst")

        # Get and remove gmb_percent from kwargs if given
        if "gmb_percent" in kwargs:
            self.gmb_percent = kwargs.pop("gmb_percent")

        # Original attributes
        self._original_attributes = {}
        self.materialized = False
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

        self.base_uri = "{0}/{1}/{2}".format(
            Qos.base_uri, qos_name, self.resource_uri_name
        )

        self.path = "{0}/{1}".format(self.base_uri, self.queue_number)

    @property
    def burst(self):
        return self.__burst

    @burst.setter
    def burst(self, value):
        if not Device(self.session).is_capable("qos_queue_burst"):
            raise UnsupportedCapabilityError(
                "This device can't configure a Queue's burst."
            )
        self.__burst = value

    @property
    def gmb_percent(self):
        return self.__gmb_percent

    @gmb_percent.setter
    def gmb_percent(self, value):
        if not Device(self.session).is_capable("qos_sched_min_bandwidth"):
            raise UnsupportedCapabilityError(
                "This device can't configure a Queue's minimum bandwidth."
            )
        self.__gmb_percent = value

    @property
    def queue_number(self):
        """
        Method to retrieve the queue_number identifier of this object.
        :return: returns the queue number of this object.
        """
        return self.__queue_number

    @property
    def qos_name(self):
        """
        Method to retrieve the qos_name identifier of this object.
        :return: returns the Qos name of this object.
        """
        return self.__qos_name

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Queue table entry and fill
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
        for k, v in data.items():
            setattr(self, k, v)

        if selector in self.session.api.configurable_selectors:
            self.config_attrs = list(data)

        # Set original attributes
        self._original_attributes = data

        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session, qos_name):
        """
        Perform a GET call to retrieve all system Queues for given Schedule
            Profile from a switch.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing all system Schedule Profile's Queues.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}{1}/{2}/{3}".format(
            cls.base_uri, Qos.base_uri, qos_name, cls.resource_uri_name
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        queues_dict = {}

        data = json.loads(response.text)
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            number, queue = cls.from_uri(session, uri)
            queues_dict[number] = queue

        return queues_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Queue. Checks
            whether the Queue exists in the switch. Calls self.update() if
            object is being updated.
        Calls self.create() if a new object is being created.
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
        Perform a PUT call to apply changes to an existing Queue table entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        queue_data = utils.get_attrs(self, self.config_attrs)
        return self._put_data(queue_data)

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST request to create a new Queue using the object's
            attributes as the request body. An exception is raised if object
            cannot be created.
        :return modified: Boolean, True if entry was created.
        """
        queue_data = utils.get_attrs(self, self.config_attrs)
        queue_data["queue_number"] = self.queue_number

        return self._post_data(queue_data)

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to delete Queue table entry.
        """
        self._send_data(self.path, None, "DELETE", "delete")

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Queue object given a related response_data.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
                "strict": "/rest/v10.08/system/qos/"<Qos name>/queues/7"
            }
        :return: Queue Object.
        """
        # Check if response is a dictionary, if so, get its value
        if isinstance(response_data, dict):
            data = list(response_data.items())[0][1]
        else:
            # when not a dictionary, it's a string
            data = response_data

        # Get queue number from uri
        data_arr = data.split("/")
        queue_number = data_arr[-1]
        qos_name = data_arr[data_arr.index(Qos.resource_uri_name) + 1]

        return cls(session, qos_name, queue_number)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Queue object given a Queue URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return name, queue: tuple with the Queue object and its name.
        """
        # Get queue number from uri
        uri_arr = uri.split("/")
        queue_number = uri_arr[-1]
        qos_name = uri_arr[uri_arr.index(Qos.resource_uri_name) + 1]
        queue = cls(session, qos_name, queue_number)

        return queue_number, queue

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain this instance's URI.
        :return: Object's URI.
        """
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
        return "Queue {0}".format(self.queue_number)
