# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class TrafficInsightMonitor(PyaoscxModule):
    """
    Provide configuration management for Traffic Insight monitors on AOS-CX
        devices. A Traffic Insight monitor defines a monitoring request bound
        to a Traffic Insight instance. These resources live under
        system/traffic_insight_monitors and are indexed by the compound key
        (traffic_insight_instance, monitor_name, monitor_type).
    """

    base_uri = "system/traffic_insight_monitors"
    resource_uri_name = "traffic_insight_monitors"

    indices = ["traffic_insight_instance", "monitor_name", "monitor_type"]

    def __init__(
        self,
        session,
        traffic_insight_instance,
        monitor_name,
        monitor_type,
        **kwargs
    ):
        self.session = session
        # The compound index is (instance, monitor_name, monitor_type). The
        # instance is a TrafficInsight object.
        self.traffic_insight_instance = traffic_insight_instance
        self.monitor_name = monitor_name
        self.monitor_type = monitor_type
        self._uri = None
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        separator = self.session.api.compound_index_separator
        self.path = "{0}/{1}{2}{3}{4}{5}".format(
            self.base_uri,
            self.traffic_insight_instance.name,
            separator,
            self.monitor_name,
            separator,
            self.monitor_type,
        )
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Traffic Insight monitor and
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
        Perform a GET call to retrieve all Traffic Insight monitors and create
            a dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing the compound index as keys and
            TrafficInsightMonitor objects as values.
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
        for index, uri in data.items():
            collection[index] = cls.from_uri(session, uri)[1]

        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a TrafficInsightMonitor object given a monitor URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the compound index and the TrafficInsightMonitor
            object.
        """
        index = uri.rstrip("/").split("/")[-1]
        separator = session.api.compound_index_separator
        instance_name, monitor_name, monitor_type = index.split(separator)
        instance = session.api.get_module(
            session, "TrafficInsight", instance_name
        )
        monitor = cls(session, instance, monitor_name, monitor_type)
        return index, monitor

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update a Traffic Insight monitor.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Traffic Insight
            monitor.

        :return: True if object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Traffic Insight monitor using the
            object's attributes as POST body. Exception is raised if object is
            unable to be created.

        :return: Boolean, True if entry was created.
        """
        data = utils.get_attrs(self, self.config_attrs)
        # The compound index fields must be present in the POST body. The
        # instance is sent as a reference.
        data["traffic_insight_instance"] = (
            self.traffic_insight_instance.get_info_format()
        )
        data["monitor_name"] = self.monitor_name
        data["monitor_type"] = self.monitor_type
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the Traffic Insight monitor.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific Traffic Insight monitor URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix,
                self.path,
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
