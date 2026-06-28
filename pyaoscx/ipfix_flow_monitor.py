# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class IpfixFlowMonitor(PyaoscxModule):
    """
    Provide configuration management for IPFIX flow monitors on AOS-CX
        devices. A flow monitor binds a flow record to one or more flow
        exporters and controls the flow cache timeouts. These resources live
        under system/ipfix_flow_monitors and are indexed by name.
    """

    base_uri = "system/ipfix_flow_monitors"
    resource_uri_name = "ipfix_flow_monitors"

    indices = ["name"]

    def __init__(self, session, name, **kwargs):
        self.session = session
        # The index is the flow monitor name
        self.name = name
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
        Perform a GET call to retrieve data for a flow monitor and fill the
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
        # them into pyaoscx objects so they are easy to manipulate.
        self._references_to_objects()
        self.materialized = True
        return True

    def _references_to_objects(self):
        """
        Convert the {name: uri} reference dictionaries returned by the API
            into pyaoscx objects: a list of IpfixFlowExporter for "exporter"
            and a single IpfixFlowRecord for "record".
        """
        exporter = getattr(self, "exporter", None)
        if isinstance(exporter, dict):
            setattr(
                self,
                "exporter",
                [
                    self.session.api.get_module(
                        self.session, "IpfixFlowExporter", n
                    )
                    for n in exporter
                ],
            )
        record = getattr(self, "record", None)
        if isinstance(record, dict):
            names = list(record)
            setattr(
                self,
                "record",
                (
                    self.session.api.get_module(
                        self.session, "IpfixFlowRecord", names[0]
                    )
                    if names
                    else None
                ),
            )

    def _build_data(self):
        """
        Build the request body, serializing reference attributes into the
            API's {name: uri} form.

        :return: Dictionary ready to be sent to the switch.
        """
        data = utils.get_attrs(self, self.config_attrs)
        if "exporter" in data:
            formatted = {}
            for obj in getattr(self, "exporter") or []:
                formatted.update(obj.get_info_format())
            data["exporter"] = formatted
        if "record" in data:
            record = getattr(self, "record")
            data["record"] = record.get_info_format() if record else {}
        return data

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all flow monitors and create a
            dictionary containing each one.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing monitor names as keys and
            IpfixFlowMonitor objects as values.
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
        Create an IpfixFlowMonitor object given a flow monitor URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the monitor name and the IpfixFlowMonitor object.
        """
        name = uri.rstrip("/").split("/")[-1]
        monitor = cls(session, name)
        return name, monitor

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update a flow monitor.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing flow monitor.

        :return: True if object was modified and a PUT request was made.
        """
        data = self._build_data()
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new flow monitor using the object's
            attributes as POST body. Exception is raised if object is unable
            to be created.

        :return: Boolean, True if entry was created.
        """
        data = self._build_data()
        # The monitor name is the index and must be present in the POST body.
        data["name"] = self.name
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the flow monitor.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific flow monitor URI.

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
