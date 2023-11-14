# (C) Copyright 2023 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError

import pyaoscx.utils.util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class ObjectGroup(PyaoscxModule):
    """
    Provide configuration management for IPv6 on AOS-CX devices.
    """

    indices = ["name", "object_type"]
    collection_uri = "system/acl_object_groups"
    object_uri = collection_uri + "/{name},{type}"
    resource_uri_name = "acl_object_groups"

    def __init__(self, session, name, object_type):
        """
        Create an instance of ObjectGroup class

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param name: Name of the object group
        :param object_type: Type of object group (ipv4, ipv6, l4port)
        """
        self.session = session
        self.name = name
        self.object_type = object_type
        self.cfg_addresses = {}
        self.cfg_ports = {}
        self.vsx_sync = []
        self.cfg_version = 0
        uri_indices = {
            "name": self.name,
            "type": self.object_type,
        }
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(**uri_indices)
        self._prev_attrs = {}
        for attr in ["cfg_ports", "cfg_addresses", "vsx_sync"]:
            self._prev_attrs[attr] = getattr(self, attr).copy()

    def __eq__(self, other):
        return (
            isinstance(other, ObjectGroup)
            and self.name == other.name
            and self.object_type == other.object_type
        )

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an Object Group table entry and
            fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        self._get_and_copy_data(depth, selector, self.indices)
        for attr in ["cfg_ports", "cfg_addresses", "vsx_sync"]:
            self._prev_attrs[attr] = getattr(self, attr).copy()
        self.materialized = True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all Object Groups and create dictionary
            containing each respective class

        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch
        :return: Dictionary containing class id and a object as value
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.collection_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        group_collection = {}
        for uri in data.values():
            group_id, group_obj = cls.from_uri(session, uri)
            group_collection[group_id] = group_obj

        return group_collection

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an
            Object Group table entry

        :return: True if the object was modified
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Object Group using the object's
            attributes as POST body. Exception is raised if object is unable
            to be created

        :returnd: Boolean, True if entry was created
        """
        logging.info("Creating %s in switch", self)
        group_data = {}
        group_data["cfg_version"] = 0
        group_data["object_type"] = self.object_type
        group_data["name"] = self.name
        self.__modified = self._post_data(group_data)
        return self.__modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Classifier

        :return: True if object was modified and a PUT request was made.
        """
        group_data = {}
        modified = False
        if (
            self.object_type in ["ipv4", "ipv6"]
            and self._prev_attrs["cfg_addresses"] != self.cfg_addresses
        ):
            group_data["cfg_addresses"] = self.cfg_addresses.copy()
            self.cfg_version = self.cfg_version + 1
            modified = True
        elif (
            self.object_type == "l4port"
            and self._prev_attrs["cfg_ports"] != self.cfg_ports
        ):
            group_data["cfg_ports"] = self.cfg_ports.copy()
            self.cfg_version = self.cfg_version + 1
            modified = True
        if self.vsx_sync != self._prev_attrs["vsx_sync"]:
            group_data["vsx_sync"] = self.vsx_sync
            modified = True
        if modified:
            logging.info("Updating %s in switch", self)
            group_data["cfg_version"] = self.cfg_version
            self.__modified = self._put_data(group_data)
            del group_data["cfg_version"]
            self._prev_attrs.update(group_data)
        else:
            self.__modified = False
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the Classifier entry.
        """
        logging.info("Deleting %s from switch", self)
        self._send_data(self.path, None, "DELETE", "Delete")
        self._prev_attrs.clear()

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create an Onbject Group given a response_data

        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param response_data: The response must be a dictionary of the form:
            {id: URL}
        :return: Object Group
        """
        uri = next(iter(response_data.values()))
        _, group_obj = cls.from_uri(session, uri)
        return group_obj

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an object given an Object Group URI

        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param uri: A String with a URI
        :return: tuple containing the Object Group id and the object.
        """
        index_pattern = re.compile(
            r"(.*)system/acl_object_groups/(?P<name>.+),(?P<grp_type>.+)"
        )
        pattern_match = index_pattern.match(uri)
        group_name = pattern_match.group("name")
        group_type = pattern_match.group("grp_type")
        group_key = "{0},{1}".format(group_name, group_type)
        group_obj = cls(session, group_name, group_type)
        return group_key, group_obj

    def __str__(self):
        return "Object Group {0},{1}".format(self.name, self.object_type)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific Object Group URI

        :return: Object's URI
        """
        uri = "{0}{1}".format(self.session.resource_prefix, self.path)
        return uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method to obtain correct object format for referencing inside
            other objects

        return: Object format depending on the API Version
        """
        return self.session.api.get_index(self)

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.

        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    @PyaoscxModule.materialized
    def update_ip_entry_to_group(self, index, ip_address):
        """
        Create or update an ip address entry

        :param index: Index of the ip address in the group
        :param ip_address: IP address to add or update
        :return: True if the object has been modified
        """
        version = utils.get_ip_version(ip_address)
        if version != self.object_type:
            raise ParameterError(
                "IP version mismatch: {0} is not {1}".format(
                    ip_address, self.object_type
                )
            )
        if not isinstance(index, str):
            index = str(index)
        group_data = {}
        group_data[index] = utils.fix_ip_mask(ip_address, self.object_type)
        self.cfg_addresses.update(group_data)
        return self.update()

    @PyaoscxModule.materialized
    def remove_ip_entry_from_group(self, index):
        """
        Remove an IP entry from group

        :param index: Index of the ip address to remove
        :return: True if the object has been modified
        """
        if not isinstance(index, str):
            index = str(index)
        if index in self.cfg_addresses:
            del self.cfg_addresses[index]
            return self.update()
        else:
            logging.warning(
                "Index %s not found in IP group for %s", str(index), self
            )
            return False

    @PyaoscxModule.materialized
    def update_port_range_to_group(self, index, port_min=0, port_max=65535):
        """
        Create or update an L4 port range entry

        :param index: Index of the port range in the group
        :param port_min: Minimum port of the range
        :param port_max: Maximum port of the range
        :return: True if the object has been modified
        """
        if self.object_type != "l4port":
            raise ParameterError("{0} is not type L4 port".format(self))
        if not isinstance(index, str):
            index = str(index)
        group_data = {}
        group_data[index] = {
            "l4_port_min": int(port_min),
            "l4_port_max": int(port_max),
        }
        self.cfg_ports.update(group_data)
        return self.update()

    @PyaoscxModule.materialized
    def update_port_to_group(self, index, port):
        """
        Create or update an L4 port entry, it can be numeric or string value

        :param index: Index of the port entry in the group
        :param port: L4 port, it can be string or numeric
        :return: True if the object has been modified
        """
        if not isinstance(index, str):
            index = str(index)
        if isinstance(port, int):
            tmp_port = port
        elif isinstance(port, str):
            if port.isnumeric():
                tmp_port = int(port)
            elif port in utils.l4_ports:
                tmp_port = utils.l4_ports[port]
            else:
                raise ParameterError(
                    "Invalid L4 port name {0}, valid names are: {1}".format(
                        port, ", ".join(utils.l4_ports)
                    )
                )
        else:
            raise ParameterError("Invalid port {0}".format(port))
        group_data = {}
        group_data[index] = {"l4_port_min": tmp_port, "l4_port_max": tmp_port}
        self.cfg_ports.update(group_data)
        return self.update()

    @PyaoscxModule.materialized
    def remove_port_range_from_group(self, index):
        """
        Remove a Port Range entry

        :param index: Index of the port range to remove
        :return: True if the object has been modified
        """
        if not isinstance(index, str):
            index = str(index)
        if index in self.cfg_ports:
            del self.cfg_ports[index]
            return self.update()
        else:
            logging.warning(
                "Index %s not found in Port Range for %s", str(index), self
            )
            return False
