# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re
from copy import deepcopy

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class ContainerIsolatedNetwork(PyaoscxModule):
    """
    Provide configuration management for Container Isolated Networks on
        AOS-CX devices.

    Container Isolated Networks provide network connectivity to containers
    running on AOS-CX switches. Each isolated network is associated with a
    VLAN and an IPv4 address that the container will use.

    Note: Container endpoints require API version v10.17+ on 8325 (GL.10.19)
        or v10.18+ on 6300 (FL.10.18). Ensure the Session is created with
        the appropriate API version.
    """

    base_uri = "system/container_isolated_networks"
    resource_uri_name = "container_isolated_networks"
    indices = ["name"]

    def __init__(
        self,
        session,
        name,
        vlan=None,
        ipv4_address=None,
        uri=None,
        **kwargs,
    ):
        """
        Create a ContainerIsolatedNetwork object.

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param name: Alphanumeric name of the isolated network.
        :param vlan: A Vlan object or VLAN ID (int) to associate with this
            isolated network. Used to build the virtual_interfaces reference.
        :param ipv4_address: IPv4 address with prefix for the network,
            e.g. "192.168.10.99/24".
        :param uri: Optional URI string.
        :param kwargs: Additional keyword arguments for writable attributes.
        """
        self.session = session
        self._uri = uri
        self.name = name
        self.vlan = vlan
        self.ipv4_address = ipv4_address
        self.virtual_interfaces = None
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        self.__modified = False
        utils.set_creation_attrs(self, **kwargs)

        self.path = "{0}/{1}".format(
            ContainerIsolatedNetwork.base_uri, self.name
        )

    def _build_virtual_interfaces(self):
        """
        Build the virtual_interfaces dictionary from the vlan and
            ipv4_address attributes.

        :return: Dictionary suitable for the REST API payload.
        """
        if self.vlan is None and self.ipv4_address is None:
            return self.virtual_interfaces
        if self.vlan is None or self.ipv4_address is None:
            raise ParameterError(
                "Both VLAN and IPv4 address are needed to select an interface"
            )

        # Accept either a Vlan object or an integer VLAN ID
        if hasattr(self.vlan, "id"):
            vlan_id = self.vlan.id
        else:
            vlan_id = int(self.vlan)

        vlan_uri = "{0}system/vlans/{1}".format(
            self.session.resource_prefix, vlan_id
        )
        interfaces = deepcopy(self.virtual_interfaces or {})
        interface_key = next(
            (
                key for key in interfaces
                if str(key).rstrip("/").rsplit("/", 1)[-1] == str(vlan_id)
            ),
            vlan_uri,
        )
        attributes = interfaces.get(interface_key, {})
        if interface_key not in interfaces and len(interfaces) == 1:
            attributes = interfaces.pop(next(iter(interfaces)))
        attributes["ipv4_address"] = self.ipv4_address
        interfaces[interface_key] = attributes
        return interfaces

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Container Isolated Network
            table entry and fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        utils.create_attrs(self, data)

        if "virtual_interfaces" in data:
            self.vlan = None
            self.ipv4_address = None
            interfaces = self.virtual_interfaces or {}
            if len(interfaces) == 1:
                reference, attributes = next(iter(interfaces.items()))
                self.vlan = int(str(reference).rstrip("/").rsplit("/", 1)[-1])
                self.ipv4_address = attributes.get("ipv4_address")

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(
                self, data, "config_attrs", ["name"]
            )

        self._original_attributes = data
        if "name" in self._original_attributes:
            self._original_attributes.pop("name")

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all Container Isolated Networks and
            create a dictionary containing each respective object.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing network names as keys and
            ContainerIsolatedNetwork objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request(
                "GET", ContainerIsolatedNetwork.base_uri
            )
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        networks_dict = {}
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            name, net = ContainerIsolatedNetwork.from_uri(session, uri)
            networks_dict[name] = net

        return networks_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create a Container Isolated Network, or
            update an existing one. Checks whether the network exists in the
            switch. Calls self.update() if network is being updated. Calls
            self.create() if the network doesn't exist in the switch.

        :return modified: Boolean, True if object was created or modified.
        """
        modified = False
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Container Isolated
            Network table entry.

        :return modified: True if Object was modified and a PUT request was
            made.
        """
        net_data = utils.get_attrs(self, self.config_attrs)

        vi = self._build_virtual_interfaces()
        if vi is not None:
            net_data["virtual_interfaces"] = vi

        return self._put_data(net_data)

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Container Isolated Network using
            the object's attributes as POST body.

        :return modified: Boolean, True if network was created.
        """
        net_data = utils.get_attrs(self, self.config_attrs)
        net_data["name"] = self.name

        vi = self._build_virtual_interfaces()
        if vi is not None:
            net_data["virtual_interfaces"] = vi

        return self._post_data(net_data)

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete Container Isolated Network table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a ContainerIsolatedNetwork object given response_data.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
            "net10": "/rest/v10.18/system/container_isolated_networks/net10"
            }
        :return: ContainerIsolatedNetwork Object.
        """
        name_arr = session.api.get_keys(
            response_data, ContainerIsolatedNetwork.resource_uri_name
        )
        name = name_arr[0]
        return ContainerIsolatedNetwork(session, name)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a ContainerIsolatedNetwork object given a URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: tuple (name, ContainerIsolatedNetwork object).
        """
        index_pattern = re.compile(
            r"(.*)container_isolated_networks/(?P<index>.+)"
        )
        name = index_pattern.match(uri).group("index")
        net_obj = ContainerIsolatedNetwork(session, name, uri=uri)
        return name, net_obj

    def __str__(self):
        return "ContainerIsolatedNetwork, name: '{0}'".format(self.name)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific object URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                ContainerIsolatedNetwork.base_uri,
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

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified
