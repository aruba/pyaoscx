# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from abc import ABC, abstractmethod
from importlib import import_module

from pyaoscx.exceptions.parameter_error import ParameterError


class API(ABC):
    """
    Generic API class, that handles REST API versioning.
    """

    license = "Apache-2.0"

    def __str__(self):
        return self.version

    @classmethod
    def create(cls, target_version):
        """
        Translate the version string name to a valid python symbol.
        :param cls: API Class object.
        :param target_version: String with the API Version.
        :return api: API object.
        """
        version_name = "v" + target_version.replace(".", "_")

        try:
            # Import the appropriate API class based on the name.
            target_module = "pyaoscx.rest.{0}.api".format(version_name)
            api_class = getattr(import_module(target_module), version_name)

        except ModuleNotFoundError:
            raise ParameterError("Provided API version is not valid")

        return api_class()

    @classmethod
    @abstractmethod
    def __init__(self):
        """
        This method must be overwritten in the derived classes to set up the
            internal attributes, like version as minimum.
        """
        pass

    def valid_depth(self, depth):
        """
        Verifies if given depth is valid for the current API version.
        :param depth: Integer
        :return valid: Boolean True if depth is valid.
        """
        return depth in self.valid_depths

    def get_index(self, obj):
        """
        Method used to obtain the correct format of the objects information
            which depends on the Current API version.
        :param obj: PyaoscxModule object.
        :return info: Dictionary in the form of:
            "keepalive_vrf": {
                "keepalive_name": "Resource uri",
            }.
        """
        key_str = ""
        length = len(obj.indices)
        attributes = []
        for i in range(length):
            attr_name = obj.indices[i]
            attr_value = getattr(obj, attr_name)
            if not isinstance(attr_value, str):
                attr_value = str(attr_value)
            attributes.append(attr_value)

        key_str = ",".join(attributes)
        info = {key_str: obj.get_uri()}
        return info

    def get_keys(self, response_data, module_name=None):
        """
        Given a response_data obtain the indices of said dictionary and return
            them. Get keys should be used for only one element in the
            dictionary.
        :param response_data: a dictionary object in the form of:
            {
                "idx_1,idx_2": "/rest/v10.0X/system/<module>/<idx_1>,<idx_2>",
            }
        :return indices: List of indices.
        """
        indices = None
        for k, v in response_data.items():
            indices = k

        indices = indices.split(",")
        return indices

    def get_uri_from_data(self, data):
        """
        Given a response data, create a list of URI items. In this Version the
            data is a dict.
        :param data: Dictionary containing URI data in the form of:
            {
                '<name>': '/rest/v10.0X/system/<module>/<name>',
                '<name>': '/rest/v10.0X/system/<module>/<name>',
                '<name>': '/rest/v10.0X/system/<module>/<name>'
            }.
        :return uri_list: a list containing the input dictionary's values.
            Example:
            [
                '/rest/v10.0X/system/<module>/<name>',
                '/rest/v10.0X/system/<module>/<name>'
            ].
        """
        uri_list = []
        for k, v in data.items():
            uri_list.append(v)

        return uri_list

    def get_module_class(self, session, name):
        """
        Get a module's class given a session, and the module's name.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param name: Name of the module's class to be imported.
        """
        module_names = {
            "Interface": "rest.v{0}.interface".format(
                self.version.replace(".", "_")
            ),
            "Ipv6": "ipv6",
            "Vlan": "vlan",
            "Vrf": "vrf",
            "Vsx": "vsx",
            "BgpRouter": "bgp_router",
            "BgpNeighbor": "bgp_neighbor",
            "VrfAddressFamily": "vrf_address_family",
            "OspfRouter": "ospf_router",
            "Ospfv3Router": "ospfv3_router",
            "OspfVlink": "ospf_virtual_link",
            "OspfArea": "ospf_area",
            "OspfInterface": "ospf_interface",
            "DhcpRelay": "dhcp_relay",
            "ACL": "acl",
            "AclEntry": "acl_entry",
            "AggregateAddress": "aggregate_address",
            "StaticRoute": "static_route",
            "StaticNexthop": "static_nexthop",
            "PoEInterface": "poe_interface",
            "Mac": "mac",
            "StaticMac": "static_mac",
            "Qos": "qos",
            "QosCos": "qos_cos",
            "QosDscp": "qos_dscp",
            "Queue": "queue",
            "QueueProfile": "queue_profile",
            "QueueProfileEntry": "queue_profile_entry",
            "TunnelEndpoint": "tunnel_endpoint",
            "Vni": "vni",
        }
        if name not in module_names:
            raise ParameterError(
                "Wrong module name. {0} doesn't exist".format(name)
            )
        return getattr(import_module("pyaoscx." + module_names[name]), name)

    def get_module(self, session, module, index_id=None, **kwargs):
        """
        Create a module object given a response data and the module's type.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param module: Name representing the module which is about to be
            created
        :param index_id: The module index_id or ID
        :return object: Return object same as module
        """
        module_class = self.get_module_class(session, module)

        if module == "OspfArea":
            return self._create_ospf_area(
                module_class, session, index_id, **kwargs
            )
        elif module == "Vsx":
            return self._create_vsx(module_class, session, **kwargs)
        else:
            return module_class(session, index_id, **kwargs)

    def _create_vsx(self, module_class, session, **kwargs):
        return module_class(session, **kwargs)
