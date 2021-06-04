# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from datetime import date

from pyaoscx.api import API


class v10_04(API):
    '''
    Represents a REST API Version 10.04. It keeps all the information
    needed for the version and methods related to it.
    '''

    def __init__(self):
        self.release_date = date(2019, 1, 1)
        self.version = '10.04'
        self.default_selector = 'writable'
        self.default_depth = 1
        self.default_facts_depth = 2
        self.default_subsystem_facts_depth = 4
        self.valid_selectors = [
            'configuration', 'status', 'statistics', 'writable']
        self.configurable_selectors = ['writable']
        self.compound_index_separator = ','
        self.valid_depths = [0, 1, 2, 3, 4]

    def valid_depth(self, depth):
        '''
        Verifies if given depth is valid for the current API version
        :param depth: Integer
        :return valid: Boolean True if depth is valid
        '''
        valid = True
        if depth not in self.valid_depths:
            valid = False
        return valid

    def get_index(self, obj):
        '''
        Method used to obtain the correct format of the objects information
        which depends on the Current API version
        :param obj: PyaoscxModule object
        :return info: Dictionary in the form of
        Example:
         "keepalive_vrf": {
                "keepalive_name": "Resource uri",
            }

        '''
        key_str = ""
        length = len(obj.indices)
        attributes = []
        for i in range(length):
            attr_name = obj.indices[i]
            attr_value = getattr(obj, attr_name)
            if not isinstance(attr_value, str):
                attr_value = str(attr_value)
            attributes.append(attr_value)

        key_str = ','.join(attributes)
        info = {
            key_str: obj.get_uri()
        }
        return info

    def get_module(self, session, module, index_id=None, **kwargs):
        '''
        Create a module object given a response data and the module's type.

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param module: Name representing the module which is about to be
            created
        :param index_id: The module index_id or ID
        :return object: Return object same as module

        '''

        if module == 'Interface':
            from pyaoscx.rest.v10_04.interface import Interface

        elif module == 'Ipv6':
            from pyaoscx.ipv6 import Ipv6

        elif module == 'Vlan':
            from pyaoscx.vlan import Vlan

        elif module == 'Vrf':
            from pyaoscx.vrf import Vrf

        elif module == 'Vsx':
            from pyaoscx.vsx import Vsx
            return Vsx(session, **kwargs)

        elif module == 'BgpRouter':
            from pyaoscx.bgp_router import BgpRouter

        elif module == 'BgpNeighbor':
            from pyaoscx.bgp_neighbor import BgpNeighbor

        elif module == 'VrfAddressFamily':
            from pyaoscx.vrf_address_family import VrfAddressFamily

        elif module == 'OspfRouter':
            from pyaoscx.ospf_router import OspfRouter

        elif module == 'OspfArea':
            from pyaoscx.ospf_area import OspfArea
            # Add data for correct Ospf Area creation
            other_config = {
                "stub_default_cost": 1,
                "stub_metric_type": "metric_non_comparable"
            }
            return OspfArea(session, index_id, other_config=other_config,
                            **kwargs)

        elif module == 'OspfInterface':
            from pyaoscx.ospf_interface import OspfInterface

        elif module == 'DhcpRelay':
            from pyaoscx.dhcp_relay import DhcpRelay

        elif module == 'ACL':
            from pyaoscx.acl import ACL

        elif module == 'AclEntry':
            from pyaoscx.acl_entry import AclEntry

        elif module == 'AggregateAddress':
            from pyaoscx.aggregate_address import AggregateAddress

        elif module == 'StaticRoute':
            from pyaoscx.static_route import StaticRoute

        elif module == 'StaticNexthop':
            from pyaoscx.static_nexthop import StaticNexthop

        else:
            raise Exception("Invalid Module Name")

        return locals()[module](session, index_id, **kwargs)
      
    def get_keys(self, response_data, module_name=None):
        '''
        Given a response_data obtain the indices of said dictionary and return
        them.
        Get keys should be used for only one element in the dictionary.
        :param response_data: a dictionary object in the form of
            {
                "index_1,index_2": "/rest/v10.04/system/<module>/<index_1>,<index_2>",
            }
        :return indices: List of indices
        '''

        indices = None
        for k, v in response_data.items():
            indices = k

        indices = indices.split(',')
        return indices

    def get_uri_from_data(self, data):
        '''
        Given a response data, create a list of URI items. In this Version the
        data is a dict.

        :param data: Dictionary containing URI data in the form of
            example:
            {'<name>': '/rest/v10.04/system/<module>/<name>',
            '<name>': '/rest/v10.04/system/<module>/<name>',
            '<name>': '/rest/v10.04/system/<module>/<name>'}

        :return uri_list: a list containing the input dictionary's values
            example:
            [
                '/rest/v10.04/system/<module>/<name>',
                '/rest/v10.04/system/<module>/<name>'
            ]

        '''
        uri_list = []
        for k, v in data.items():
            uri_list.append(v)

        return uri_list
