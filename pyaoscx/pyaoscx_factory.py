# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.session import Session
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.device import Device
from pyaoscx.dns import Dns
from pyaoscx.configuration import Configuration


class PyaoscxFactory():
    '''
    Provide a Factory class to instantiate all pyaoscx Modules
    through specific methods.
    Using the API Version given by the Session
    '''

    __instance__ = None

    def __init__(self, session: Session):

        self.session = session
        if PyaoscxFactory.__instance__ is None:
            PyaoscxFactory.__instance__ = self
        else:
            raise Exception("You cannot create another PyaoscxFactory class")

    @staticmethod
    def get_instance(session):
        """
        Static method to fetch the current instance.
        """
        if not PyaoscxFactory.__instance__:
            PyaoscxFactory(session)
        return PyaoscxFactory.__instance__

    def device(self):
        """
        Create a Device class, to obtain common device configuration,
        capacities, capabilities, among other information related.
        :return: Device object
        """

        switch = Device(self.session)
        # Get Partial configuration attributes
        switch.get()
        return switch

    def configuration(self):
        """
        Create a Configuration class, to obtain device configuration
        and perform other actions such as backup_config
        :return: Configuration object
        """

        config = Configuration(self.session)
        # Get full configuration
        config.get()
        return config

    def dns(self, vrf=None,
            domain_name=None,
            domain_list=None,
            domain_servers=None,
            host_v4_address_mapping=None,
            host_v6_address_mapping=None):
        """
        Create a DNS class, to configure a DNS inside a given VRF
        :param domain_name: Domain name used for name resolution by
            the DNS client, if 'dns_domain_list' is not configured
        :param domain_list: dict of DNS Domain list names to be used for
            address resolution, keyed by the resolution priority order
            Example:
                {
                    0: "hpe.com"
                    1: "arubanetworks.com"
                }
        :param domain_servers: dict of DNS Name servers to be used for address
            resolution, keyed by the resolution priority order
            Example:
                {
                    0: "4.4.4.10"
                    1: "4.4.4.12"
                }
        :param host_v4_address_mapping: dict of static host
            address configurations and the IPv4 address associated with them
            Example:
                {
                    "host1": "5.5.44.5"
                    "host2": "2.2.44.2"
                }
        :param host_v6_address_mapping: dict of static host
            address configurations and the IPv6 address associated with them
            Example:
                {
                    "host1": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
                }
        : return DNS object
        """
        if vrf is None:
            vrf = 'default'

        # Create Vrf object using Factory
        vrf_obj = self.vrf(vrf)

        if domain_list is None:
            domain_list = {}
        if domain_servers is None:
            domain_servers = {}
        if host_v4_address_mapping is None:
            host_v4_address_mapping = {}
        if host_v6_address_mapping is None:
            host_v6_address_mapping = {}

        # Ensure that all keys are integers
        domain_list = {
            int(k): v for k, v in domain_list.items()}
        domain_servers = {
            int(k): v for k, v in domain_servers.items()}

        # Create DNS object
        dns = Dns(self.session, vrf, domain_name, domain_list,
                  domain_servers, host_v4_address_mapping,
                  host_v6_address_mapping)

        # Apply object into Switch
        dns.apply()

        return dns

    def interface(self, name: str):
        """
        Create an Interface object.

        :param name: Alphanumeric name of Interface
        :return: Interface object
        """
        interface_obj = self.session.api_version.get_module(
            self.session, 'Interface',
            name)

        try:
            # Try to create, if object exists then get
            interface_obj.apply()

        except GenericOperationError:
            interface_obj.get()

        return interface_obj

    def ipv6(self, address: str, interface_name,
             address_type=None):
        """
        Create a Ipv6 object. If values differ from existing object, incoming
        changes will be applied

        :param address: Alphanumeric address of IPv6.
            Example:
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param interface_name: Alphanumeric name of the Interface parent
            of the IPv6 Address.
            A Interface object is also accepted
        :param address_type: Type of IPv6 address. Defaults to
            "global-unicast" if not specified.
        :return: Ipv6 object
        """
        if address_type is None:
            _type = "global-unicast"
        else:
            _type = address_type

        if isinstance(interface_name, str):
            # Make Interface into an object
            interface = self.session.api_version.get_module(
                self.session, 'Interface', interface_name)
            # Materialize interface to ensure its existence
            interface.get()

        ipv6_obj = self.session.api_version.get_module(
            self.session, 'Ipv6', address,
            parent_int=interface, type=_type,
            preferred_lifetime=604800,
            valid_lifetime=2592000,
            node_address=True,
            ra_prefix=True,
            route_tag=0)

        # Try to obtain data; if not, create
        try:
            ipv6_obj.get()
            # Configure variables in case something changes
            if address_type is not None:
                ipv6_obj.type = address_type
            ipv6_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            ipv6_obj.apply()

        return ipv6_obj

    def vlan(self, vlan_id: int, name=None, description=None,
             vlan_type=None, admin_conf_state="up"):
        """
        Create a Vlan object.

        :param vlan_id: Numeric ID for VLAN
        :param name: Alphanumeric name of VLAN, Defaults to "VLAN <ID>"
        :param description: Optional description to add to VLAN
        :param vlan_type: VLAN type. Defaults to "static" if not
            specified
        :param admin_conf_state: Optional administratively-configured state of
            VLAN. Only configurable for static VLANs. Defaults to "up" for
            static VLANs.
        :return: Vlan object
        """
        if name is None:
            name = "VLAN {}".format(str(vlan_id))

        if vlan_type is None:
            pvlan_type = "static"
        else:
            pvlan_type = vlan_type

        if pvlan_type == "static":
            # admin-configured state can only be set on static VLANs
            vlan_obj = self.session.api_version.get_module(
                self.session, 'Vlan', vlan_id,
                name=name, description=description,
                admin=admin_conf_state)
        else:
            vlan_obj = self.session.api_version.get_module(
                self.session, 'Vlan', vlan_id, name=name,
                description=description)

        # Try to obtain data; if not, create
        try:
            vlan_obj.get()
            # Configure variables in case something changes
            if name is not None:
                vlan_obj.name = name
            if description is not None:
                vlan_obj.description = description
            if admin_conf_state is not None and vlan_type == "static":
                vlan_obj.admin = admin_conf_state
            vlan_obj.apply()

        except Exception:
            # Create object inside switch
            vlan_obj.apply()

        return vlan_obj

    def vrf(self, name: str, route_distinguisher=None, vrf_type=None):
        """
        Create a Vrf object. If values differ from existing object, incoming
        changes will be applied
        :param name: VRF name
        :param route_distinguisher: Optional route distinguisher to add.
            Defaults to nothing if not specified.
        :param vrf_type: Optional VRF type. Defaults to "user" if not
            specified.
        :return: Vrf object
        """
        if vrf_type is None:
            _type = "user"
        else:
            _type = vrf_type

        if route_distinguisher is not None and _type != 'default':
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', name,
                rd=route_distinguisher, type=_type)
        else:
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', name, type=_type)

        # Try to obtain data; if not, create
        try:
            vrf_obj.get()
            # Configure variables in case something changes
            if route_distinguisher is not None:
                vrf_obj.rd = route_distinguisher
            # Apply changes wanted by user
            vrf_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            vrf_obj.apply()

        return vrf_obj

    def vsx(self, role=None, isl_port=None, keepalive_vrf=None,
            keepalive_peer=None, keepalive_src=None, vsx_mac=None,
            keepalive_port=None):
        """
        Create a Vsx object.  If values differ from existing object, incoming
        changes will be applied

        :param role: Alphanumeric role that the system will be in the VSX pair.
            The options are "primary" or "secondary"
        :param isl_port: Alphanumeric name of the interface that will function
            as the inter-switch link
            A Interface object is also accepted
        :param keepalive_vrf: Alphanumeric name of the VRF that the keepalive
            connection will reside on.
            A Vrf object is also accepted
        :param keepalive_peer: Alphanumeric IP address of the VSX Peer that
            will be reached as the keepalive connection.
            Example:
                '1.1.1.1'
        :param keepalive_src: Alphanumeric IP address on the switch that will
            function as the keepalive connection source.
            Example:
                '1.1.1.1'
        :param vsx_mac: Alphanumeric MAC address that will function as the VSX
            System MAC.
            Example:
                '01:02:03:04:05:06'
        :param keepalive_port: Numeric Keepalive UDP port. Defaults to 7678
        :return: Vsx object
        """
        if keepalive_port is None:
            _keepalive_port = 7678
        else:
            _keepalive_port = keepalive_port
        if keepalive_vrf is not None:
            if isinstance(keepalive_vrf, str):
                keepalive_vrf = self.session.api_version.get_module(
                    self.session, 'Vrf', keepalive_vrf)
                keepalive_vrf.get()

        if isl_port is not None:
            if isinstance(isl_port, str):
                isl_port = self.session.api_version.get_module(
                    self.session, 'Interface', isl_port)
                isl_port.get()
            # Check ISL Port routing
            if isl_port.routing:
                # Set routing to False
                isl_port.routing = False
                isl_port.apply()

        vsx_obj = self.session.api_version.get_module(
            self.session, 'Vsx', device_role=role,
            isl_port=isl_port, keepalive_peer_ip=keepalive_peer,
            keepalive_src_ip=keepalive_src, keepalive_vrf=keepalive_vrf,
            system_mac=vsx_mac, keepalive_udp_port=_keepalive_port)

        # Try to obtain data; if not, create
        try:
            vsx_obj.get()
            # Configure variables in case something changes
            if role is not None:
                vsx_obj.device_role = role
            if isl_port is not None:
                vsx_obj.isl_port = isl_port
            if keepalive_peer is not None:
                vsx_obj.keepalive_peer_ip = keepalive_peer
            if keepalive_src is not None:
                vsx_obj.keepalive_src_ip = keepalive_src
            if keepalive_vrf is not None:
                vsx_obj.keepalive_vrf = keepalive_vrf
            if vsx_mac is not None:
                vsx_obj.system_mac = vsx_mac
            if _keepalive_port is not None:
                vsx_obj.keepalive_udp_port = _keepalive_port
            # Apply changes
            vsx_obj.apply()

        except GenericOperationError:
            # Create object inside switch
            vsx_obj.apply()

        return vsx_obj

    def bgp_router_asn(self, vrf, asn: int, router_id=None):
        """
        Create a BgpRouter object as Autonomous System Number.
        If values differ from existing object, incoming
        changes will be applied

        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to.
            A Vrf object is also accepted
        :param asn: Integer that represents the Autonomous System Number
        :param router_id: Optional IPv4 address that functions as the
            BGP Router ID
        :return: BgpRouter object
        """
        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        bgp_router_obj = self.session.api_version.get_module(
            self.session, 'BgpRouter', asn, parent_vrf=vrf,
            router_id=router_id)

        # Try to obtain data; if not, create
        try:
            bgp_router_obj.get()
            # Change attributes
            if router_id is not None:
                bgp_router_obj.router_id = router_id
            # Apply changes
            bgp_router_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            bgp_router_obj.apply()

        return bgp_router_obj

    def bgp_router_vrf(self, vrf, asn: int, redistribute):
        """
        Create a BgpRouter object with a BGP VRF settings for the
        associated BGP ASN.
        If values differ from existing object, incoming
        changes will be applied

        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to.
            A Vrf object is also accepted
        :param asn: Integer that represents the Autonomous System Number
        :param redistribute: Alphanumeric to specify which
            types of routes that should be redistributed by BGP. The
            options are "ipv4-unicast" or "ipv6-unicast".
        :return: BgpRouter object
        """
        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        redistribute_data = {}

        if redistribute == 'ipv4-unicast':
            redistribute_data = {
                "ipv4-unicast": ["connected"]
            }
        elif redistribute == 'ipv6-unicast':
            redistribute_data = {
                "ipv6-unicast": ["connected"]
            }

        bgp_router_obj = self.session.api_version.get_module(
            self.session, 'BgpRouter', asn, parent_vrf=vrf,
            redistribute=redistribute_data)

        # Try to obtain data; if not, create
        try:
            bgp_router_obj.get()
            # Change attributes
            bgp_router_obj.redistribute = redistribute_data
            # Apply changes
            bgp_router_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            bgp_router_obj.apply()

        return bgp_router_obj

    def bgp_neighbor(self, vrf, bgp_router_asn, group_ip,
                     family_type=None, reflector=None,
                     send_community=None, local_interface=""):
        """
        Create a BgpNeighbor object.
        If values differ from existing object, incoming
        changes will be applied
        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to.
            A Vrf object is also accepted
        :param bgp_router_asn: Integer that represents the Autonomous System
            Number
        :param group_ip: IPv4 address or name of group of the neighbors that
            functions as the BGP Router link.
            Example:
               '1.1.1.1'
        :param family_type: Alphanumeric to specify what type of neighbor
            settings to configure. The options are 'l2vpn-evpn',
            'ipv4-unicast', or 'ipv6-unicast'. When setting to l2vpn-evpn,
            the neighbor configurations also will add
            route-reflector-client and send-community settings.
        :param reflector: Boolean value to determine whether this neighbor
            has route reflector enabled.  Default is False.
        :param send_community: Boolean value to determine whether this
            neighbor has send-community enabled.  Default is False.
        :param local_interface: Optional alphanumeric to specify which
        interface the neighbor will apply to.

        :return: BgpNeighbor object
        """
        if family_type is None:
            _family_type = "l2vpn-evpn"

        if _family_type not in ['l2vpn-evpn', 'ipv4-unicast', 'ipv6-unicast']:
            raise Exception("ERROR: family_type should be 'l2vpn-evpn',\
                            'ipv4-unicast', or 'ipv6-unicast'")

        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        if isinstance(bgp_router_asn, int):
            # Make BGP Router into an object
            bgp_router_obj = self.session.api_version.get_module(
                self.session, 'BgpRouter', bgp_router_asn, parent_vrf=vrf)

            # Materialize BGP Router to ensure its existence
            bgp_router_obj.get()
            # Set asn integer
            asn = bgp_router_asn
            # Set variable as an object
            bgp_router_asn = bgp_router_obj
        else:
            asn = bgp_router_asn.asn

        if local_interface != "":
            if isinstance(local_interface, str):
                local_interface = self.session.api_version.get_module(
                    self.session, 'Interface', local_interface)
                local_interface.get()

        # Set values needed
        activate = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False
        }

        next_hop_unchanged = {
            "l2vpn-evpn": False
        }

        route_reflector_client = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False
        }

        send_community_data = {
            "ipv4-unicast": "none",
            "ipv6-unicast": "none",
            "l2vpn-evpn": "none"
        }

        activate[_family_type] = True

        # Set incoming variables
        if send_community is None:
            _send_community = False
        else:
            _send_community = send_community
        if reflector is None:
            _reflector = False
        else:
            _reflector = reflector

        if _send_community:
            send_community_data[_family_type] = "both"

        if _reflector:
            route_reflector_client[_family_type] = reflector

        bgp_neighbor_obj = self.session.api_version.get_module(
            self.session, 'BgpNeighbor', group_ip,
            parent_bgp_router=bgp_router_asn,
            remote_as=asn, shutdown=False,
            local_interface=local_interface,
            activate=activate, next_hop_unchanged=next_hop_unchanged,
            route_reflector_client=route_reflector_client,
            send_community=send_community_data
        )

        # Try to obtain data; if not, create
        try:
            bgp_neighbor_obj.get()
            # Change attributes
            if local_interface != "":
                bgp_neighbor_obj.local_interface = local_interface
            if family_type is not None:
                bgp_neighbor_obj.activate = activate
            if send_community is not None:
                bgp_neighbor_obj.send_community = send_community_data
            if reflector is not None:
                bgp_neighbor_obj.route_reflector_client = \
                    route_reflector_client
            # Apply changes
            bgp_neighbor_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            bgp_neighbor_obj.apply()

        return bgp_neighbor_obj

    def ospf_router_id(self, vrf, ospf_id,
                       redistribute=None):
        """
        Create a OspfRouter object as OSPF ID.
        If values differ from existing object, incoming
        changes will be applied

        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to
            A Vrf object is also accepted
        :param ospf_id: OSPF process ID between numbers 1-63
        :param redistribute: List of types of redistribution methods for
            the OSPF Process, with the options being "bgp",
            "connected", and "static"
        :return: OspfRouter object
        """
        if redistribute is None:
            _redistribute = ["connected", "static"]
        else:
            _redistribute = redistribute

        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        ospf_router_obj = self.session.api_version.get_module(
            self.session, 'OspfRouter', ospf_id, parent_vrf=vrf,
            redistribute=_redistribute)

        # Try to obtain data; if not, create
        try:
            ospf_router_obj.get()
            # Change attributes
            if redistribute is not None:
                ospf_router_obj.redistribute = redistribute
            # Apply changes
            ospf_router_obj.apply()

        except GenericOperationError:
            # Create object inside switch
            ospf_router_obj.apply()

        return ospf_router_obj

    def ospf_router_area(self, vrf, ospf_id, area_id, area_type=None):
        """
        Create an OspfArea object.
        If values differ from existing object, incoming
        changes will be applied

        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to
        :param ospf_id: OSPF process ID between numbers 1-63
        :param area_id: Unique identifier as a string in the form of x.x.x.x
        :param area_type: Alphanumeric defining how the external routing and
            summary LSAs for this area will be handled.
            Options are "default","nssa","nssa_no_summary","stub",
            "stub_no_summary"

        :return: OspfArea object
        """
        if area_type is None:
            _area_type = 'default'
        else:
            _area_type = area_type

        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        if isinstance(ospf_id, int):
            # Make OSPF Router into an object
            ospf_router_obj = self.session.api_version.get_module(
                self.session, 'OspfRouter', ospf_id, parent_vrf=vrf)

            # Materialize OSPF Router to ensure its existence
            ospf_router_obj.get()
            # Set variable as an object
            ospf_router = ospf_router_obj
        else:
            # Set ospf_router variable as OspfRouter object
            ospf_router = ospf_id

        # Create OspfArea object
        ospf_area_obj = self.session.api_version.get_module(
            self.session, 'OspfArea', area_id, parent_ospf_router=ospf_router,
            area_type=_area_type, ipsec_ah={}, ipsec_esp={})

        # Try to obtain data; if not, create
        try:
            ospf_area_obj.get()
            # Change attributes
            if area_type is not None:
                ospf_area_obj.area_type = area_type
            # Apply changes
            ospf_area_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            ospf_area_obj.apply()

        return ospf_area_obj

    def ospf_interface(self, vrf, ospf_id, area_id, interface_name):
        """
        Create a OspfInterface object.

        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to.
            A Vrf object is also accepted
        :param ospf_id: OSPF process ID between numbers 1-63
            A OSPF Router is accepted
        :param area_id: Unique identifier as a string in the form of x.x.x.x
        :param interface_name: Alphanumeric name of the interface that will be
            attached to the OSPF area
        :return: OspfInterface object
        """

        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        if isinstance(ospf_id, int):
            # Make Ospf ID into an object
            ospf_router_obj = self.session.api_version.get_module(
                self.session, 'OspfRouter', ospf_id, parent_vrf=vrf)

            # Materialize OSPF Router to ensure its existence
            ospf_router_obj.get()

            # Set variable as an object
            ospf_router = ospf_router_obj
        else:
            ospf_router = ospf_id

        if isinstance(area_id, str):
            # Create OspfArea object
            ospf_area_obj = self.session.api_version.get_module(
                self.session, 'OspfArea', area_id,
                parent_ospf_router=ospf_router)
            # Materialize it
            ospf_area_obj.get()

            # Set variable as an object
            area = ospf_area_obj
        else:
            area = area_id

        # Make Ospf ID into an object
        ospf_interface = self.session.api_version.get_module(
            self.session, 'OspfInterface', interface_name,
            parent_ospf_area=area)

        # Try to obtain data; if not, create
        try:
            ospf_interface.get()
        except GenericOperationError:
            # Create object inside switch
            ospf_interface.apply()

        return ospf_interface

    def vlan_and_svi(self, vlan_id, vlan_name, vlan_int_name,
                     vlan_desc=None, ipv4=None, vrf_name="default",
                     vlan_port_desc=None):
        """
        Create VLAN and Interface objects to represent VLAN and SVI, respectively.

        :param vlan_id: Numeric ID of VLAN
        :param vlan_name: Alphanumeric name of VLAN
        :param vlan_int_name: Alphanumeric name for the VLAN interface
        :param vlan_desc: Optional description to add to VLAN
        :param ipv4: Optional IPv4 address to assign to the interface.Defaults
            to nothing if not specified..
            Example:
                '1.1.1.1'
        :param vrf_name: VRF to attach the SVI to. Defaults to "default" i
             not specified
        :param vlan_port_desc: Optional description for the interface.
            Defaults to nothing if not specified.
        :return: A tuple with a Vlan object and a Interface SVI object
        """
        # Create Vlan object
        vlan_obj = self.vlan(vlan_id, vlan_name, vlan_desc)

        # Create Interface Object
        interface_obj = self.interface(vlan_int_name)
        # Set Interface as an SVI
        interface_obj.configure_svi(vlan_id, ipv4, vrf_name, vlan_port_desc)

        return vlan_obj, interface_obj

    def dhcp_relay(self, vrf, port):
        """
        Create a DhcpRelay object.

        :param vrf: Alphanumeric name of VRF
        :param port: Alphanumeric name of Port

        :return: DhcpRelay object
        """
        port_obj = self.session.api_version.get_module(
            self.session, 'Interface',
            port)
        vrf_obj = self.session.api_version.get_module(
            self.session, 'Vrf', vrf)

        dhcp_relay = self.session.api_version.get_module(
            self.session, 'DhcpRelay', index_id=vrf_obj, port=port_obj)

        # Try to obtain data; if not, create
        try:
            dhcp_relay.get()
        except GenericOperationError:
            # Create object inside switch
            dhcp_relay.apply()

        return dhcp_relay

    def acl(self, list_name, list_type):
        """
        Create an Acl object.

        :param list_name: Alphanumeric name of ACL
        :param list_type: Alphanumeric type of ACL.
            Type should be one of "ipv4," "ipv6," or "mac"

        :return: Acl object
        """

        acl = self.session.api_version.get_module(
            self.session, 'ACL', index_id=list_name, list_type=list_type)

        # Try to obtain data; if not, create
        try:
            acl.get()
        except GenericOperationError:
            # Create object inside switch
            acl.apply()

        return acl

    def acl_entry(self, list_name, list_type, sequence_num, action='permit',
                  count=None, protocol=None, src_ip=None, dst_ip=None,
                  dst_l4_port_min=None, dst_l4_port_max=None, src_mac=None,
                  dst_mac=None, ethertype=None):
        """
        Create an AclEntry object

        :param list_name: Alphanumeric name of the ACL
        :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
        :param sequence_num: Integer number of the sequence
        :param action: Action should be either "permit" or "deny"
        :param count: Optional boolean flag that when true, will make entry
            increment hit count for matched packets
        :param protocol: Optional integer IP protocol number
        :param src_ip: Optional source IP address. Both IPv4 and IPv6 are supported.
            Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_ip: Optional destination IP address. Both IPv4 and IPv6 are supported.
            Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_l4_port_min: Optional minimum L4 port number in range; used
            in conjunction with dst_l4_port_max.
        :param dst_l4_port_max: Optional maximum L4 port number in range; used
            in conjunction with dst_l4_port_min.
        :param src_mac: Optional source MAC address
            Example:
                '01:02:03:04:05:06'
        :param dst_mac: Optional destination MAC address
            Example:
                '01:02:03:04:05:06'
        :param ethertype: Optional integer EtherType number

        :return acl_entry: A AclEntry object

        """
        # Create Acl object
        acl = self.session.api_version.get_module(
            self.session, 'ACL', index_id=list_name, list_type=list_type)

        # Get ACL data
        acl.get()

        # Create ACL Entry
        acl_entry_obj = self.session.api_version.get_module(
            self.session, 'AclEntry', index_id=sequence_num, parent_acl=acl,
            action=action, count=count, protocol=protocol, src_ip=src_ip,
            dst_ip=dst_ip, dst_l4_port_min=dst_l4_port_min,
            dst_l4_port_max=dst_l4_port_max, src_mac=src_mac,
            dst_mac=dst_mac, ethertype=ethertype)

        # Try to obtain data; if not, create
        try:
            acl_entry_obj.get()
            # Change attributes
            if dst_l4_port_min is not None:
                acl_entry_obj.dst_l4_port_min = dst_l4_port_min
            if dst_l4_port_max is not None:
                acl_entry_obj.dst_l4_port_max = dst_l4_port_max
            if src_mac is not None:
                acl_entry_obj.src_mac = src_mac
            if dst_mac is not None:
                acl_entry_obj.dst_mac = dst_mac
            if ethertype is not None:
                acl_entry_obj.ethertype = ethertype
            # Apply changes
            acl_entry_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            acl_entry_obj.apply()

        return acl_entry_obj

    def vrf_address_family(self, vrf, address_family='ipv4_unicast'):
        """
        Create a VrfAddressFamily object with a VRF

        :param vrf: Alphanumeric name of the VRF the Family Address belongs to.
            A Vrf object is also accepted
        :param address_family: Alphanumeric type of the Address Family.
            The options are 'ipv4_unicast' and 'ipv6_unicast'.
            The default value is set to 'ipv4_unicast'.
        :return: VRF_Address_Family object
        """
        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        vrf_address_fam_obj = self.session.api_version.get_module(
            self.session, 'VrfAddressFamily', address_family,
            parent_vrf=vrf)

        # Try to obtain data; if not, create
        try:
            vrf_address_fam_obj.get()
        except GenericOperationError:
            # Create object inside switch
            vrf_address_fam_obj.apply()

        return vrf_address_fam_obj

    def aggregate_address(self, vrf, bgp_router_asn, family_type,
                          ip_prefix):
        """
        Create an AggregateAddress object.
        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to.
            A Vrf object is also accepted
        :param bgp_router_asn: Integer that represents the Autonomous System
            Number
        :param family_type: Address Family type for the Aggregate Address.
            Either 'ipv4-unicast', 'ipv6-unicast'
        :param ip_prefix: IP address and mask used to key Aggregate Address.
            Example:
                '1.1.1.1/24'

        :return: AggregateAddress object
        """

        if family_type not in ['ipv4-unicast', 'ipv6-unicast']:
            raise Exception("ERROR: family_type should be\
                            'ipv4-unicast', or 'ipv6-unicast'")

        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        if isinstance(bgp_router_asn, int):
            # Make BGP Router into an object
            bgp_router_obj = self.session.api_version.get_module(
                self.session, 'BgpRouter', bgp_router_asn, parent_vrf=vrf)

            # Materialize interface to ensure its existence
            bgp_router_obj.get()
            # Set variable as an object
            bgp_router_asn = bgp_router_obj

        aggregate_add_obj = self.session.api_version.get_module(
            self.session, 'AggregateAddress',
            family_type,
            ip_prefix=ip_prefix,
            parent_bgp_router=bgp_router_asn
        )

        # Try to obtain data; if not, create
        try:
            aggregate_add_obj.get()
        except GenericOperationError:
            # Create object inside switch
            aggregate_add_obj.apply()

        return aggregate_add_obj

    def static_route(self, vrf, destination_address_prefix):
        """
        Create a StaticRoute object with a VRF.

        :param vrf: Name of the VRF on which the static route
            is to be configured. Defaults to default vrf
            A Vrf object is also accepted
        :param destination_address_prefix: String IPv4 or IPv6 destination
            prefix and mask in the address/mask format.
            Example:
                '1.1.1.1'
                or
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :return: StaticRoute object
        """

        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj

        static_route_obj = self.session.api_version.get_module(
            self.session, 'StaticRoute', destination_address_prefix,
            parent_vrf=vrf)

        # Try to obtain data; if not, create
        try:
            static_route_obj.get()
        except GenericOperationError:
            # Create object inside switch
            static_route_obj.apply()

        return static_route_obj

    def static_nexthop(self, vrf, destination_address_prefix,
                       next_hop_ip_address=None,
                       nexthop_type=None,
                       distance=None,
                       next_hop_interface=None,
                       bfd_enable=None):
        """
        Create a Static Nexthop, with a VRF and a Destination Address
        related to a Static Route.

        :param vrf: Name of the VRF on which the static route
            is to be configured. Defaults to default vrf
            A Vrf object is also accepted
        :param destination_address_prefix: String IPv4 or IPv6 destination
            prefix and mask in the address/mask format
            A StaticRoute object is also accepted.
            Example:
                '1.1.1.1'
                or
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param next_hop_ip_address: The IPv4 address or the IPv6 address of
            next hop.
            Example:
                '1.1.1.1'
                or
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param nexthop_type: Specifies whether the static route is a forward,
            blackhole or reject route.
        :param distance: Administrative distance to be used for the next
        hop in the static route instead of default value.
        :param next_hop_interface: The interface through which the next hop
            can be reached.
        :param bfd_enable: Boolean to enable BFD
        :return: StaticNexthop object
        """

        if isinstance(vrf, str):
            # Make VRF into an object
            vrf_obj = self.session.api_version.get_module(
                self.session, 'Vrf', vrf)
            # Materialize VRF to ensure its existence
            vrf_obj.get()
            vrf = vrf_obj
        static_route = destination_address_prefix
        if isinstance(destination_address_prefix, str):
            # Make a Static Route Object
            static_route_obj = self.session.api_version.get_module(
                self.session, 'StaticRoute', destination_address_prefix,
                parent_vrf=vrf)
            # Materialize Object to ensure its existence
            static_route_obj.get()
            static_route = static_route_obj

        if distance is None:
            distance = 1
        # Set variable
        next_hop_interface_obj = None
        if next_hop_interface is not None:
            next_hop_interface_obj = self.session.api_version.get_module(
                self.session, 'Interface',
                next_hop_interface)
        if nexthop_type is None:
            nexthop_type = 'forward'

        if nexthop_type == 'forward':
            bfd_enable = False

        static_nexthop_obj = self.session.api_version.get_module(
            self.session, 'StaticNexthop', 0,
            parent_static_route=static_route,
        )

        # Try to obtain data; if not, create
        try:
            static_nexthop_obj.get()
            # Delete previous static nexthop
            static_nexthop_obj.delete()
        except GenericOperationError:
            # Catch error
            pass

        finally:
            static_nexthop_obj = self.session.api_version.get_module(
                self.session, 'StaticNexthop',
                0,
                parent_static_route=static_route_obj,
                ip_address=next_hop_ip_address,
                distance=distance,
                port=next_hop_interface_obj,
                type=nexthop_type,
                bfd_enable=bfd_enable
            )
            # Create object inside switch
            static_nexthop_obj.apply()

        return static_nexthop_obj

    def poe_interface(self, interface):
        """
        Create a PoE Interface object with associated settings

        :param Interface: Alphanumeric name of the Interface the PoE_Interface belongs to.
            An Interface object is also accepted
        :return: PoE Interface object
        """
        if isinstance(interface, str):
            # Make Interface into an object
            interface_obj = self.session.api_version.get_module(
                self.session, 'Interface', interface)
            # Materialize Interface to ensure its existence
            interface_obj.get()
            interface = interface_obj

        poe_interface_obj = self.session.api_version.get_module(
            self.session, 'PoEInterface', interface)

        poe_interface_obj.get()

        return poe_interface_obj
