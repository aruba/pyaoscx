# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.configuration import Configuration
from pyaoscx.dns import Dns


class Singleton(type):
    """
    Metaclass to turn classes into a Singleton.
    """

    __instance = None

    def __call__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super(Singleton, cls).__call__(*args, **kwargs)
        return cls.__instance


class PyaoscxFactory(metaclass=Singleton):
    """
    Provide a Factory class to instantiate all pyaoscx Modules through specific
        methods. This class is superseded by the Device class, use the Device
        class instead of this one.
    Using the API Version given by the Session.
    """

    def __init__(self, session):
        self.session = session

    def configuration(self):
        """
        Create a Configuration class, to obtain device configuration and
            perform other actions such as backup_config.
        :return: Configuration object.
        """
        config = Configuration(self.session)
        # Get full configuration
        config.get()
        return config

    def dns(
        self,
        vrf=None,
        domain_name=None,
        domain_list=None,
        domain_servers=None,
        host_v4_address_mapping=None,
        host_v6_address_mapping=None,
    ):
        """
        Create a DNS class, to configure a DNS inside a given VRF.
        :param domain_name: Domain name used for name resolution by the DNS
            client, if 'dns_domain_list' is not configured.
        :param domain_list: dict of DNS Domain list names to be used for
            address resolution, keyed by the resolution priority order.
            Example:
                {
                    0: "hpe.com"
                    1: "arubanetworks.com"
                }
        :param domain_servers: dict of DNS Name servers to be used for address
            resolution, keyed by the resolution priority order. Example:
                {
                    0: "4.4.4.10"
                    1: "4.4.4.12"
                }
        :param host_v4_address_mapping: dict of static host address
            configurations and the IPv4 address associated with them. Example:
                {
                    "host1": "5.5.44.5"
                    "host2": "2.2.44.2"
                }
        :param host_v6_address_mapping: dict of static host address
            configurations and the IPv6 address associated with them. Example:
                {
                    "host1": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
                }
        : return DNS object.
        """
        if vrf is None:
            vrf = "default"

        if domain_list is None:
            domain_list = {}
        if domain_servers is None:
            domain_servers = {}
        if host_v4_address_mapping is None:
            host_v4_address_mapping = {}
        if host_v6_address_mapping is None:
            host_v6_address_mapping = {}

        # Ensure that all keys are integers
        domain_list = {int(k): v for k, v in domain_list.items()}
        domain_servers = {int(k): v for k, v in domain_servers.items()}

        # Create DNS object
        dns = Dns(
            self.session,
            vrf,
            domain_name,
            domain_list,
            domain_servers,
            host_v4_address_mapping,
            host_v6_address_mapping,
        )

        # Apply object into Switch
        dns.apply()

        return dns

    def interface(self, name):
        """
        Create an Interface object.
        :param name: Alphanumeric name of Interface.
        :return: Interface object.
        """
        interface_obj = self.session.api.get_module(
            self.session, "Interface", name
        )
        try:
            # Try to create the interface
            interface_obj.create()

        except GenericOperationError:
            # The GenericOperationError is risen if the POST request was
            # executed correctly, but the switch didn't accept it. This means
            # that the interface already exists.
            interface_obj.get()

        return interface_obj

    def ipv6(self, address, interface_name, address_type=None):
        """
        Create a Ipv6 object. If values differ from existing object, incoming
            changes will be applied.
        :param address: Alphanumeric address of IPv6. Example:
            '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param interface_name: Alphanumeric name of the Interface parent of the
            IPv6 Address. A Interface object is also accepted.
        :param address_type: Type of IPv6 address. Defaults to "global-unicast"
            if not specified..
        :return: Ipv6 object.
        """
        if address_type is None:
            _type = "global-unicast"
        else:
            _type = address_type

        if isinstance(interface_name, str):
            # Make Interface into an object
            interface = self.session.api.get_module(
                self.session, "Interface", interface_name
            )
            # Materialize interface to ensure its existence
            interface.get()

        ipv6_obj = self.session.api.get_module(
            self.session,
            "Ipv6",
            address,
            parent_int=interface,
            type=_type,
            preferred_lifetime=604800,
            valid_lifetime=2592000,
            node_address=True,
            ra_prefix=True,
            route_tag=0,
        )

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

    def vlan(
        self,
        vlan_id,
        name=None,
        description=None,
        vlan_type=None,
        admin_conf_state="up",
    ):
        """
        Create a Vlan object.
        :param vlan_id: Numeric ID for VLAN.
        :param name: Alphanumeric name of VLAN, Defaults to "VLAN <ID>".
        :param description: Optional description to add to VLAN.
        :param vlan_type: VLAN type. Defaults to "static" if not specified.
        :param admin_conf_state: Optional administratively-configured state of
            VLAN. Only configurable for static VLANs. Defaults to "up" for
            static VLANs.
        :return: Vlan object.
        """
        if name is None:
            name = "VLAN {0}".format(str(vlan_id))

        if vlan_type is None:
            pvlan_type = "static"
        else:
            pvlan_type = vlan_type

        if pvlan_type == "static":
            # admin-configured state can only be set on static VLANs
            vlan_obj = self.session.api.get_module(
                self.session,
                "Vlan",
                vlan_id,
                name=name,
                description=description,
                admin=admin_conf_state,
            )
        else:
            vlan_obj = self.session.api.get_module(
                self.session,
                "Vlan",
                vlan_id,
                name=name,
                description=description,
            )

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

    def __get_vrf_from_switch(self, name):
        """
        Get VRF from switch, this avoids making changes to the VRF object. Note
            the __double_leading_underscore that signifies that this is meant
            to be used only inside this module.
        :param name: VRF name.
        :return: Materialized Vrf object.
        """
        vrf = self.session.api.get_module(self.session, "Vrf", name)
        vrf.get()
        return vrf

    def vrf(self, name, route_distinguisher=None, vrf_type=None):
        """
        Create a Vrf object. If values differ from existing object, incoming
            changes will be applied.
        :param name: VRF name.
        :param route_distinguisher: Optional route distinguisher to add.
            Defaults to nothing if not specified.
        :param vrf_type: Optional VRF type. Defaults to "user" if not
            specified.
        :return: Vrf object.
        """
        if vrf_type is None:
            _type = "user"
        else:
            _type = vrf_type

        if route_distinguisher is not None and _type != "default":
            vrf_obj = self.session.api.get_module(
                self.session, "Vrf", name, rd=route_distinguisher, type=_type
            )
        else:
            vrf_obj = self.session.api.get_module(
                self.session, "Vrf", name, type=_type
            )

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

    def vsx(self, **kwargs):
        """
        Create a Vsx object.  If values differ from existing object, incoming
            changes will be applied.
        :return: A Vsx object.
        :rtype: Vsx.
        """
        keepalive_vrf = kwargs.get("keepalive_vrf")
        if keepalive_vrf:
            if isinstance(keepalive_vrf, str):
                keepalive_vrf = self.__get_vrf_from_switch(keepalive_vrf)
            kwargs["keepalive_vrf"] = keepalive_vrf.get_info_format()
        software_update_vrf = kwargs.get("software_update_vrf")
        if software_update_vrf:
            if isinstance(software_update_vrf, str):
                software_update_vrf = self.__get_vrf_from_switch(
                    software_update_vrf
                )
            kwargs[
                "software_update_vrf"
            ] = software_update_vrf.get_info_format()
        isl_port = kwargs.get("isl_port")
        if isl_port:
            if isinstance(isl_port, str):
                isl_port = self.session.api.get_module(
                    self.session, "Interface", isl_port
                )
                isl_port.get()
            # Check ISL Port routing
            if isl_port.routing:
                # Set routing to False
                isl_port.routing = False
                isl_port.apply()
            kwargs["isl_port"] = isl_port.get_info_format()
        vsx_obj = self.session.api.get_module(self.session, "Vsx", **kwargs)
        # Try to obtain data; if not, create
        try:
            vsx_obj.get()
            # get() overwrites object's attributes with the switch config, so
            # set them here after object is materialized, to keep the new ones
            for key, value in kwargs.items():
                setattr(vsx_obj, key, value)
        except GenericOperationError:
            pass
        finally:
            # Create object inside switch
            vsx_obj.apply()
        return vsx_obj

    def bgp_router_asn(self, vrf, asn, router_id=None):
        """
        Create a BgpRouter object as Autonomous System Number. If values differ
            from existing object, incoming changes will be applied.
        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to. A Vrf
            object is also accepted.
        :param asn: Integer that represents the Autonomous System Number.
        :param router_id: Optional IPv4 address that functions as the BGP
            Router ID.
        :return: BgpRouter object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)

        bgp_router_obj = self.session.api.get_module(
            self.session, "BgpRouter", asn, parent_vrf=vrf, router_id=router_id
        )

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

    def bgp_router_vrf(self, vrf, asn, redistribute):
        """
        Create a BgpRouter object with a BGP VRF settings for the associated
            BGP ASN. If values differ from existing object, incoming changes
            will be applied.
        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to. A Vrf
            object is also accepted.
        :param asn: Integer that represents the Autonomous System Number.
        :param redistribute: Alphanumeric to specify which types of routes that
            should be redistributed by BGP. The options are "ipv4-unicast" or
            "ipv6-unicast".
        :return: BgpRouter object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)

        redistribute_data = {}

        if redistribute == "ipv4-unicast":
            redistribute_data = {"ipv4-unicast": ["connected"]}
        elif redistribute == "ipv6-unicast":
            redistribute_data = {"ipv6-unicast": ["connected"]}

        bgp_router_obj = self.session.api.get_module(
            self.session,
            "BgpRouter",
            asn,
            parent_vrf=vrf,
            redistribute=redistribute_data,
        )

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

    def bgp_neighbor(
        self,
        vrf,
        bgp_router_asn,
        group_ip,
        family_type=None,
        reflector=None,
        send_community=None,
        local_interface="",
    ):
        """
        Create a BgpNeighbor object. If values differ from existing object,
            incoming changes will be applied.
        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to.
            A Vrf object is also accepted.
        :param bgp_router_asn: Integer that represents the Autonomous System
            Number.
        :param group_ip: IPv4 address or name of group of the neighbors that
            functions as the BGP Router link. Example: '1.1.1.1'
        :param family_type: Alphanumeric to specify what type of neighbor
            settings to configure. The options are 'l2vpn-evpn',
            'ipv4-unicast', or 'ipv6-unicast'. When setting to l2vpn-evpn,
            the neighbor configurations also will add route-reflector-client
            and send-community settings.
        :param reflector: Boolean value to determine whether this neighbor
            has route reflector enabled. Default is False.
        :param send_community: Boolean value to determine whether this neighbor
            has send-community enabled. Default is False.
        :param local_interface: Optional alphanumeric to specify which
            interface the neighbor will apply to.
        :return: BgpNeighbor object.
        """
        if family_type is None:
            _family_type = "l2vpn-evpn"

        _valid_family_types = ["l2vpn-evpn", "ipv4-unicast", "ipv6-unicast"]
        if _family_type not in _valid_family_types:
            raise Exception(
                "ERROR: family_type must be one of: {0}".format(
                    _valid_family_types
                )
            )

        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)

        if isinstance(bgp_router_asn, int):
            # Make BGP Router into an object
            bgp_router_obj = self.session.api.get_module(
                self.session, "BgpRouter", bgp_router_asn, parent_vrf=vrf
            )

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
                local_interface = self.session.api.get_module(
                    self.session, "Interface", local_interface
                )
                local_interface.get()

        # Set values needed
        activate = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False,
        }

        next_hop_unchanged = {"l2vpn-evpn": False}

        route_reflector_client = {
            "ipv4-unicast": False,
            "ipv6-unicast": False,
            "l2vpn-evpn": False,
        }

        send_community_data = {
            "ipv4-unicast": "none",
            "ipv6-unicast": "none",
            "l2vpn-evpn": "none",
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

        bgp_neighbor_obj = self.session.api.get_module(
            self.session,
            "BgpNeighbor",
            group_ip,
            parent_bgp_router=bgp_router_asn,
            remote_as=asn,
            shutdown=False,
            local_interface=local_interface,
            activate=activate,
            next_hop_unchanged=next_hop_unchanged,
            route_reflector_client=route_reflector_client,
            send_community=send_community_data,
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
                bgp_neighbor_obj.route_reflector_client = (
                    route_reflector_client
                )
            # Apply changes
            bgp_neighbor_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            bgp_neighbor_obj.apply()

        return bgp_neighbor_obj

    def ospf_router(self, vrf, ospf_id, **kwargs):
        """
        Create OspfRouter object. If values differ from existing object,
            incoming changes will be applied.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to A Vrf
            object is also accepted.
        :param ospf_id: OSPF process ID between numbers 1-63.
        :param redistribute: List of types of redistribution methods for the
            OSPF Process, with the options being "bgp", "connected", and
            "static".
        :return: OspfRouter object.
        """
        if "redistribute" not in kwargs:
            kwargs["redistribute"] = ["connected", "static"]
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        ospf_router_obj = self.session.api.get_module(
            self.session, "OspfRouter", ospf_id, parent_vrf=vrf, **kwargs
        )
        # Try to obtain data; if not, create
        try:
            ospf_router_obj.get()
            # get() overwrites object's attributes with the switch config, so
            # set them here after object is materialized, to keep the new ones
            utils.set_config_attrs(ospf_router_obj, kwargs)
            ospf_router_obj.apply()
        except GenericOperationError:
            ospf_router_obj.create()
        return ospf_router_obj

    def ospfv3_router(self, vrf, ospfv3_id, **kwargs):
        """
        Create Ospfv3Router object. If values differ from existing object,
            incoming changes will be applied.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to.
            A Vrf object is also accepted.
        :param ospfv3_id: OSPF process ID between numbers 1-63.
        :param redistribute: List of types of redistribution methods for the
        OSPF Process, with the options being "bgp", "connected",
        "local_loopback", "rip", and "static".
        :return: Ospfv3Router object.
        """
        if "redistribute" not in kwargs:
            kwargs["redistribute"] = ["connected", "static"]
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        ospfv3_router_obj = self.session.api.get_module(
            self.session, "Ospfv3Router", ospfv3_id, parent_vrf=vrf, **kwargs
        )
        # Try to obtain data; if not, create
        try:
            ospfv3_router_obj.get()
            # get() overwrites object's attributes with the switch config, so
            # set them here after object is materialized, to keep the new ones
            utils.set_config_attrs(ospfv3_router_obj, kwargs)
            ospfv3_router_obj.apply()
        except GenericOperationError:
            ospfv3_router_obj.create()
        return ospfv3_router_obj

    def ospf_router_area(self, vrf, ospf_router, area_id, **kwargs):
        """
        Create an OspfArea object. If values differ from existing object,
            incoming changes will be applied.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to.
        :param ospf_router: OSPF process ID in [1, 63], an OspfRouter, or
            Ospfv3Router object is also accepted.
        :param area_id: Unique identifier as a string in the form of x.x.x.x.
        :param area_type: Alphanumeric defining how the external routing and
            summary LSAs for this area will be handled. Options are "default",
            "nssa", "nssa_no_summary", "stub", "stub_no_summary". If no value
            is passed, "default" is used.
        :return: OspfArea object.
        """
        if "area_type" not in kwargs:
            kwargs["area_type"] = "default"
        if "ipsec_ah" not in kwargs:
            kwargs["ipsec_ah"] = {}
        if "ipsec_esp" not in kwargs:
            kwargs["ipsec_esp"] = {}
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        router = ospf_router
        if isinstance(router, int):
            # Make OSPF Router into an object
            ospf_router_obj = self.session.api.get_module(
                self.session, "OspfRouter", ospf_router, parent_vrf=vrf
            )
            # Materialize OSPF Router to ensure its existence
            ospf_router_obj.get()
            # Set variable as an object
            router = ospf_router_obj
        # Create OspfArea object
        ospf_area_obj = self.session.api.get_module(
            self.session,
            "OspfArea",
            area_id,
            parent_ospf_router=router,
            **kwargs
        )
        # Try to obtain data; if not, create
        try:
            ospf_area_obj.get()
            # get() overwrites object's attributes with the switch config, so
            # set them here after object is materialized, to keep the new ones
            utils.set_config_attrs(ospf_area_obj, kwargs)
            ospf_area_obj.apply()
        except GenericOperationError:
            ospf_area_obj.create()
        return ospf_area_obj

    def __get_ospf_router(self, ospf_id, vrf):
        """
        Get OSPF Router object from switch, this avoids making changes to it.
            Note the __double_leading_underscore that signifies that this is
            meant to be used only inside this module.
        :param ospf_id: OSPF process ID in [1,63].
        :param vrf: Vrf (object).
        :return: Materialized OspfRouter (object).
        """
        ospf_router_obj = self.session.api.get_module(
            self.session, "OspfRouter", ospf_id, parent_vrf=vrf
        )
        ospf_router_obj.get()
        return ospf_router_obj

    def __get_ospfv3_router(self, ospfv3_id, vrf):
        """
        Get OSPFv3 Router object from switch, this avoids making changes to it.
            Note the __double_leading_underscore that signifies that this is
            meant to be used only inside this module.
        :param ospfv3_id: OSPFv3 process ID in [1,63].
        :param vrf: Vrf (object).
        :return: Materialized Ospfv3Router (object).
        """
        ospfv3_router_obj = self.session.api.get_module(
            self.session, "Ospfv3Router", ospfv3_id, parent_vrf=vrf
        )
        ospfv3_router_obj.get()
        return ospfv3_router_obj

    def __get_ospf_area(self, area_id, ospf_router):
        """
        Get OSPFv3 Area object from switch, this avoids making changes to it.
            Note the __double_leading_underscore that signifies that this is
            meant to be used only inside this module.
        :param area_id: Unique identifier as a string in the form of x.x.x.x.
        :param ospf_router: OspfRouter (object) or Ospfv3Router (object).
        :return: Materialized Ospfv3Router (object).
        """
        ospf_area_obj = self.session.api.get_module(
            self.session, "OspfArea", area_id, parent_ospf_router=ospf_router
        )
        ospf_area_obj.get()
        return ospf_area_obj

    def ospfv3_router_area(self, vrf, ospfv3_id, area_id, **kwargs):
        """
        Create OspfArea object. If values differ from existing object, incoming
            changes will be applied.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to.
        :param ospfv3_id: OSPFv3 process ID in [1,63], an Ospfv3Router object
            is also accepted.
        :param area_id: Unique identifier as a string in the form of x.x.x.x.
        :param area_type: Alphanumeric defining how the external routing and
            summary LSAs for this area will be handled. Options are "default",
            "nssa", "nssa_no_summary", "stub", "stub_no_summary" if no value
            is passed, "default" is used.
        :return: OspfArea object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        ospfv3_router = ospfv3_id
        if isinstance(ospfv3_id, int):
            ospfv3_router = self.__get_ospfv3_router(ospfv3_id, vrf)
        return self.ospf_router_area(vrf, ospfv3_router, area_id, **kwargs)

    def ospf_interface(self, vrf, ospf_id, area_id, interface_name, **kwargs):
        """
        Create a OspfInterface object.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to. A Vrf
            object is also accepted.
        :param ospf_id: OSPF process ID between numbers 1-63. A OSPF Router is
            accepted.
        :param area_id: Unique identifier as a string in the form of x.x.x.x.
        :param interface_name: Alphanumeric name of the interface that will be
            attached to the OSPF area.
        :return: OspfInterface object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        ospf_router = ospf_id
        if isinstance(ospf_id, int):
            ospf_router = self.__get_ospf_router(ospf_id, vrf)
        area = area_id
        if isinstance(area_id, str):
            area = self.__get_ospf_area(area_id, ospf_router)
        # Make Ospf ID into an object
        ospf_interface = self.session.api.get_module(
            self.session,
            "OspfInterface",
            interface_name,
            parent_ospf_area=area,
            **kwargs
        )
        # Try to obtain data; if not, create
        try:
            ospf_interface.get()
        except GenericOperationError:
            # Create object inside switch
            ospf_interface.apply()

        return ospf_interface

    def ospfv3_interface(
        self, vrf, ospf_id, area_id, interface_name, **kwargs
    ):
        """
        Create a OspfInterface object.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to. A Vrf
            object is also accepted.
        :param ospfv3_id: OSPFv3 process ID between numbers 1-63. An OSPFv3
            Router is accepted.
        :param area_id: Unique identifier as a string in the form of x.x.x.x.
        :param interface_name: Alphanumeric name of the interface that will be
            attached to the OSPF area.
        :return: OspfInterface object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        ospf_router = ospf_id
        if isinstance(ospf_id, int):
            ospf_router = self.__get_ospfv3_router(ospf_id, vrf)
        return self.ospf_interface(
            vrf, ospf_router, area_id, interface_name, **kwargs
        )

    def ospf_vlink(self, vrf, ospf_router, area_id, peer_router, **kwargs):
        """
        Create a OspfVlink object. Defaults to using OspfRouter, when providing
            the OSPF process ID.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to. A Vrf
            object is also accepted.
        :param ospf_router: OSPF process ID number in [1,63]. An OSPF Router
            object is also accepted (both v2, and v3 versions).
        :param area_id: Unique identifier as a string in the form of x.x.x.x.
        :param peer_router: ID of the peer OSPF router as IP address in x.x.x.x
            form.
        :return: OspfVlink object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        if isinstance(ospf_router, int):
            router = self.__get_ospf_router(ospf_router, vrf)
        area = area_id
        if isinstance(area_id, str):
            area = self.__get_ospf_area(area_id, router)
        # Get OspfVlink from peer_router
        vlink = self.session.api.get_module(
            self.session,
            "OspfVlink",
            peer_router,
            parent_ospf_area=area,
            **kwargs
        )
        try:
            # Get the remote configuration, but the local one takes precedence
            vlink.get()
            utils.set_config_attrs(vlink, kwargs)  # so it gets re-applied here
            vlink.apply()
        except GenericOperationError:
            vlink.apply()  # if can't get it, create
        return vlink

    def ospfv3_vlink(self, vrf, ospf_router, area_id, peer_router, **kwargs):
        """
        Create a OspfVlink object.
        :param vrf: Alphanumeric name of the VRF the OSPF ID belongs to. A Vrf
            object is also accepted.
        :param ospf_router: OSPFv3 process ID number in [1, 63]. An
             Ospfv3Router object is also accepted.
        :param area_id: Unique identifier as a string in the form of x.x.x.x.
        :param peer_router: ID of the peer OSPFv3 router as IP address in
            x.x.x.x form.
        :return: OspfVlink object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        if isinstance(ospf_router, int):
            router = self.__get_ospfv3_router(ospf_router, vrf)
        return self.ospf_vlink(vrf, router, area_id, peer_router, **kwargs)

    def vlan_and_svi(
        self,
        vlan_id,
        vlan_name,
        vlan_int_name,
        vlan_desc=None,
        ipv4=None,
        vrf_name="default",
        vlan_port_desc=None,
    ):
        """
        Create VLAN and Interface objects to represent VLAN and SVI,
            respectively.
        :param vlan_id: Numeric ID of VLAN.
        :param vlan_name: Alphanumeric name of VLAN.
        :param vlan_int_name: Alphanumeric name for the VLAN interface.
        :param vlan_desc: Optional description to add to VLAN.
        :param ipv4: Optional IPv4 address to assign to the interface. Defaults
            to nothing if not specified. Example: '1.1.1.1'
        :param vrf_name: VRF to attach the SVI to. Defaults to "default".
        :param vlan_port_desc: Optional description for the interface.
            Defaults to nothing if not specified.
        :return: A tuple with a Vlan object and a Interface SVI object.
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
        :param vrf: Alphanumeric name of VRF.
        :param port: Alphanumeric name of Port.
        :return: DhcpRelay object.
        """
        port_obj = self.session.api.get_module(self.session, "Interface", port)
        vrf_obj = self.session.api.get_module(self.session, "Vrf", vrf)

        dhcp_relay = self.session.api.get_module(
            self.session, "DhcpRelay", index_id=vrf_obj, port=port_obj
        )

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
        :param list_name: Alphanumeric name of ACL.
        :param list_type: Alphanumeric type of ACL. Type should be one of
            "ipv4," "ipv6," or "mac".
        :return: Acl object.
        """
        acl = self.session.api.get_module(
            self.session, "ACL", index_id=list_name, list_type=list_type
        )

        # Try to obtain data; if not, create
        try:
            acl.get()
        except GenericOperationError:
            # Create object inside switch
            acl.apply()

        return acl

    def acl_entry(
        self,
        list_name,
        list_type,
        sequence_num,
        action="permit",
        count=None,
        protocol=None,
        src_ip=None,
        dst_ip=None,
        dst_l4_port_min=None,
        dst_l4_port_max=None,
        src_mac=None,
        dst_mac=None,
        ethertype=None,
        **kwargs
    ):
        """
        Create an AclEntry object.
        :param list_name: Alphanumeric name of the ACL.
        :param list_type: Type should be one of "ipv4," "ipv6," or "mac".
        :param sequence_num: Integer number of the sequence.
        :param action: Action should be either "permit" or "deny".
        :param count: Optional boolean flag that when true, will make entry
            increment hit count for matched packets.
        :param protocol: Optional integer IP protocol number.
        :param src_ip: Optional source IP address. Both IPv4 and IPv6 are
            supported. Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_ip: Optional destination IP address. Both IPv4 and IPv6 are
            supported. Example:
                10.10.12.11/255.255.255.255
                2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        :param dst_l4_port_min: Optional minimum L4 port number in range; used
            in conjunction with dst_l4_port_max.
        :param dst_l4_port_max: Optional maximum L4 port number in range; used
            in conjunction with dst_l4_port_min.
        :param src_mac: Optional source MAC address. Example:
            '01:02:03:04:05:06'
        :param dst_mac: Optional destination MAC address. Example:
            '01:02:03:04:05:06'
        :param ethertype: Optional integer EtherType number.
        :param kwargs: Optional keyword arguments for more detailed
            configuration.
        :return acl_entry: A AclEntry object.
        """
        # Create Acl object
        acl = self.session.api.get_module(
            self.session, "ACL", index_id=list_name, list_type=list_type
        )

        # Get ACL data
        acl.get()

        # Create ACL Entry
        acl_entry_obj = self.session.api.get_module(
            self.session,
            "AclEntry",
            index_id=sequence_num,
            parent_acl=acl,
            action=action,
            count=count,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_l4_port_min=dst_l4_port_min,
            dst_l4_port_max=dst_l4_port_max,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ethertype=ethertype,
            **kwargs
        )

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

    def vrf_address_family(self, vrf, address_family="ipv4_unicast"):
        """
        Create a VrfAddressFamily object with a VRF.
        :param vrf: Alphanumeric name of the VRF the Family Address belongs to.
            A Vrf object is also accepted.
        :param address_family: Alphanumeric type of the Address Family. The
            options are 'ipv4_unicast' and 'ipv6_unicast'. Defaults to
            'ipv4_unicast'.
        :return: VRF_Address_Family object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)

        vrf_address_fam_obj = self.session.api.get_module(
            self.session, "VrfAddressFamily", address_family, parent_vrf=vrf
        )

        # Try to obtain data; if not, create
        try:
            vrf_address_fam_obj.get()
        except GenericOperationError:
            # Create object inside switch
            vrf_address_fam_obj.apply()

        return vrf_address_fam_obj

    def aggregate_address(self, vrf, bgp_router_asn, family_type, ip_prefix):
        """
        Create an AggregateAddress object.
        :param vrf: Alphanumeric name of the VRF the BGP ASN belongs to. A Vrf
            object is also accepted.
        :param bgp_router_asn: Integer that represents the Autonomous System
            Number.
        :param family_type: Address Family type for the Aggregate Address.
            The options are: 'ipv4-unicast', 'ipv6-unicast'.
        :param ip_prefix: IP address and mask used to key Aggregate Address.
            Example: '1.1.1.1/24'.
        :return: AggregateAddress object.
        """
        _valid_family_types = ["ipv4-unicast", "ipv6-unicast"]
        if family_type not in _valid_family_types:
            raise Exception(
                "ERROR: family_type must be one of: {0}".format(
                    _valid_family_types
                )
            )

        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)

        if isinstance(bgp_router_asn, int):
            # Make BGP Router into an object
            bgp_router_obj = self.session.api.get_module(
                self.session, "BgpRouter", bgp_router_asn, parent_vrf=vrf
            )

            # Materialize interface to ensure its existence
            bgp_router_obj.get()
            # Set variable as an object
            bgp_router_asn = bgp_router_obj

        aggregate_add_obj = self.session.api.get_module(
            self.session,
            "AggregateAddress",
            family_type,
            ip_prefix=ip_prefix,
            parent_bgp_router=bgp_router_asn,
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
        :param vrf: Name of the VRF on which the static route is to be
            configured. Defaults to default vrf. A Vrf object is also accepted.
        :param destination_address_prefix: String IPv4 or IPv6 destination
            prefix and mask in the address/mask format. Example:
                '1.1.1.1'
                or
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :return: StaticRoute object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)

        static_route_obj = self.session.api.get_module(
            self.session,
            "StaticRoute",
            destination_address_prefix,
            parent_vrf=vrf,
        )

        # Try to obtain data; if not, create
        try:
            static_route_obj.get()
        except GenericOperationError:
            # Create object inside switch
            static_route_obj.apply()

        return static_route_obj

    def static_nexthop(
        self,
        vrf,
        destination_address_prefix,
        next_hop_ip_address=None,
        nexthop_type=None,
        distance=None,
        next_hop_interface=None,
        bfd_enable=None,
    ):
        """
        Create a Static Nexthop, with a VRF and a Destination Address related
            to a Static Route.
        :param vrf: Name of the VRF on which the static route is to be
            configured. Defaults to "default". A Vrf object is also accepted.
        :param destination_address_prefix: String IPv4 or IPv6 destination
            prefix and mask in the address/mask format. A StaticRoute object
            is also accepted. Example:
                '1.1.1.1'
                or
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param next_hop_ip_address: The IPv4 address or the IPv6 address of
            next hop. Example:
                '1.1.1.1'
                or
                '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        :param nexthop_type: Specifies whether the static route is a forward,
            blackhole or reject route.
        :param distance: Administrative distance to be used for the next hop in
            the static route instead of default value.
        :param next_hop_interface: The interface through which the next hop can
            be reached.
        :param bfd_enable: Boolean to enable BFD.
        :return: StaticNexthop object.
        """
        if isinstance(vrf, str):
            vrf = self.__get_vrf_from_switch(vrf)
        static_route = destination_address_prefix
        if isinstance(destination_address_prefix, str):
            # Make a Static Route Object
            static_route_obj = self.session.api.get_module(
                self.session,
                "StaticRoute",
                destination_address_prefix,
                parent_vrf=vrf,
            )
            # Materialize Object to ensure its existence
            static_route_obj.get()
            static_route = static_route_obj

        if distance is None:
            distance = 1
        # Set variable
        next_hop_interface_obj = None
        if next_hop_interface is not None:
            next_hop_interface_obj = self.session.api.get_module(
                self.session, "Interface", next_hop_interface
            )
        if nexthop_type is None:
            nexthop_type = "forward"

        if nexthop_type == "forward":
            bfd_enable = False

        static_nexthop_obj = self.session.api.get_module(
            self.session,
            "StaticNexthop",
            0,
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
            static_nexthop_obj = self.session.api.get_module(
                self.session,
                "StaticNexthop",
                0,
                parent_static_route=static_route_obj,
                ip_address=next_hop_ip_address,
                distance=distance,
                port=next_hop_interface_obj,
                type=nexthop_type,
                bfd_enable=bfd_enable,
            )
            # Create object inside switch
            static_nexthop_obj.apply()

        return static_nexthop_obj

    def poe_interface(self, interface):
        """
        Create a PoE Interface object with associated settings.
        :param Interface: Alphanumeric name of the Interface the PoE_Interface
            belongs to. An Interface object is also accepted.
        :return: PoE Interface object.
        """
        if isinstance(interface, str):
            # Make Interface into an object
            interface_obj = self.session.api.get_module(
                self.session, "Interface", interface
            )
            # Materialize Interface to ensure its existence
            interface_obj.get()
            interface = interface_obj

        poe_interface_obj = self.session.api.get_module(
            self.session, "PoEInterface", interface
        )

        poe_interface_obj.get()

        return poe_interface_obj

    def mac(self, vlan, from_id, mac_address):
        """
        Create an Mac object.
        :param vlan_id: Numeric ID for VLAN. A Vlan object is also accepted.
        :param from_id: String source of the MAC address.
            Must be "dynamic", "VSX", "static", "VRRP", "port-access-security",
            "evpn", or "hsc".
        :param mac_address: String MAC address, or netaddr EUI object. Example:
            '01:02:03:04:05:06'.
        :return: Mac object.
        """
        if isinstance(vlan, int):
            vlan = self.vlan(vlan, "Vlan{0}".format(vlan))

        mac_obj = self.session.api.get_module(
            self.session,
            "Mac",
            from_id,
            mac_addr=mac_address,
            parent_vlan=vlan,
        )

        # Get MAC data
        mac_obj.get()

        return mac_obj

    def static_mac(self, vlan, port, mac_address):
        """
        Create an StaticMac object.
        param vlan_id: Numeric ID for VLAN. A Vlan object is also accepted.
        :param port: String for the Port's name. Example: 1/1/1.
        :param mac_address: String MAC address, or netaddr EUI object. Example:
            '01:02:03:04:05:06'.
        :return: StaticMac object.
        """
        if isinstance(vlan, int):
            vlan = self.vlan(vlan, "Vlan{0}".format(vlan))

        if isinstance(port, str):
            port = self.interface(port)

        static_mac_obj = self.session.api.get_module(
            self.session, "StaticMac", mac_address, parent_vlan=vlan, port=port
        )

        # Try to obtain data; if not, create
        try:
            static_mac_obj.get()
            if port is not None:
                if port.name != static_mac_obj.port.name:
                    static_mac_obj.port = port
                    static_mac_obj.apply()
        except GenericOperationError:
            # Create object inside switch
            static_mac_obj.apply()

        return static_mac_obj

    def qos(self, name, **kwargs):
        """
        Create a Qos object.
        :param name: String representing a user-defined name for a Qos object.
        :return: Returns a Qos object.
        """
        # Check for data type of name
        if not isinstance(name, str):
            raise ValueError("ERROR: Name must be on string format.")

        qos_obj = self.session.api.get_module(
            self.session, "Qos", name, **kwargs
        )

        # Try to obtain data; if unable to, create
        try:
            qos_obj.get()
            for k, v in kwargs.items():
                setattr(qos_obj, k, v)
        except GenericOperationError:
            pass  # not present in switch, not an error
        qos_obj.apply()
        return qos_obj

    def qos_cos(self, code_point, **kwargs):
        """
        Gets a QoS COS trust mode object.
        :param code_point: Integer to identify an entry a QoS COS trust mode
            object.
        :return: Returns a QoS COS trust mode object.
        """
        if not isinstance(code_point, int):
            raise ValueError("ERROR: Code Point must be an integer.")

        qos_cos_obj = self.session.api.get_module(
            self.session, "QosCos", code_point
        )

        # Try to obtain data only
        qos_cos_obj.get()

        # Review kwargs to change configurable attributes inside the object
        change_needed = False
        for attr, value in kwargs.items():
            if attr in qos_cos_obj.config_attrs:
                setattr(qos_cos_obj, attr, value)
                change_needed = True

        if change_needed:
            qos_cos_obj.apply()

        return qos_cos_obj

    def qos_dscp(self, code_point, **kwargs):
        """
        Retrieves a QoS DSCP trust mode map entry as an object.
        :param code_point: Integer to identify an entry a QoS DSCP trust mode
            object.
        :return: Returns a QoS DSCP trust mode object.
        """
        if not isinstance(code_point, int):
            raise Exception("ERROR: Code point must be an integer.")

        qos_dscp_obj = self.session.api.get_module(
            self.session, "QosDscp", code_point
        )

        # Try to obtain data only
        qos_dscp_obj.get()

        # Review kwargs to change configurable attributes inside the object
        change_needed = False
        for attr, value in kwargs.items():
            if attr in qos_dscp_obj.config_attrs:
                setattr(qos_dscp_obj, attr, value)
                change_needed = True

        if change_needed:
            qos_dscp_obj.apply()

        return qos_dscp_obj

    def queue(self, qos_name, queue_number, **kwargs):
        """
        Create a Queue object.
        :param qos_name: String with a user-defined name for a QoS object.
        :param queue_number: Integer representing a queue priority, with zero
            being the lowest priority. The maximum number of queues is
            hardware-dependent.
        :return: Queue object.
        """
        if not isinstance(qos_name, str):
            raise ValueError("ERROR: QoS name must be a string.")

        if not isinstance(queue_number, int):
            raise ValueError("ERROR: Queue number must be an integer.")

        queue_obj = self.session.api.get_module(
            self.session,
            "Queue",
            qos_name,
            queue_number=queue_number,
            **kwargs
        )

        # Try to obtain data; if unable to, create
        try:
            # Get the remote configuration, but the local one takes precedence
            queue_obj.get()
            for k, v in kwargs.items():
                setattr(queue_obj, k, v)
            queue_obj.apply()
        except GenericOperationError:
            queue_obj.create()

        # return object
        return queue_obj

    def queue_profile(self, name, **kwargs):
        """
        Create a Queue Profile object.
        :param name: name of the profile.
        :return: Queue Profile object.
        """
        profile = self.session.api.get_module(
            self.session, "QueueProfile", index_id=name, **kwargs
        )
        try:
            # Get the remote configuration, but the local one takes precedence
            profile.get()
            utils.create_attrs(profile, kwargs)  # so it gets re-applied here
        except GenericOperationError:
            pass
        finally:
            # Apply the local configuration to the switch
            profile.apply()
        return profile

    def queue_profile_entry(self, queue_number, queue_profile, **kwargs):
        """
        Create a Queue Profile Entry object.
        :param queue_number: Number that identifies the entry.
        :param queue_profile: A Queue Profile object.
        :return: Queue Profile Entry object.
        """
        if isinstance(queue_profile, str):
            queue_profile = self.session.api.get_module(
                self.session, "QueueProfile", index_id=queue_profile
            )

        entry = self.session.api.get_module(
            self.session,
            "QueueProfileEntry",
            index_id=queue_number,
            parent_profile=queue_profile,
            **kwargs
        )
        try:
            # Get the remote configuration, but the local one takes precedence
            entry.get()
            utils.create_attrs(entry, kwargs)  # so it gets re-applied here
        except GenericOperationError:
            pass
        finally:
            # Apply the local configuration to the switch
            entry.apply()
        return entry

    def vni(
        self,
        vni_id,
        interface,
        vni_type="vxlan_vni",
        routing=None,
        vlan=None,
        vrf=None,
        **kwargs
    ):
        """
        Create a Virtual Network ID (VNI).
        :param vni_id: VNI identifier.
        :param interface: Attached interface to the VNI.
        :param vni_type: Type of the VNI (for now just vxlan_vni).
        :param vlan: Mapped VLAN to the VNI.
        :param vrf: Mapped VRF to the VNI (if L3 is supported).
        :param routing: Flag that indicates if VNI is L2 or L3.
        :return: VNI object.
        """
        if vlan is not None:
            if routing is not None and routing is True:
                raise VerificationError("Routing does not allow VLAN")
            kwargs["vlan"] = vlan
        if vrf is not None:
            if not routing:
                raise VerificationError("Routing must be enabled for L3 VNI")
            kwargs["vrf"] = vrf
        if routing is not None:
            kwargs["routing"] = routing

        vni = self.session.api.get_module(
            self.session,
            "Vni",
            index_id=vni_id,
            interface=interface,
            vni_type=vni_type,
            **kwargs
        )

        try:
            vni.get()
            utils.create_attrs(vni, kwargs)
        except GenericOperationError:
            pass
        finally:
            vni.apply()

        return vni

    def tunnel_endpoint(
        self,
        interface,
        network_id,
        destination,
        origin="static",
        vrf=None,
        **kwargs
    ):
        """
        Create a Tunnel Endpoint
        :param interface: Attached interface for tunnel
        :param network_id: Network identifier
        :param destination: Destination IP
        :param origin: Type of tunneling
            'static' for user configuration (default)
            'evpn' for dynamically learnt via EVPN
            'hsc' for dynamically learnt from a remote controller
        :param vrf: Mapped VRF of tunnel
        """
        tep = self.session.api.get_module(
            self.session,
            "TunnelEndpoint",
            index_id=interface,
            network_id=network_id,
            destination=destination,
            origin=origin,
            vrf=vrf,
            **kwargs
        )

        try:
            tep.get()
            utils.create_attrs(tep, kwargs)
        except GenericOperationError:
            pass
        finally:
            tep.apply()

        return tep
