# (C) Copyright 2023 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from __future__ import absolute_import, division, print_function

from ipaddress import IPv4Interface, IPv6Interface
from urllib.parse import quote_plus

from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.device import Device


def overlapping_ips(
    session, interface, ip4_addr=None, ip6_addr=None, new_vrf="default"
):
    """
    Check if IPv4/IPv6 address is already configured.
    :param session: pyaoscx.Session object used to represent a logical
        connection to the device.
    :param interface: Interface to be configured.
    :param ip4_addr: IPv4 address to check.
    :param ip6_addr: IPv6 address to check.
    :param new_vrf: New VRF name for interface.
    """
    overlapping_ips = []

    device = Device(session)
    configuration = device.configuration()
    running_config = configuration.get_full_config()

    interfaces = running_config["Port"]
    interfaces.pop(quote_plus(interface), None)
    for intf in interfaces.values():
        old_vrf = intf["vrf"] if "vrf" in intf else "default"
        if new_vrf != old_vrf:
            continue
        if ip4_addr:
            new_net = IPv4Interface(ip4_addr).network
            if "ip4_address" in intf:
                old_net = IPv4Interface(intf["ip4_address"]).network
                if new_net.overlaps(old_net):
                    overlapping_ips.append(ip4_addr)
            if "ip4_address_secondary" in intf:
                ip4_secs = []
                if isinstance(intf["ip4_address_secondary"], str):
                    ip4_secs.append(intf["ip4_address_secondary"])
                elif isinstance(intf["ip4_address_secondary"], list):
                    ip4_secs.extend(intf["ip4_address_secondary"])
                for old_ip4 in ip4_secs:
                    old_net = IPv4Interface(old_ip4).network
                    if new_net.overlaps(old_net):
                        overlapping_ips.append(ip4_addr)
        if ip6_addr:
            new_net = IPv6Interface(ip6_addr).network
            if "ip6_addresses" in intf:
                for old_ip6 in intf["ip6_addresses"].keys():
                    old_net = IPv6Interface(old_ip6).network
                    print(old_net, new_net)
                    if new_net.overlaps(old_net):
                        overlapping_ips.append(ip6_addr)

    if overlapping_ips != []:
        raise VerificationError(
            "Following IPs already exist or are overlapping network "
            "in VRF {0}: {1}.".format(new_vrf, ",".join(overlapping_ips))
        )
