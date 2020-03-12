# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops, vrf

import json
import logging


def get_bgp_routers(vrf_name, **kwargs):
    """
    Perform a GET call to get a list of all BGP Router Autonomous System Number references

    :param vrf_name: Alphanumeric name of the VRF that we are retrieving all BGP ASNs from
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all BGP Router ASNs in the table
    """
    target_url = kwargs["url"] + "system/vrfs/%s/bgp_routers" % vrf_name

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all BGP Router ASNs failed with status code %d: %s"
              % (response.status_code, response.text))
        bgp_list = {}
    else:
        logging.info("SUCCESS: Getting list of all BGP Router ASNs succeeded")
        bgp_list = response.json()

    return bgp_list


def create_bgp_asn(vrf_name, asn, router_id=None, **kwargs):
    """
    Perform a POST call to create a BGP Router Autonomous System Number

    :param vrf_name: Alphanumeric name of the VRF the BGP ASN belongs to
    :param asn: Integer that represents the Autonomous System Number
    :param router_id: Optional IPv4 address that functions as the BGP Router ID
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    bgp_data = {
      "asn": asn
    }

    if router_id:
        bgp_data['router_id'] = router_id

    target_url = kwargs["url"] + "system/vrfs/%s/bgp_routers" % vrf_name

    post_data = json.dumps(bgp_data, sort_keys=True, indent=4)
    response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating BGP ASN '%s' on vrf %s failed with status code %d: %s"
              % (asn, vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating BGP ASN '%s' succeeded on vrf %s" % (asn, vrf_name))
        return True


def delete_bgp_asn(vrf_name, asn, **kwargs):
    """
    Perform a DELETE call to remove a BGP Router Autonomous System Number

    :param vrf_name: Alphanumeric name of the VRF the BGP ASN belongs to
    :param asn: Integer that represents the Autonomous System Number
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    bgp_list = get_bgp_routers(vrf_name, **kwargs)

    if str(asn) in bgp_list:
        target_url = kwargs["url"] + "system/vrfs/%s/bgp_routers/%d" % (vrf_name, asn)
        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting BGP ASN '%s' on vrf %s failed with status code %d: %s"
                  % (asn, vrf_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting BGP ASN '%s' succeeded on vrf %s" % (asn, vrf_name))
            return True
    else:
        logging.info("SUCCESS: No need to Delete BGP ASN '%s' as it does not exists!" % asn)
        return True


def get_bgp_neighbors_list(vrf_name, asn, **kwargs):
    """
    Perform a GET call to get a list of all BGP neighbors for the supplied Autonomous System Number

    :param vrf_name: Alphanumeric name of the VRF that we are retrieving all BGP ASNs from
    :param asn: Integer that represents the Autonomous System Number
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all BGP neighbors in the table for the ASN
    """
    target_url = kwargs["url"] + "system/vrfs/%s/bgp_routers/%s/bgp_neighbors" % (vrf_name, asn)

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all BGP neighbors for ASN '%s' failed with status code %d: %s"
              % (asn, response.status_code, response.text))
        neighbor_list = {}
    else:
        logging.info("SUCCESS: Getting list of all BGP neighbors for ASN '%s' succeeded" % asn)
        neighbor_list = response.json()
    return neighbor_list


def create_bgp_neighbors(vrf_name, asn, group_ip, family_type="l2vpn_evpn", reflector=False, send_community=False,
                         local_interface="", **kwargs):
    """
    Perform a POST call to create BGP neighbors to the associated BGP ASN.  With l2vpn_evpn being True, this will
    also apply EVPN settings to the BGP neighbor configurations.
    Note that this functions has logic that works for both v1 and v10.04

    :param vrf_name: Alphanumeric name of the VRF the BGP ASN belongs to
    :param asn: Integer that represents the Autonomous System Number
    :param group_ip: IPv4 address or name of group of the neighbors that functions as the BGP Router link
    :param family_type: Alphanumeric to specify what type of neighbor settings to configure. The options are 'l2vpn-evpn',
        'ipv4-unicast', or 'ipv6-unicast'. When setting to l2vpn-evpn, the neighbor configurations also will add
        route-reflector-client and send-community settings.
    :param reflector: Boolean value to determine whether this neighbor has route reflector enabled.  Default is False.
    :param send_community: Boolean value to determine whether this neighbor has send-community enabled.  Default is False.
    :param local_interface: Optional alphanumeric to specify which interface the neighbor will apply to.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if family_type not in ['l2vpn-evpn', 'ipv4-unicast', 'ipv6-unicast']:
        raise Exception("ERROR: family_type should be 'l2vpn-evpn', 'ipv4-unicast', or 'ipv6-unicast'")

    neighbor_list = get_bgp_neighbors_list(vrf_name, asn, **kwargs)

    if group_ip not in neighbor_list:
        bgp_data = {
            "ip_or_group_name": group_ip,
            "is_peer_group": False,
            "remote_as": asn,
            "shutdown": False,
            "activate": {
                "ipv4-unicast": False,
                "ipv6-unicast": False,
                "l2vpn-evpn": False
            },
            "next_hop_unchanged": {
                "l2vpn-evpn": False
            },
            "route_reflector_client": {
                "ipv4-unicast": False,
                "ipv6-unicast": False,
                "l2vpn-evpn": False
            },
            "send_community": {
                "ipv4-unicast": "none",
                "ipv6-unicast": "none",
                "l2vpn-evpn": "none"
            }
        }

        if local_interface:
            int_percents = common_ops._replace_special_characters(local_interface)
            if kwargs["url"].endswith("/v1/"):
                bgp_data.update({'local_interface': "/rest/v1/system/ports/%s" % int_percents})
            else:
                # Else logic designed for v10.04 and later
                bgp_data.update({'local_interface': "/rest/v10.04/system/interfaces/%s" % int_percents})

        bgp_data['activate'][family_type] = True

        if send_community:
            bgp_data['send_community'][family_type] = "both"

        if reflector:
            bgp_data['route_reflector_client'][family_type] = reflector

        target_url = kwargs["url"] + "system/vrfs/%s/bgp_routers/%s/bgp_neighbors" % (vrf_name, asn)

        post_data = json.dumps(bgp_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating BGP Neighbor for ASN '%s' on interface %s failed with status code %d: %s"
                  % (asn, local_interface, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating BGP Neighbor for ASN '%s' succeeded on interface %s" % (asn, local_interface))
            return True
    else:
        logging.info("SUCCESS: BGP Neighbor already exists for ASN '%s' on interface '%s'." % (asn, local_interface))
        return True


def create_bgp_vrf(vrf_name, asn, redistribute, **kwargs):
    """
    Perform a POST call to create BGP VRF settings for the associated BGP ASN.
    Note that this functions has logic that works for both v1 and v10.04

    :param vrf_name: Alphanumeric name of the VRF the BGP ASN belongs to
    :param asn: Integer that represents the Autonomous System Number
    :param redistribute: Optional alphanumeric to specify which types of routes that should be redistributed by BGP. The
        options are "ipv4-unicast" or "ipv6-unicast".
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if redistribute not in ['ipv4-unicast', 'ipv6-unicast']:
        raise Exception("ERROR: redistribute should be 'ipv4-unicast' or 'ipv6-unicast'")

    vrf_list = vrf.get_all_vrfs(**kwargs)

    if kwargs["url"].endswith("/v1/"):
        vrf_check = "/rest/v1/system/vrfs/%s" % vrf_name
    else:   # Updated else for when version is v10.04
        vrf_check = vrf_name

    if vrf_check in vrf_list:
        bgp_vrf_data = {
            "asn": asn
        }
        if redistribute == 'ipv4-unicast':
            bgp_vrf_data['redistribute'] = {
                "ipv4-unicast": ["connected"]
            }
        elif redistribute == 'ipv6-unicast':
            bgp_vrf_data['redistribute'] = {
                "ipv6-unicast": ["connected"]
            }

        target_url = kwargs["url"] + "system/vrfs/%s/bgp_routers" % vrf_name
        post_data = json.dumps(bgp_vrf_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating BGP VRF '%s' for ASN '%s' failed with status code %d: %s"
                  % (vrf_name, asn, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating BGP VRF '%s' for ASN '%s' succeeded" % (vrf_name, asn))
            return True
    else:
        logging.warning("FAIL: Cannot create BGP VRF '%s' as VRF does not exist!" % vrf_name)
        return False


def delete_bgp_vrf(vrf_name, asn, **kwargs):
    """
    Perform a DELETE call to remove BGP VRF settings for the associated BGP ASN.
    Note that this functions has logic that works for both v1 and v10.04

    :param vrf_name: Alphanumeric name of the VRF the BGP ASN belongs to
    :param asn: Integer that represents the Autonomous System Number
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vrf_list = vrf.get_all_vrfs(**kwargs)

    if kwargs["url"].endswith("/v1/"):
        vrf_check = "/rest/v1/system/vrfs/%s" % vrf_name
    else:   # Updated else for when version is v10.04
        vrf_check = vrf_name

    if vrf_check in vrf_list:
        target_url = kwargs["url"] + "system/vrfs/%s/bgp_routers" % vrf_name
        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting BGP VRF '%s' for ASN '%s' failed with status code %d: %s"
                  % (vrf_name, asn, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting BGP VRF '%s' for ASN '%s' succeeded" % (vrf_name, asn))
            return True
    else:
        logging.info("SUCCESS: No need to Delete BGP VRF '%s' as VRF does not exists." % vrf_name)
        return True
