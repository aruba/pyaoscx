# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops, interface, port, system

import json
import logging


def get_vsx(depth=0, selector=None, **kwargs):
    """
    Perform a GET call to get get the current VSX information on a system.

    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.  If running v10.04 or later, an additional option 'writable' is included.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: JSON of VSX information
    """
    if kwargs["url"].endswith("/v1/"):
        return _get_vsx_v1(depth, selector, **kwargs)
    else:   # Updated else for when version is v10.04
        return _get_vsx(depth, selector, **kwargs)


def _get_vsx_v1(depth, selector, **kwargs):
    """
    Perform a GET call to get get the current VSX information on a system.

    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: JSON of VSX information
    """
    if selector not in ['configuration', 'status', 'statistics', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', or 'statistics'")

    target_url = kwargs["url"] + "system/vsx"
    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    result = []
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting VSX failed with status code %d: %s"
              % (response.status_code, response.text))
        if response.status_code == 400:
            logging.warning("FAIL: Possibly no VSX currently configured")
    else:
        logging.info("SUCCESS: Getting VSX information succeeded")
        result = response.json()

    return result


def _get_vsx(depth, selector, **kwargs):
    """
    Perform a GET call to get get the current VSX information on a system.

    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', 'statistics' or 'writable'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: JSON of VSX information
    """
    if selector not in ['configuration', 'status', 'statistics', 'writable', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', 'statistics', or 'writable'")

    target_url = kwargs["url"] + "system/vsx"
    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    result = []
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting VSX failed with status code %d: %s"
              % (response.status_code, response.text))
        if response.status_code == 400:
            logging.warning("FAIL: Possibly no VSX currently configured")
    else:
        logging.info("SUCCESS: Getting VSX information succeeded")
        result = response.json()

    return result


def create_vsx(role, isl_port, keepalive_peer, keepalive_src, keepalive_vrf, vsx_mac, **kwargs):
    """
    Perform a POST call to create VSX commands.

    :param role: Alphanumeric role that the system will be in the VSX pair.  The options are "primary" or "secondary"
    :param isl_port: Alphanumeric name of the interface that will function as the inter-switch link
    :param keepalive_peer: Alphanumeric IP address of the VSX Peer that will be reached as the keepalive connection.
    :param keepalive_src: Alphanumeric IP address on the switch that will function as the keepalive connection source.
    :param keepalive_vrf: Alphanumeric name of the VRF that the keepalive connection will reside on.
    :param vsx_mac: Alphanumeric MAC address that will function as the VSX System MAC.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if role not in ['primary', 'secondary']:
        raise Exception("ERROR: VSX role should be 'primary' or 'secondary'")

    if kwargs["url"].endswith("/v1/"):
        return _create_vsx_v1(role, isl_port, keepalive_peer, keepalive_src, keepalive_vrf, vsx_mac, **kwargs)
    else:   # Updated else for when version is v10.04
        return _create_vsx(role, isl_port, keepalive_peer, keepalive_src, keepalive_vrf, vsx_mac, **kwargs)


def _create_vsx_v1(role, isl_port, keepalive_peer, keepalive_src, keepalive_vrf, vsx_mac,
                   keepalive_port=7678, **kwargs):
    """
    Perform a POST call to create VSX commands.

    :param role: Alphanumeric role that the system will be in the VSX pair.  The options are "primary" or "secondary"
    :param isl_port: Alphanumeric name of the interface that will function as the inter-switch link
    :param keepalive_peer: Alphanumeric IP address of the VSX Peer that will be reached as the keepalive connection.
    :param keepalive_src: Alphanumeric IP address on the switch that will function as the keepalive connection source.
    :param keepalive_vrf: Alphanumeric name of the VRF that the keepalive connection will reside on.
    :param vsx_mac: Alphanumeric MAC address that will function as the VSX System MAC.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    current_vsx = system.get_system_info(**kwargs)

    if 'vsx' in current_vsx:
        logging.warning("FAIL: Creating VSX Role '%s' on vrf %s.  There is already an existing VSX setup."
              % (role, keepalive_vrf))
        return False
    else:
        if role not in ['primary', 'secondary']:
            raise Exception("ERROR: VSX role should be 'primary' or 'secondary'")

        ip_src_subnet = keepalive_src.find('/')
        ip_peer_subnet = keepalive_peer.find('/')
        if ip_src_subnet >= 0:
            keepalive_src = keepalive_src[0:ip_src_subnet]
        if ip_peer_subnet >= 0:
            keepalive_peer = keepalive_peer[0:ip_peer_subnet]

        vsx_data = {
                "config_sync_disable": False,
                "config_sync_features": [],
                "device_role": role,
                "isl_port": "/rest/v1/system/ports/" + isl_port,
                "isl_timers": {
                    "hello_interval": 1,
                    "hold_time": 0,
                    "peer_detect_interval": 300,
                    "timeout": 20
                },
                "keepalive_peer_ip": keepalive_peer,
                "keepalive_src_ip": keepalive_src,
                "keepalive_timers": {
                    "dead_interval": 3,
                    "hello_interval": 1
                },
                "keepalive_udp_port": keepalive_port,
                "keepalive_vrf": "/rest/v1/system/vrfs/" + keepalive_vrf,
                "linkup_delay_timer": 180,
                "split_recovery_disable": False,
                "system_mac": vsx_mac
            }

        target_url = kwargs["url"] + "system/vsx"
        post_data = json.dumps(vsx_data, sort_keys=True, indent=4)
        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating VSX Role '%s' on vrf %s failed with status code %d: %s"
                  % (role, keepalive_vrf, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating VSX Role '%s' succeeded on vrf %s" % (role, keepalive_vrf))
            return True


def _create_vsx(role, isl_port, keepalive_peer, keepalive_src, keepalive_vrf, vsx_mac, keepalive_port=7678, **kwargs):
    """
    Perform a POST call to create VSX commands.

    :param role: Alphanumeric role that the system will be in the VSX pair.  The options are "primary" or "secondary"
    :param isl_port: Alphanumeric name of the interface that will function as the inter-switch link
    :param keepalive_peer: Alphanumeric IP address of the VSX Peer that will be reached as the keepalive connection.
    :param keepalive_src: Alphanumeric IP address on the switch that will function as the keepalive connection source.
    :param keepalive_vrf: Alphanumeric name of the VRF that the keepalive connection will reside on.
    :param vsx_mac: Alphanumeric MAC address that will function as the VSX System MAC.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_info_dict = system.get_system_info(**kwargs)

    if system_info_dict['vsx'] is not None:
        logging.warning("FAIL: Creating VSX Role '%s' on vrf %s.  There is already an existing VSX setup."
              % (role, keepalive_vrf))
        return False
    else:
        if role not in ['primary', 'secondary']:
            raise Exception("ERROR: VSX role should be 'primary' or 'secondary'")

        # Checks if the ISL Port is a physical interface or a Lag.  If an interface, replace the slashes
        if isl_port[0].isdigit():
            isl_port = common_ops._replace_special_characters(isl_port)

        isl_port_uri = "/rest/v10.04/system/interfaces/" + isl_port

        ip_src_subnet = keepalive_src.find('/')
        ip_peer_subnet = keepalive_peer.find('/')
        if ip_src_subnet >= 0:
            keepalive_src = keepalive_src[0:ip_src_subnet]
        if ip_peer_subnet >= 0:
            keepalive_peer = keepalive_peer[0:ip_peer_subnet]

        vsx_data = {
                "config_sync_disable": False,
                "config_sync_features": [],
                "device_role": role,
                "isl_port": isl_port_uri,
                "isl_timers": {
                    "hello_interval": 1,
                    "hold_time": 0,
                    "peer_detect_interval": 300,
                    "timeout": 20
                },
                "keepalive_peer_ip": keepalive_peer,
                "keepalive_src_ip": keepalive_src,
                "keepalive_timers": {
                    "dead_interval": 3,
                    "hello_interval": 1
                },
                "keepalive_udp_port": keepalive_port,
                "keepalive_vrf": {
                    keepalive_vrf: "/rest/v10.04/system/vrfs/" + keepalive_vrf,
                },
                "linkup_delay_timer": 180,
                "split_recovery_disable": False,
                "system_mac": vsx_mac
            }

        target_url = kwargs["url"] + "system/vsx"
        post_data = json.dumps(vsx_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating VSX Role '%s' on vrf %s failed with status code %d: %s"
                  % (role, keepalive_vrf, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating VSX Role '%s' succeeded on vrf %s" % (role, keepalive_vrf))
            return True


def update_vsx_interface_vlan(vlan_id, active_forwarding, vsx_sync, act_gw_mac, act_gw_ip, **kwargs):
    """
    Perform PUT calls on a VLAN interface to configure VSX IPv4 settings.

    :param vlan_id: Numeric ID of VLAN to that will be configured
    :param active_forwarding: True or False Boolean to set VSX active forwarding
    :param vsx_sync: Set of alphanumeric values to enable VSX configuration synchronization.  The options are
        any combination of 'active-gateways', 'irdp', and 'policies'.  VSX Sync is mainly used in the Primary.
    :param act_gw_mac: Alphanumeric value of the Virtual MAC address for the interface active gateway
    :param act_gw_ip: Alphanumeric value of the Virtual IP address for the interface active gateway
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _update_vsx_interface_vlan_v1(vlan_id, active_forwarding, vsx_sync, act_gw_mac, act_gw_ip, **kwargs)
    else:   # Updated else for when version is v10.04
        return _update_vsx_interface_vlan(vlan_id, active_forwarding, vsx_sync, act_gw_mac, act_gw_ip, **kwargs)


def _update_vsx_interface_vlan_v1(vlan_id, active_forwarding, vsx_sync, act_gw_mac, act_gw_ip, **kwargs):
    """
    Perform PUT calls on a VLAN interface to configure VSX IPv4 settings.

    :param vlan_id: Numeric ID of VLAN to that will be configured
    :param active_forwarding: True or False Boolean to set VSX active forwarding
    :param vsx_sync: Set of alphanumeric values to enable VSX configuration synchronization.  The options are
        any combination of 'active-gateways', 'irdp', and 'policies'
    :param act_gw_mac: Alphanumeric value of the Virtual MAC address for the interface active gateway
    :param act_gw_ip: Alphanumeric value of the Virtual IP address for the interface active gateway
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    ports_list = port.get_all_ports(**kwargs)
    vlan_name = "vlan" + str(vlan_id)

    if "/rest/v1/system/ports/%s" % vlan_name not in ports_list:
        logging.warning("FAIL: Adding VSX information to VLAN Interface '%d' failed because VLAN "
              "Interface doesn't exist" % vlan_id)
        return False
    else:
        port_data = port.get_port(vlan_name, depth=0, selector="configuration", **kwargs)
       
        vsx_sync_set = []
        if vsx_sync == None:
            vsx_sync = {}
        if "active-gateways" in vsx_sync:
            vsx_sync_set.append("^vsx_virtual.*")
        if "irdp" in vsx_sync:
            vsx_sync_set.append(".irdp.*")
        if "policies" in vsx_sync:
            vsx_sync_set.append("^policy.*")

        port_data["vsx_active_forwarding_enable"] = active_forwarding
        port_data["vsx_sync"] = vsx_sync_set
        port_data["vsx_virtual_gw_mac_v4"] = act_gw_mac
        port_data["vsx_virtual_ip4"] = [act_gw_ip]

        port_data.pop('name', None)  # must remove this item from the json since name can't be modified
        port_data.pop('origin', None)  # must remove this item from the json since origin can't be modified

        target_url = kwargs["url"] + "system/ports/%s" % vlan_name
        put_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Adding VSX information to VLAN Interface '%d' failed with status code %d: %s"
                  % (vlan_id, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding VSX information to VLAN Interface '%d' succeeded" % vlan_id)
            return True


def _update_vsx_interface_vlan(vlan_id, active_forwarding, vsx_sync, act_gw_mac, act_gw_ip, **kwargs):
    """
    Perform PUT calls on a VLAN interface to configure VSX IPv4 settings.

    :param vlan_id: Numeric ID of VLAN to that will be configured
    :param active_forwarding: True or False Boolean to set VSX active forwarding
    :param vsx_sync: Set of alphanumeric values to enable VSX configuration synchronization.  The options are
        any combination of 'active-gateways', 'irdp', and 'policies'
    :param act_gw_mac: Alphanumeric value of the Virtual MAC address for the interface active gateway
    :param act_gw_ip: Alphanumeric value of the Virtual IP address for the interface active gateway
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ints_list = interface.get_all_interfaces(**kwargs)
    vlan_name = "vlan" + str(vlan_id)

    if vlan_name not in ints_list:
        logging.warning("FAIL: Adding VSX information to VLAN Interface '%d' failed because "
              "VLAN Interface doesn't exist" % vlan_id)
        return False
    else:
        interface_vsx_data = interface.get_interface(vlan_name, depth=1, selector="writable", **kwargs)

        vsx_sync_set = []
        if "active-gateways" in vsx_sync:
            vsx_sync_set.append("^vsx_virtual.*")
        if "irdp" in vsx_sync:
            vsx_sync_set.append(".irdp.*")
        if "policies" in vsx_sync:
            vsx_sync_set.append("^policy.*")

        if interface_vsx_data['vrf']:
            # Convert the dictionary to a URI string
            interface_vsx_data['vrf'] = list(interface_vsx_data['vrf'].values())[0]

        interface_vsx_data["vsx_active_forwarding_enable"] = active_forwarding
        interface_vsx_data["vsx_sync"] = vsx_sync_set
        interface_vsx_data["vsx_virtual_gw_mac_v4"] = act_gw_mac
        interface_vsx_data["vsx_virtual_ip4"] = [act_gw_ip]

        target_url = kwargs["url"] + "system/interfaces/" + vlan_name
        put_data = json.dumps(interface_vsx_data, sort_keys=True, indent=4)
        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Adding VSX information to VLAN Interface '%d' failed with status code %d: %s"
                  % (vlan_id, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding VSX information to VLAN Interface '%d' succeeded" % vlan_id)
            return True


def delete_vsx_interface_vlan(vlan_id, **kwargs):
    """
    Perform PUT calls on a VLAN interface to remove VSX IPv4 settings.

    :param vlan_id: Numeric ID of VLAN to that will be configured
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _delete_vsx_interface_vlan_v1(vlan_id, **kwargs)
    else:   # Updated else for when version is v10.04
        return _delete_vsx_interface_vlan(vlan_id, **kwargs)


def _delete_vsx_interface_vlan_v1(vlan_id, **kwargs):
    """
    Perform PUT calls on a VLAN interface to remove VSX IPv4 settings.

    :param vlan_id: Numeric ID of VLAN to that will be configured
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = port.get_all_ports(**kwargs)
    vlan_name = "vlan" + str(vlan_id)

    if "/rest/v1/system/ports/%s" % vlan_name not in ports_list:
        logging.warning("FAIL: Deleting VSX information from VLAN Interface '%d' failed "
              "because VLAN Interface doesn't exist" % vlan_id)
        return False
    else:

        port_data = port.get_port(vlan_name, depth=0, selector="configuration", **kwargs)

        port_data["vsx_active_forwarding_enable"] = False
        port_data["vsx_sync"] = []
        port_data["vsx_virtual_ip4"] = []
        port_data.pop('vsx_virtual_gw_mac_v4', None)

        port_data.pop('name', None)  # must remove this item from the json since name can't be modified
        port_data.pop('origin', None)  # must remove this item from the json since origin can't be modified

        target_url = kwargs["url"] + "system/ports/%s" % vlan_name
        put_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Deleting VSX information from VLAN Interface '%d' failed with status code %d: %s"
                  % (vlan_id, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting VSX information from VLAN Interface '%d' succeeded" % vlan_id)
            return True


def _delete_vsx_interface_vlan(vlan_id, **kwargs):
    """
    Perform PUT calls on a VLAN interface to remove VSX IPv4 settings.

    :param vlan_id: Numeric ID of VLAN to that will be configured
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ints_list = interface.get_all_interfaces(**kwargs)
    vlan_name = "vlan" + str(vlan_id)

    if vlan_name not in ints_list:
        logging.warning("FAIL: Deleting VSX information to VLAN Interface '%d' failed because "
              "VLAN Interface doesn't exist" % vlan_id)
        return False
    else:
        interface_vsx_data = interface.get_interface(vlan_name, depth=2, selector="writable", **kwargs)

        interface_vsx_data["vsx_active_forwarding_enable"] = None
        interface_vsx_data["vsx_sync"] = None
        interface_vsx_data["vsx_virtual_gw_mac_v4"] = None
        interface_vsx_data["vsx_virtual_ip4"] = []

        target_url = kwargs["url"] + "system/interfaces/" + vlan_name
        put_data = json.dumps(interface_vsx_data, sort_keys=True, indent=4)
        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Deleting VSX information from VLAN Interface '%d' failed with status code %d: %s"
                  % (vlan_id, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting VSX information from VLAN Interface '%d' succeeded" % vlan_id)
            return True


def delete_vsx(**kwargs):
    """
    Perform a DELETE call to get get the current VSX information on a system.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    target_url = kwargs["url"] + "system/vsx"
    response = kwargs["s"].delete(target_url, verify=False, timeout=2)

    if not common_ops._response_ok(response, "DELETE"):
        logging.warning("FAIL: Deleting VSX instance failed with status code %d: %s"
                        % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Deleting VSX succeeded")
        return True
