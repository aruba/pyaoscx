# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops, interface

import json
import logging


def get_port(port_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve data for a Port table entry

    :param port_name: Alphanumeric name of the port
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing port data
    """
    if kwargs["url"].endswith("/v1/"):
        return _get_port_v1(port_name, depth, selector, **kwargs)
    else:  # Updated else for when version is v10.04
        return _get_port(port_name, depth, selector, **kwargs)


def _get_port_v1(port_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve data for a Port table entry

    :param port_name: Alphanumeric name of the port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing port data
    """

    if selector not in ['configuration', 'status', 'statistics', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', or 'statistics'")

    payload = {
        "depth": depth,
        "selector": selector
    }

    port_name_percents = common_ops._replace_special_characters(port_name)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    port_name = common_ops._replace_percents(port_name_percents)
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting Port table entry '%s' failed with status code %d: %s"
                        % (port_name, response.status_code, response.text))
        output = {}
    else:
        logging.info("SUCCESS: Getting Port table entry '%s' succeeded" % port_name)
        output = response.json()

    return output


def _get_port(port_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve data for a Port table entry

    :param port_name: Alphanumeric name of the port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing port data
    """
    if selector not in ['configuration', 'status', 'statistics', 'writable', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', 'statistics', or 'writable'")

    payload = {
        "depth": depth,
        "selector": selector
    }

    port_name_percents = common_ops._replace_special_characters(port_name)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    port_name = common_ops._replace_percents(port_name_percents)
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting Port table entry '%s' failed with status code %d: %s"
                        % (port_name, response.status_code, response.text))
        output = {}
    else:
        logging.info("SUCCESS: Getting Port table entry '%s' succeeded" % port_name)
        output = response.json()

    return output


def get_all_ports(**kwargs):
    """
    Perform a GET call to get a list of all entries in the Port table

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all ports in the table
    """
    target_url = kwargs["url"] + "system/ports"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all Port table entries failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all Port table entries succeeded")

    ports_list = response.json()
    return ports_list


def add_vlan_port(vlan_port_name, vlan_id, ipv4=None, vrf_name="default", vlan_port_desc=None,
                  port_admin_state="up", **kwargs):
    """
    Perform a POST call to create a logical VLAN Port as part of SVI creation.

    :param vlan_port_name: Alphanumeric Port name
    :param vlan_id: Numeric ID of VLAN
    :param ipv4: Optional IPv4 address to assign to the interface.Defaults to nothing if not specified.
    :param vrf_name: VRF to attach the SVI to. Defaults to "default" if not specified
    :param vlan_port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param port_admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    ports_list = get_all_ports(**kwargs)

    if "/rest/v1/system/ports/%s" % vlan_port_name not in ports_list:
        vlan_port_data = {"admin": port_admin_state,
                          "name": vlan_port_name,
                          "vrf": "/rest/v1/system/vrfs/%s" % vrf_name,
                          "vlan_tag": "/rest/v1/system/vlans/%s" % vlan_id
                          }

        if vlan_port_desc is not None:
            vlan_port_data['description'] = vlan_port_desc

        if ipv4 is not None:
            vlan_port_data['ip4_address'] = ipv4

        target_url = kwargs["url"] + "system/ports"
        post_data = json.dumps(vlan_port_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Port table entry '%s' for SVI failed with status code %d: %s"
                  % (vlan_port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Port table entry '%s' for SVI succeeded" % vlan_port_name)
            return True
    else:
        logging.info("SUCCESS: No need to create VLAN Port '%s' since it already exists" % vlan_port_name)
        return True


def add_l2_port(port_name, port_desc=None, port_admin_state="up", **kwargs):
    """
    Perform a POST call to create a Port table entry for physical L2 interface.  If the Port table entry exists, this
    function will perform a PUT call to update the entry with the given parameters.

    :param port_name: Alphanumeric Port name
    :param port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param port_admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = get_all_ports(**kwargs)

    port_name_percents = common_ops._replace_special_characters(port_name)
    port_data = {
        "admin": port_admin_state,
        "interfaces": ["/rest/v1/system/interfaces/%s" % port_name_percents],
        "name": port_name,
        "routing": False
    }

    if port_desc is not None:
        port_data['description'] = port_desc

    if "/rest/v1/system/ports/%s" % port_name_percents not in ports_list:
        target_url = kwargs["url"] + "system/ports"
        payload_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].post(target_url, data=payload_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Port table entry '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Port table entry '%s' succeeded" % port_name)
            return True
    else:
        target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
        port_data.pop('name', None)  # must remove this item from the json since name can't be modified
        payload_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].put(target_url, data=payload_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Updating Port table entry '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Updating Port table entry '%s' succeeded" % port_name)
            return True


def add_l3_ipv4_port(port_name, ip_address=None, port_desc=None, port_admin_state="up", vrf="default", **kwargs):
    """
    Perform a POST call to create a Port table entry for a physical L3 interface. If the port already exists, the
    function will enable routing on the port and update the IPv4 address if given.

    :param port_name: Alphanumeric Port name
    :param ip_address: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param port_admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = get_all_ports(**kwargs)

    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = {"admin": port_admin_state,
                 "interfaces": ["/rest/v1/system/interfaces/%s" % port_name_percents],
                 "name": port_name,
                 "routing": True,
                 "vrf": "/rest/v1/system/vrfs/%s" % vrf
                 }

    if port_desc is not None:
        port_data['description'] = port_desc

    if ip_address is not None:
        port_data['ip4_address'] = ip_address

    if "/rest/v1/system/ports/%s" % port_name_percents not in ports_list:
        target_url = kwargs["url"] + "system/ports"
        payload_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].post(target_url, data=payload_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding IPv4 Port table entry '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding IPv4 Port table entry '%s' succeeded" % port_name)
            return True
    else:
        return update_port_ipv4(port_name, ip_address, port_admin_state, vrf, **kwargs)


def update_port_ipv4(port_name, ipv4, port_admin_state, vrf, **kwargs):
    """
    Perform GET and PUT calls to update an L3 interface's ipv4 address

    :param port_name: Alphanumeric name of the Port
    :param ipv4: IPv4 address to associate with the VLAN Port
    :param port_admin_state: Administratively-configured state of the port.
    :param vrf: Name of the VRF to which the Port belongs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    port_data = get_port(port_name, depth=0, selector="configuration", **kwargs)

    port_data['ip4_address'] = ipv4
    port_data['routing'] = True
    port_data['admin'] = port_admin_state
    port_data['vrf'] = "/rest/v1/system/vrfs/%s" % vrf

    port_data.pop('name', None)  # must remove this item from the json since name can't be modified
    port_data.pop('origin', None)  # must remove this item from the json since origin can't be modified

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating IPv4 addresses for Port '%s' to '%s' failed with status code %d: %s"
              % (port_name, repr(ipv4), response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating IPv4 addresses for Port '%s' to '%s' succeeded"
              % (port_name, repr(ipv4)))
        return True


def add_l3_ipv6_port(port_name, ip_address=None, port_desc=None, port_admin_state="up", vrf="default", **kwargs):
    """
    Perform a POST call to create a Port table entry for a physical L3 interface. If the port already exists, the
    function will perform a PUT call to update the Port table entry to enable routing on the port and update
    the IPv6 address if given.

    :param port_name: Alphanumeric Port name
    :param ip_address: IPv6 address to assign to the interface. Defaults to nothing if not specified.
    :param port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param port_admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = get_all_ports(**kwargs)

    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = {
        "admin": port_admin_state,
         "interfaces": ["/rest/v1/system/interfaces/%s" % port_name_percents],
         "name": port_name,
         "routing": True,
         "vrf": "/rest/v1/system/vrfs/%s" % vrf
    }

    if port_desc is not None:
        port_data['description'] = port_desc

    if "/rest/v1/system/ports/%s" % port_name_percents not in ports_list:
        target_url = kwargs["url"] + "system/ports"
        payload_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].post(target_url, data=payload_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding L3 IPv6 Port table entry '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding L3 IPv6 Port table entry '%s' succeeded" % port_name)
            # IPv6 defaults
            ipv6_data = {
                "address": ip_address,
                "node_address": True,
                "origin": "configuration",
                "ra_prefix": True,
                "route_tag": 0,
                "type": "global-unicast"
            }

            target_url = kwargs["url"] + "system/interfaces/%s/ip6_addresses" % port_name_percents
            post_data = json.dumps(ipv6_data, sort_keys=True, indent=4)

            response = kwargs["s"].put(target_url, data=post_data, verify=False)
            if not common_ops._response_ok(response, "POST"):
                logging.warning("FAIL: Final configuration of L3 IPv6 Port table entry '%s' failed with status code %d: %s"
                      % (port_name, response.status_code, response.text))
                return False
            else:
                logging.info("SUCCESS: Final configuration of L3 IPv6 Port table entry '%s' succeeded" % port_name)
                return True
    else:
        port_data.pop('name', None)  # must remove this item from the json since name can't be modified
        target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
        payload_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].put(target_url, data=payload_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Updating L3 IPv6 Port table entry '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Updating L3 IPv6 Port table entry '%s' succeeded" % port_name)
            return update_port_ipv6(port_name, ip_address, **kwargs)


def update_port_ipv6(port_name, ip_address, addr_type="global-unicast", **kwargs):
    """
    Perform a POST call to create an IPv6 address entry to update an L3 interface's ipv6 address

    :param port_name: Alphanumeric name of the Port
    :param ipv6: IPv6 address to associate with the Port
    :param addr_type: Type of IPv6 address. Defaults to "global-unicast" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    ipv6_data = {
        "address": ip_address,
        "node_address": True,
        "origin": "configuration",
        "ra_prefix": True,
        "route_tag": 0,
        "type": addr_type
    }

    target_url = kwargs["url"] + "system/ports/%s/ip6_addresses" % port_name_percents
    post_data = json.dumps(ipv6_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating IPv6 address to update Port '%s' to '%s' failed with status code %d: %s"
              % (port_name, ip_address, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating IPv6 address to update Port '%s' to '%s' succeeded"
              % (port_name, ip_address))
        return True


def delete_port(port_name, **kwargs):
    """
    Perform a DELETE call to delete a Port table entry.

    :param port_name: Port table entry name
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    port_name_percents = common_ops._replace_special_characters(port_name)

    ports_list = get_all_ports(**kwargs)

    if "/rest/v1/system/ports/%s" % port_name_percents in ports_list:

        target_url = kwargs["url"] + "system/ports/%s" % port_name_percents

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting Port '%s' failed with status code %d: %s"
                            % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting Port '%s' succeeded" % port_name)
            return True
    else:
        logging.info("SUCCESS: No need to remove  Port '%s' since it doesn't exist" % port_name)
        return True


def _delete_ipv6_address(port_name, ip, **kwargs):
    """
    Perform a DELETE call to remove an IPv6 address from an Interface.

    :param port_name: Alphanumeric Interface name
    :param ip: IPv6 address assigned to the interface that will be removed.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if ip in interface.get_ipv6_addresses(port_name, **kwargs):
        port_name_percents = common_ops._replace_special_characters(port_name)
        ip_address = common_ops._replace_special_characters(ip)
        target_url = kwargs["url"] + "system/interfaces/%s/ip6_addresses/%s" % (port_name_percents, ip_address)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting IPv6 Address '%s' from Port table entry '%s' failed with status code %d: %s"
                  % (ip, port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting IPv6 Address '%s' from Port table entry '%s' succeeded"
                  % (ip, port_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete IPv6 Address '%s' from Port table entry '%s' since it does not exist"
              % (ip, port_name))
        return True


def _port_set_vlan_mode(l2_port_name, vlan_mode, **kwargs):
    """
    Perform GET and PUT calls to set an L2 interface's VLAN mode (native-tagged, native-untagged, or access)

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_mode: A string, either 'native-tagged', 'native-untagged', or 'access', specifying the desired VLAN
        mode
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if vlan_mode not in ['native-tagged', 'native-untagged', 'access']:
        raise Exception("ERROR: VLAN mode should be 'native-tagged', 'native-untagged', or 'access'")

    l2_port_name_percents = common_ops._replace_special_characters(l2_port_name)
    port_data = get_port(l2_port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data.pop('name', None)
    port_data.pop('origin', None)
    port_data.pop('vrf', None)

    port_data['vlan_mode'] = vlan_mode
    port_data['routing'] = False

    target_url = kwargs["url"] + "system/ports/%s" % l2_port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting port '%s' VLAN mode to '%s' failed with status code %d: %s"
              % (l2_port_name, vlan_mode, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting port '%s' VLAN mode to '%s' succeeded" % (l2_port_name, vlan_mode))
        return True


def _port_set_untagged_vlan(l2_port_name, vlan_id, **kwargs):
    """
    Perform GET and PUT/POST calls to set a VLAN on an access port

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_id: Numeric ID of VLAN to set on access port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    l2_port_name_percents = common_ops._replace_special_characters(l2_port_name)
    
    port_data = get_port(l2_port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data.pop('name', None)
    port_data.pop('origin', None)
    port_data.pop('vrf', None)

    port_data['vlan_mode'] = "access"
    port_data['vlan_tag'] = "/rest/v1/system/vlans/%s" % vlan_id
    port_data['routing'] = False

    target_url = kwargs["url"] + "system/ports/%s" % l2_port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not (common_ops._response_ok(response, "PUT") or common_ops._response_ok(response, "POST")):
        logging.warning("FAIL: Setting Port '%s' access VLAN to VLAN ID '%d' failed with status code %d: %s"
              % (l2_port_name, vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting Port '%s' access VLAN to VLAN ID '%d' succeeded"
              % (l2_port_name, vlan_id))
        return True


def _port_add_vlan_trunks(l2_port_name, vlan_trunk_ids=[], **kwargs):
    """
    Perform GET and PUT/POST calls to add specified VLANs to a trunk port. By default, this will also set the port to
    have 'no routing' and if there is not a native VLAN, will set the native VLAN to VLAN 1.

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_trunk_ids: List of VLANs to specify as allowed on the trunk port.  If empty, the interface will
        allow all VLANs on the trunk.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    # need to create port resource for physical port if it doesn't exist
    ports_list = get_all_ports(**kwargs)
    l2_port_name_percents = common_ops._replace_special_characters(l2_port_name)

    trunk_list = []
    for x in vlan_trunk_ids:
        trunk_list.append("/rest/v1/system/vlans/%d" % x)

    if "/rest/v1/system/ports/%s" % l2_port_name_percents not in ports_list:
        # if Port table entry doesn't exist, create it
        port_data = {"name": l2_port_name,
                     "interfaces":
                     [
                         "/rest/v1/system/interfaces/%s" % l2_port_name_percents
                     ],
                     "vlan_mode": "native-untagged",
                     "vlan_tag": "/rest/v1/system/vlans/1",
                     "vlan_trunks": trunk_list,
                     "routing": False
                     }

        target_url = kwargs["url"] + "system/ports"
        post_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

    else:
        # otherwise just update the physical port
        port_data = get_port(l2_port_name_percents, depth=0, selector="configuration", **kwargs)

        port_data.pop('name', None)
        port_data.pop('origin', None)
        port_data.pop('vrf', None)

        if 'vlan_tag' not in port_data:
            port_data['vlan_tag'] = "/rest/v1/system/vlans/1"
        if 'vlan_mode' not in port_data:
            port_data['vlan_mode'] = "native-untagged"
        port_data['routing'] = False

        if not trunk_list:
            port_data['vlan_trunks'] = []
        else:
            for y in trunk_list:
                if y not in port_data['vlan_trunks']:
                    port_data['vlan_trunks'].append(y)

        target_url = kwargs["url"] + "system/ports/%s" % l2_port_name_percents
        put_data = json.dumps(port_data, sort_keys=True, indent=4)
        response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not (common_ops._response_ok(response, "PUT") or common_ops._response_ok(response, "POST")):
        logging.warning("FAIL: Adding VLANs '%s' to Port '%s' trunk failed with status code %d: %s"
              % (vlan_trunk_ids, l2_port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Adding VLANs '%s' to Port '%s' trunk succeeded"
              % (vlan_trunk_ids, l2_port_name))
        return True


def _port_set_native_vlan(l2_port_name, vlan_id, tagged=True, **kwargs):
    """
    Perform GET and PUT/POST calls to set a VLAN to be the native VLAN on the trunk. Also gives the option to set
    the VLAN as tagged.

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_id: Numeric ID of VLAN to add to trunk port
    :param tagged: Boolean to determine if the native VLAN will be set as the tagged VLAN.  If False, the VLAN
        will be set as the native untagged VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if tagged:
        vlan_mode = "native-tagged"
    else:
        vlan_mode = "native-untagged"

    # need to create port resource for physical port if it doesn't exist
    ports_list = get_all_ports(**kwargs)
    l2_port_name_percents = common_ops._replace_special_characters(l2_port_name)

    if "/rest/v1/system/ports/%s" % l2_port_name_percents not in ports_list:
        # if Port table entry doesn't exist, create it
        port_data = {"name": l2_port_name,
                     "interfaces":
                     [
                         "/rest/v1/system/interfaces/%s" % l2_port_name_percents
                     ],
                     "vlan_mode": vlan_mode,
                     "vlan_tag": "/rest/v1/system/vlans/%s" % vlan_id,
                     "vlan_trunks": [],
                     "routing": False
                     }

        target_url = kwargs["url"] + "system/ports"
        post_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

    else:
        # otherwise just update the physical port
        port_data = get_port(l2_port_name_percents, depth=0, selector="configuration", **kwargs)

        port_data.pop('name', None)
        port_data.pop('origin', None)
        port_data.pop('vrf', None)

        port_data['vlan_tag'] = "/rest/v1/system/vlans/%s" % vlan_id
        port_data['routing'] = False
        port_data['vlan_mode'] = vlan_mode

        if (port_data['vlan_trunks']) and ("/rest/v1/system/vlans/%s" % vlan_id not in port_data['vlan_trunks']):
            port_data['vlan_trunks'].append("/rest/v1/system/vlans/%s" % vlan_id)

        target_url = kwargs["url"] + "system/ports/%s" % l2_port_name_percents
        put_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not (common_ops._response_ok(response, "PUT") or common_ops._response_ok(response, "POST")):
        logging.warning("FAIL: Setting native VLAN ID '%d' to Port '%s' failed with status code %d: %s"
              % (vlan_id, l2_port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting native VLAN ID '%d' to Port '%s' succeeded"
              % (vlan_id, l2_port_name))
        return True


def _delete_vlan_port(l2_port_name, vlan_id, **kwargs):
    """
    Perform GET and PUT calls to remove a VLAN from a trunk port

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_id: Numeric ID of VLAN to remove from trunk port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    l2_port_name_percents = common_ops._replace_special_characters(l2_port_name)

    port_data = get_port(l2_port_name, depth=0, selector="configuration", **kwargs)

    port_data.pop('name', None)
    port_data.pop('origin', None)
    port_data.pop('vrf', None)

    if "/rest/v1/system/vlans/%s" % vlan_id in port_data['vlan_trunks']:
        # remove vlan from 'vlan_trunks'
        port_data['vlan_trunks'].remove("/rest/v1/system/vlans/%s" % vlan_id)

    target_url = kwargs["url"] + "system/ports/%s" % l2_port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing VLAN ID '%d' from Port '%s' trunk failed with status code %d: %s"
              % (vlan_id, l2_port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing VLAN ID '%d' from Port '%s' trunk succeeded"
              % (vlan_id, l2_port_name))
        return True


def create_loopback_port(port_name, vrf, ipv4=None, port_desc=None, **kwargs):
    """
    Perform POST calls to create a Loopback Interface table entry for a logical L3 Interface. If the
    Loopback Interface already exists and an IPv4 address is given, the function will update the IPv4 address.

    :param port_name: Alphanumeric Interface name
    :param vrf: Alphanumeric name of the VRF that the loopback port is attached to
    :param ipv4: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = get_all_ports(**kwargs)

    if "/rest/v1/system/ports/%s" % port_name not in ports_list:
        port_data = {
            "admin": "up",
            "interfaces": [],
            "name": port_name,
            "origin": "configuration",
            "ospf_if_type": "ospf_iftype_loopback",
            "vrf": "/rest/v1/system/vrfs/%s" % vrf
            }

        if port_desc is not None:
            port_data['description'] = port_desc

        if ipv4 is not None:
            port_data['ip4_address'] = ipv4

        port_url = kwargs["url"] + "system/ports"
        post_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(port_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Port table entry '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            # If the port creation for the Loopback interface is successful, then the interface resource must be mapped.
            interface_data = {
                "name": port_name,
                "referenced_by": "/rest/v1/system/ports/%s" % port_name,
                "type": "loopback",
                "user_config": {
                    "admin": "up"
                }
            }
            interface_url = kwargs["url"] + "system/interfaces"
            post_data = json.dumps(interface_data, sort_keys=True, indent=4)

            response = kwargs["s"].post(interface_url, data=post_data, verify=False)

            if not common_ops._response_ok(response, "POST"):
                logging.warning("FAIL: Adding Interface table entry '%s' failed with status code %d: %s"
                      % (port_name, response.status_code, response.text))
                return False
            else:
                logging.info("SUCCESS: Adding Port and Interface table entries '%s' succeeded" % port_name)
                return True
    else:
        return update_port_ipv4(port_name, ipv4, "up", vrf, **kwargs)


def _create_vxlan_port(port_name, source_ipv4=None, port_desc=None, dest_udp_port=4789, **kwargs):
    """
    Perform POST calls to create a VXLAN table entry for a logical L3 Interface. If the
    VXLAN Interface already exists and an IPv4 address is given, the function will update the IPv4 address.

    :param port_name: Alphanumeric Interface name
    :param source_ipv4: Source IPv4 address to assign to the VXLAN interface. Defaults to nothing if not specified.
    :param port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param dest_udp_port: Optional Destination UDP Port that the VXLAN will use.  Default is set to 4789
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = get_all_ports(**kwargs)

    if "/rest/v1/system/ports/%s" % port_name not in ports_list:
        port_data = {
            "admin": "up",
            "interfaces": [],
            "name": port_name,
            "routing": False
            }

        if port_desc is not None:
            port_data['description'] = port_desc

        port_url = kwargs["url"] + "system/ports"
        post_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(port_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding VXLAN Port table entry '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            interface_data = {
                "name": port_name,
                "options": {
                    "local_ip": source_ipv4,
                    "vxlan_dest_udp_port": str(dest_udp_port)
                },
                "referenced_by": "/rest/v1/system/ports/%s" % port_name,
                "type": "vxlan",
                "user_config": {
                    "admin": "up"
                }
            }
            interface_url = kwargs["url"] + "system/interfaces"
            post_data = json.dumps(interface_data, sort_keys=True, indent=4)

            response = kwargs["s"].post(interface_url, data=post_data, verify=False)

            if not common_ops._response_ok(response, "POST"):
                logging.warning("FAIL: Adding VXLAN Interface table entry '%s' failed with status code %d: %s"
                      % (port_name, response.status_code, response.text))
                return False
            else:
                logging.info("SUCCESS: Adding VXLAN Port and Interface table entries '%s' succeeded" % port_name)
                return True
    else:
        return update_port_ipv4(port_name, source_ipv4, "up", "default", **kwargs)


def _enable_disable_port(port_name, state="up", **kwargs):
    """
    Perform GET and PUT calls to either enable or disable the port by setting Port's admin state to
        "up" or "down"

    :param port_name: Alphanumeric name of the interface
    :param state: State to set the interface to
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if state not in ['up', 'down']:
        raise Exception("Administratively-configured state of interface should be 'up' or 'down'")

    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = get_port(port_name, depth=0, selector="configuration", **kwargs)

    if port_data:
        port_data['admin'] = state

        port_data.pop('name', None)
        port_data.pop('origin', None)

        target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
        put_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Updating Port '%s' with admin-configured state '%s' "
                  "failed with status code %d: %s" % (port_name, state, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Updating Port '%s' with admin-configured state '%s' "
                  "succeeded" % (port_name, state))
            return True
    else:
        logging.warning("FAIL: Unable to update Port '%s' because operation could not find existing Port" % port_name)
        return False


def _clear_port_acl(port_name, acl_type="aclv4_out", **kwargs):
    """
    Perform GET and PUT calls to clear a Port's Ingress ACL

    :param port_name: Alphanumeric name of the Port
    :param acl_type: Type of ACL, options are between 'aclv4_out', 'aclv4_in', and 'aclv6_in'
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if acl_type not in ['aclv4_out', 'aclv4_in', 'aclv6_in']:
        raise Exception("ERROR: acl_type should be 'aclv4_out', 'aclv4_in', or 'aclv6_in'")

    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = get_port(port_name, depth=0, selector="configuration", **kwargs)

    cfg_type = acl_type + '_cfg'
    cfg_version = acl_type + '_cfg_version'

    port_data.pop(cfg_type, None)
    port_data.pop(cfg_version, None)

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing %s ACL on Port '%s' failed with status code %d: %s"
              % (cfg_type, port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing %s ACL on Port '%s' succeeded"
              % (cfg_type, port_name))
        return True


def initialize_port_entry(port_name, **kwargs):
    """
    Perform a PUT call on the Port to initialize it to it's default state, then initialize the Interface entry.

    :param port_name: Alphanumeric name of the system port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    port_data = {}
    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Initializing port '%s' failed with status code %d: %s"
                        % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Initializing port '%s' succeeded" % port_name)
        return interface.initialize_interface_entry(port_name, **kwargs)