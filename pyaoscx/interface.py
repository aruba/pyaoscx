# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops, port

import json
import random
import logging


def get_interface(int_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve data for an Interface table entry

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.  If running v10.04 or later, an additional option 'writable' is included.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data for Interface entry
    """
    if kwargs["url"].endswith("/v1/"):
        return _get_interface_v1(int_name, depth, selector, **kwargs)
    else:   # Updated else for when version is v10.04
        return _get_interface(int_name, depth, selector, **kwargs)


def _get_interface_v1(int_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve data for an Interface table entry

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data for Interface entry
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    if selector not in ['configuration', 'status', 'statistics', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', or 'statistics'")

    target_url = kwargs["url"] + "system/interfaces/%s?" % int_name_percents
    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=3)

    result = []
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting Interface table entry '%s' failed with status code %d: %s"
              % (int_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting Interface table entry '%s' succeeded" % int_name)
        result = response.json()
    return result


def _get_interface(int_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve data for an Interface table entry

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', 'statistics' or 'writable'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data for Interface entry
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    if selector not in ['configuration', 'status', 'statistics', 'writable', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', 'statistics', or 'writable'")

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=3)
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting Interface table entry '%s' failed with status code %d: %s"
              % (int_name, response.status_code, response.text))
        result = {}
    else:
        logging.info("SUCCESS: Getting Interface table entry '%s' succeeded" % int_name)
        result = response.json()

    return result


def get_all_interfaces(**kwargs):
    """
    Perform a GET call to get a list (or dictionary) of all entries in the Interface table

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List/dict of all Interfaces in the table
    """
    target_url = kwargs["url"] + "system/interfaces"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list/dict of all Interface table entries failed with status code %d: %s"
              % (response.status_code, response.text))
        interface_list = []
    else:
        logging.info("SUCCESS: Getting list/dict of all Interface table entries succeeded")
        interface_list = response.json()

    return interface_list


def get_all_interface_names(**kwargs):
    """
    Perform a GET call to get a list of all of the names for each interface in the Interface table

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all Interface names in the table
    """
    target_url = kwargs["url"] + "system/interfaces"

    response = kwargs["s"].get(target_url, verify=False)
    interface_list = []

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of Interface names failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of Interface names succeeded")
        uri_list = response.json()
        if kwargs["url"].endswith("/v1/"):
            for interface_uri in uri_list:
                interface_name = interface_uri[(interface_uri.rfind('/')+1):]  # Takes string after last '/'
                if interface_name != "bridge_normal":  # Ignore bridge_normal interface
                    interface_list.append(common_ops._replace_percents(interface_name))
        else:  # Updated else for when version is v10.04
            for interface_key in uri_list:
                interface_list.append(interface_key)
    return interface_list


def get_ipv6_addresses(int_name, depth=0, **kwargs):
    """
    Perform a GET call to retrieve the list of IPv6 addresses for an Interface table entry

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all ipv6 addresses for the Interface entry
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    if kwargs["url"].endswith("/v1/"):
        target_url = kwargs["url"] + "system/ports/%s/ip6_addresses" % int_name_percents
        logport = "Port"
    else:  # Updated else for when version is v10.04
        target_url = kwargs["url"] + "system/interfaces/%s/ip6_addresses" % int_name_percents
        logport = "Interface"

    payload = {
        "depth": depth
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=3)
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting IPv6 list for %s table entry '%s' failed with status code %d: %s"
              % (logport, int_name, response.status_code, response.text))
        result = []
    else:
        logging.info("SUCCESS: Getting IPv6 list for %s table entry '%s' succeeded" % (logport, int_name))
        result = response.json()

    return result


def add_vlan_interface(vlan_int_name, vlan_port_name, vlan_id, ipv4, vrf_name, vlan_port_desc, int_type="vlan",
                       user_config=None, **kwargs):
    """
    Perform a POST call to add Interface table entry for a VLAN.

    :param vlan_int_name: Alphanumeric name for the VLAN interface
    :param vlan_port_name: Alphanumeric Port name to associate with the interface
    :param vlan_id: Numeric ID of VLAN
    :param ipv4: Optional IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param vrf_name: VRF to attach the SVI to. Defaults to "default" if not specified
    :param vlan_port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param int_type: Type of interface; generally should be "vlan" for SVI's.
        As such, defaults to "internal" if not specified.
    :param user_config: User configuration to apply to interface. Defaults to {"admin": "up"} if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _add_vlan_interface_v1(vlan_int_name, vlan_port_name, int_type, user_config, **kwargs)
    else:  # Updated else for when version is v10.04
        return _add_vlan_interface(vlan_int_name, vlan_id, ipv4, vrf_name, vlan_port_desc, int_type, user_config, **kwargs)


def _add_vlan_interface_v1(vlan_int_name, vlan_port_name, int_type="vlan", user_config=None, **kwargs):
    """
    Perform a POST call to add Interface table entry for a VLAN.

    :param vlan_int_name: Alphanumeric name for the VLAN interface
    :param vlan_port_name: Alphanumeric Port name to associate with the interface
    :param int_type: Type of interface; generally should be "vlan" for SVI's.
        As such, defaults to "internal" if not specified.
    :param user_config: User configuration to apply to interface. Defaults to {"admin": "up"} if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ints_list = get_all_interfaces(**kwargs)

    if "/rest/v1/system/interfaces/%s" % vlan_int_name not in ints_list:
        if user_config is None:
            # optional argument can't default to a dictionary type,
            # so make it None and change it to the dictionary {"admin": "up"} if it was None
            user_config = {"admin": "up"}

        vlan_int_data = {"name": vlan_int_name,
                         "referenced_by": "/rest/v1/system/ports/%s" % vlan_port_name,
                         "type": int_type,  # API says: "vlan: generally represents SVI - L3 VLAN interfaces."
                         "user_config": user_config
                         }

        target_url = kwargs["url"] + "system/interfaces"

        post_data = json.dumps(vlan_int_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Interface table entry '%s' for SVI failed with status code %d: %s"
                  % (vlan_int_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Interface table entry '%s' for SVI succeeded" % vlan_int_name)
            return True
    else:
        logging.info("SUCCESS: No need to create Interface table entry '%s' for SVI since it already exists"
              % vlan_int_name)
        return True


def _add_vlan_interface(vlan_int_name, vlan_id=None, ipv4=None, vrf_name="default", vlan_port_desc=None,
                        int_type="vlan", user_config=None, **kwargs):
    """
    Perform a POST call to add Interface table entry for a VLAN.

    :param vlan_int_name: Alphanumeric name for the VLAN interface
    :param vlan_port_name: Alphanumeric Port name to associate with the interface
    :param int_type: Type of interface; generally should be "vlan" for SVI's.
        As such, defaults to "internal" if not specified.
    :param user_config: User configuration to apply to interface. Defaults to {"admin": "up"} if not speicifed.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ints_dict = get_all_interfaces(**kwargs)

    if vlan_int_name not in ints_dict:
        if user_config is None:
            # optional argument can't default to a dictionary type,
            # so make it None and change it to the dictionary {"admin": "up"} if it was None
            user_config = {"admin": "up"}

        vlan_int_data = {"name": vlan_int_name,
                         "type": int_type,  # API says: "vlan: generally represents SVI - L3 VLAN interfaces."
                         "user_config": user_config,
                         "vrf": "/rest/v10.04/system/vrfs/%s" % vrf_name,
                         "vlan_tag": "/rest/v10.04/system/vlans/%s" % vlan_id
                         }

        if vlan_port_desc is not None:
            vlan_int_data['description'] = vlan_port_desc

        if ipv4 is not None:
            vlan_int_data['ip4_address'] = ipv4

        target_url = kwargs["url"] + "system/interfaces"

        post_data = json.dumps(vlan_int_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Interface table entry '%s' for SVI failed with status code %d: %s"
                  % (vlan_int_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Interface table entry '%s' for SVI succeeded" % vlan_int_name)
            return True
    else:
        logging.info("SUCCESS: No need to create Interface table entry '%s' for SVI since it already exists"
              % vlan_int_name)
        return True


def add_l2_interface(interface_name, interface_desc=None, interface_admin_state="up", **kwargs):
    """
    Perform a POST call to create an Interface table entry for physical L2 interface.

    :param interface_name: Alphanumeric Interface name
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return port.add_l2_port(interface_name, interface_desc, interface_admin_state, **kwargs)
    else:   # Updated else for when version is v10.04
        return _add_l2_interface(interface_name, interface_desc, interface_admin_state, **kwargs)


def _add_l2_interface(interface_name, interface_desc=None, interface_admin_state="up", **kwargs):
    """
    Perform a PUT call to create an Interface table entry for physical L2 interface.
    :param interface_name: Alphanumeric Interface name
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    interface_name_percents = common_ops._replace_special_characters(interface_name)

    interface_data = {
        "admin": "up",
        "description": interface_desc,
        "routing": False,
        "user_config": {
            "admin": interface_admin_state
        },
    }

    target_url = kwargs["url"] + "system/interfaces/" + interface_name_percents
    post_data = json.dumps(interface_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Adding Interface table entry '%s' failed with status code %d: %s"
              % (interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Adding Interface table entry '%s' succeeded" % interface_name)
        return True


def add_l3_ipv4_interface(interface_name, ip_address=None, interface_desc=None, interface_admin_state="up",
                          vrf="default", **kwargs):
    """
    Perform a PUT or POST call to create an Interface table entry for a physical L3 Interface. If the Interface already
    exists, the function will enable routing on the Interface and update the IPv4 address if given.

    :param interface_name: Alphanumeric Interface name
    :param ip_address: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _add_l3_ipv4_interface_v1(interface_name, ip_address, interface_desc, interface_admin_state, vrf, **kwargs)
    else:   # Updated else for when version is v10.04
        return _add_l3_ipv4_interface(interface_name, ip_address, interface_desc, interface_admin_state, vrf, **kwargs)


def _add_l3_ipv4_interface_v1(interface_name, ip_address=None, interface_desc=None, interface_admin_state="up",
                              vrf="default", **kwargs):
    """
    Perform a PUT or POST call to create an Interface table entry for a physical L3 Interface. If the Interface already
    exists, the function will enable routing on the Interface and update the IPv4 address if given.

    :param interface_name: Alphanumeric Interface name
    :param ip_address: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    return port.add_l3_ipv4_port(interface_name, ip_address, interface_desc, interface_admin_state, vrf, **kwargs)


def _add_l3_ipv4_interface(interface_name, ip_address=None, interface_desc=None, interface_admin_state="up",
                           vrf="default", **kwargs):
    """
    Perform a PUT call to update an Interface table entry for a physical L3 Interface. If the Interface already
    exists, the function will enable routing on the Interface and update the IPv4 address if given.

    :param interface_name: Alphanumeric Interface name
    :param ip_address: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    interface_name_percents = common_ops._replace_special_characters(interface_name)

    interface_data = {
        "admin": interface_admin_state,
        "interfaces": ["/rest/v10.04/system/interfaces/%s" % interface_name_percents],
        "routing": True,
        "ip4_address": ip_address,
        "vrf": "/rest/v10.04/system/vrfs/%s" % vrf
    }

    if interface_desc is not None:
        interface_data['description'] = interface_desc

    target_url = kwargs["url"] + "system/interfaces/" + interface_name_percents
    put_data = json.dumps(interface_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Adding Interface table entry '%s' failed with status code %d: %s"
              % (interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring Interface table entry '%s' succeeded" % interface_name)
        return True


def add_l3_ipv6_interface(interface_name, ip_address=None, interface_desc=None, interface_admin_state="up",
                          vrf="default", **kwargs):
    """
    Perform a PUT or POST call to create an Interface table entry for a physical L3 Interface. If the Interface already
    exists, the function will enable routing on the Interface and update the IPv6 address if given.

    :param interface_name: Alphanumeric Interface name
    :param ip_address: IPv6 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _add_l3_ipv6_interface_v1(interface_name, ip_address, interface_desc, interface_admin_state, vrf, **kwargs)
    else:   # Updated else for when version is v10.04
        return _add_l3_ipv6_interface(interface_name, ip_address, interface_desc, interface_admin_state, vrf, **kwargs)


def _add_l3_ipv6_interface_v1(interface_name, ip_address=None, interface_desc=None, interface_admin_state="up",
                              vrf="default", **kwargs):
    """
    Perform a PUT or POST call to create an Interface table entry for a physical L3 Interface. If the Interface already
    exists, the function will enable routing on the Interface and update the IPv6 address if given.

    :param interface_name: Alphanumeric Interface name
    :param ip_address: IPv6 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    return port.add_l3_ipv6_port(interface_name, ip_address, interface_desc, interface_admin_state, vrf, **kwargs)


def _add_l3_ipv6_interface(interface_name, ip_address=None, interface_desc=None, interface_admin_state="up",
                           vrf="default", **kwargs):
    """
    Perform a PUT call to update an Interface table entry for a physical L3 Interface, then a POST call to add an IPv6
    mapping. If the Interface already exists, the function will enable routing on the Interface and update the
    IPv6 address if given.

    :param interface_name: Alphanumeric Interface name
    :param ip_address: IPv6 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param interface_admin_state: Optional administratively-configured state of the interface.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    interface_name_percents = common_ops._replace_special_characters(interface_name)

    interface_data = {
        "admin": interface_admin_state,
        "interfaces": ["/rest/v10.04/system/interfaces/%s" % interface_name_percents],
        "routing": True,
        "vrf": {vrf: "/rest/v10.04/system/vrfs/%s" % vrf}
    }

    if interface_desc is not None:
        interface_data['description'] = interface_desc

    target_url = kwargs["url"] + "system/interfaces/" + interface_name_percents
    put_data = json.dumps(interface_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Initial configuration of L3 IPv6 Interface table entry '%s' failed with status code %d: %s"
              % (interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Initial configuration of L3 IPv6 Interface table entry '%s' succeeded" % interface_name)
        # IPv6 defaults
        ipv6_data = {
          "address": ip_address,
          "node_address": True,
          "origin": "configuration",
          "ra_prefix": True,
          "route_tag": 0,
          "type": "global-unicast"
        }

        target_url = kwargs["url"] + "system/interfaces/%s/ip6_addresses" % interface_name_percents
        post_data = json.dumps(ipv6_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)
        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Final configuration of L3 IPv6 Interface table entry '%s' failed with status code %d: %s"
                  % (interface_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Final configuration of L3 IPv6 Interface table entry '%s' succeeded" % interface_name)
            return True


def delete_ipv6_address(interface_name, ip, **kwargs):
    """
    Perform a DELETE call to remove an IPv6 address from an Interface.

    :param interface_name: Alphanumeric Interface name
    :param ip: IPv6 address assigned to the interface that will be removed.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return port._delete_ipv6_address(interface_name, ip, **kwargs)
    else:   # Updated else for when version is v10.04
        return _delete_ipv6_address(interface_name, ip, **kwargs)


def _delete_ipv6_address(interface_name, ip, **kwargs):
    """
    Perform a DELETE call to remove an IPv6 address from an Interface.

    :param interface_name: Alphanumeric Interface name
    :param ip: IPv6 address assigned to the interface that will be removed.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if ip in get_ipv6_addresses(interface_name, **kwargs):
        interface_name_percents = common_ops._replace_special_characters(interface_name)
        ip_address = common_ops._replace_special_characters(ip)
        target_url = kwargs["url"] + "system/interfaces/%s/ip6_addresses/%s" % (interface_name_percents, ip_address)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting IPv6 Address '%s' from Interface table entry '%s' failed with status code %d: %s"
                  % (ip, interface_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting IPv6 Address '%s' from Interface table entry '%s' succeeded"
                  % (ip, interface_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete IPv6 Address '%s' from Interface table entry '%s' since it does not exist"
              % (ip, interface_name))
        return True


def create_loopback_interface(interface_name, vrf="default", ipv4=None, interface_desc=None, **kwargs):
    """
    Perform a PUT and/or POST call to create a Loopback Interface table entry for a logical L3 Interface. If the
    Loopback Interface already exists and an IPv4 address is given, the function will update the IPv4 address.

    :param interface_name: Alphanumeric Interface name
    :param vrf: VRF to attach the SVI to. Defaults to "default" if not specified
    :param ipv4: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_loopback_interface_v1(interface_name, vrf, ipv4, interface_desc, **kwargs)
    else:   # Updated else for when version is v10.04
        return _create_loopback_interface(interface_name, vrf, ipv4, interface_desc, **kwargs)


def _create_loopback_interface_v1(interface_name, vrf, ipv4=None, interface_desc=None, **kwargs):
    """
    Perform a PUT and/or POST call to create a Loopback Interface table entry for a logical L3 Interface. If the
    Loopback Interface already exists and an IPv4 address is given, the function will update the IPv4 address.

    :param interface_name: Alphanumeric Interface name
    :param vrf: VRF to attach the SVI to. Defaults to "default" if not specified
    :param ipv4: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port.create_loopback_port(interface_name, vrf, ipv4, interface_desc, **kwargs)


def _create_loopback_interface(interface_name, vrf, ipv4=None, interface_desc=None, **kwargs):
    """
    Perform a POST call to create a Loopback Interface table entry for a logical L3 Interface. If the
    Loopback Interface already exists and an IPv4 address is given, the function will update the IPv4 address.

    :param interface_name: Alphanumeric Interface name
    :param vrf: VRF to attach the SVI to. Defaults to "default" if not specified
    :param ipv4: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param interface_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    interface_name_percents = common_ops._replace_special_characters(interface_name)

    interface_data = {
        "name": interface_name,
        "type": "loopback",
        "user_config": {
            "admin": "up"
        },
        "ospf_if_type": "ospf_iftype_loopback",
        "vrf": "/rest/v10.04/system/vrfs/%s" % vrf
    }

    if ipv4 is not None:
        interface_data['ip4_address'] = ipv4

    if interface_desc is not None:
        interface_data['description'] = interface_desc

    target_url = kwargs["url"] + "system/interfaces"
    post_data = json.dumps(interface_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Adding Interface table entry '%s' failed with status code %d: %s"
              % (interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring Interface table entry '%s' succeeded" % interface_name)
        return True


def _create_vxlan_interface(interface_name, source_ipv4=None, port_desc=None, dest_udp_port=4789, **kwargs):
    """
    Perform POST call to create a VXLAN table entry for a logical L3 Interface. If the
    VXLAN Interface already exists and an IPv4 address is given, the function will update the IPv4 address.

    :param interface_name: Alphanumeric Interface name
    :param source_ipv4: Optional source IPv4 address to assign to the VXLAN interface. Defaults to nothing if not specified.
    :param port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param dest_udp_port: Optional Destination UDP Port that the VXLAN will use.  Default is set to 4789
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    interfaces_dict = get_all_interfaces(**kwargs)

    if interface_name not in interfaces_dict:
        interface_data = {
            "name": interface_name,
            "options": {
                "local_ip": source_ipv4,
                "vxlan_dest_udp_port": str(dest_udp_port)
            },
            "type": "vxlan",
            "user_config": {
                "admin": "up"
            },

            "admin": "up",
            "routing": False
        }

        if port_desc is not None:
            interface_data['description'] = port_desc

        interface_url = kwargs["url"] + "system/interfaces"
        post_data = json.dumps(interface_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(interface_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding VXLAN Interface table entry '%s' failed with status code %d: %s"
                  % (interface_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding VXLAN Interface table entry '%s' succeeded" % interface_name)
            return True
    else:
        return update_interface_ipv4(interface_name, source_ipv4, **kwargs)


def update_interface_ipv4(interface_name, ipv4, interface_admin_state, vrf, **kwargs):
    """
    Perform GET and PUT calls to update an L3 interface's ipv4 address

    :param interface_name: Alphanumeric name of the Port
    :param ipv4: IPv4 address to associate with the VLAN Port
    :param interface_admin_state: Administratively-configured state of the port.
    :param vrf: Name of the VRF to which the Port belongs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    interface_name_percents = common_ops._replace_special_characters(interface_name)
    interface_data = get_interface(interface_name, depth=1, selector="writable", **kwargs)

    interface_data['ip4_address'] = ipv4
    interface_data['routing'] = True
    interface_data['admin'] = interface_admin_state
    interface_data['vrf'] = "/rest/v10.04/system/vrfs/%s" % vrf

    target_url = kwargs["url"] + "system/interfaces/%s" % interface_name_percents
    put_data = json.dumps(interface_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating IPv4 addresses for Port '%s' to '%s' failed with status code %d: %s"
              % (interface_name, repr(ipv4), response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating IPv4 addresses for Port '%s' to '%s' succeeded"
              % (interface_name, repr(ipv4)))
        return True


def update_port_ipv6(interface_name, ipv6, addr_type="global-unicast", **kwargs):
    """
    Perform a POST call to update an L3 interface's ipv6 address

    :param interface_name: Alphanumeric name of the Port
    :param ipv6: IPv6 address to associate with the VLAN Port
    :param addr_type: Type of IPv6 address. Defaults to "global-unicast" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    ipv6_data = {"address": ipv6,
                 "type": addr_type}

    target_url = kwargs["url"] + "system/interfaces/%s/ip6_addresses" % interface_name
    post_data = json.dumps(ipv6_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Updating IPv6 address for Port '%s' to '%s' failed with status code %d: %s"
              % (interface_name, ipv6, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating IPv6 address for Port '%s' to '%s' succeeded"
              % (interface_name, ipv6))
        return True


def enable_disable_interface(int_name, state="up", **kwargs):
    """
    Perform GET and PUT calls to either enable or disable the interface by setting Interface's admin_state to
        "up" or "down"

    :param int_name: Alphanumeric name of the interface
    :param state: State to set the interface to
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _enable_disable_interface_v1(int_name, state, **kwargs)
    else:  # Updated else for when version is v10.04
        return _enable_disable_interface(int_name, state, **kwargs)


def _enable_disable_interface_v1(int_name, state="up", **kwargs):
    """
    Perform GET and PUT calls to either enable or disable the interface by setting Interface's admin_state to
        "up" or "down"

    :param int_name: Alphanumeric name of the interface
    :param state: State to set the interface to
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if state not in ['up', 'down']:
        raise Exception("Administratively-configured state of interface should be 'up' or 'down'")

    int_name_percents = common_ops._replace_special_characters(int_name)

    interface_list = get_all_interfaces(**kwargs)

    if "/rest/v1/system/interfaces/%s" % int_name_percents in interface_list:
        int_data = get_interface(int_name, 0, "configuration", **kwargs)
        int_data['user_config'] = {"admin": state}

        target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
        put_data = json.dumps(int_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Updating Interface '%s' with admin-configured state '%s' "
                  "failed with status code %d: %s" % (int_name, state, response.status_code, response.text))
            success = False
        else:
            logging.info("SUCCESS: Updating Interface '%s' with admin-configured state '%s' "
                  "succeeded" % (int_name, state))
            success = True
        port._enable_disable_port(int_name, state, **kwargs)
        return success
    else:
        logging.warning("FAIL: Unable to update Interface '%s' because operation could not find interface" % int_name)
        return False


def _enable_disable_interface(int_name, state="up", **kwargs):
    """
    Perform GET and PUT calls to either enable or disable the interface by setting Interface's admin_state to
        "up" or "down"

    :param int_name: Alphanumeric name of the interface
    :param state: State to set the interface to
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if state not in ['up', 'down']:
        raise Exception("Administratively-configured state of interface should be 'up' or 'down'")

    int_name_percents = common_ops._replace_special_characters(int_name)

    int_data = get_interface(int_name, 1, "writable", **kwargs)
    int_data['user_config'] = {"admin": state}

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating Interface '%s' with admin-configured state '%s' "
              "failed with status code %d: %s" % (int_name, state, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating Interface '%s' with admin-configured state '%s' "
              "succeeded" % (int_name, state))
        return True


def delete_interface(interface_name, **kwargs):
    """
    Perform a DELETE call to either the Interface Table or Port Table to delete an interface

    :param interface_name: Name of interface's reference entry in Interface table
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _delete_interface_v1(interface_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_interface(interface_name, **kwargs)


def _delete_interface_v1(interface_name, **kwargs):
    """
    Perform DELETE call to Port Table to delete an interface

    Note: Interface API does not have delete methods.
    To delete an Interface, you remove its reference port.

    :param name: Name of interface's reference entry in Port table
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    return port.delete_port(interface_name, **kwargs)


def _delete_interface(name, **kwargs):
    """
    Perform DELETE call to Interface table to delete an interface
    :param name: Name of interface
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ints_dict = get_all_interfaces(**kwargs)

    if name in ints_dict:

        target_url = kwargs["url"] + "system/interfaces/%s" % name

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting Interface table entry '%s' failed with status code %d: %s"
                  % (name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting Interface table entry '%s' succeeded" % name)
            return True
    else:
        logging.info("SUCCESS: No need to delete Interface table entry '%s' because it doesn't exist"
              % name)
        return True


def delete_l2_interface(interface_name, **kwargs):
    """
    Perform either a PUT call to the Interface Table or DELETE call to Port Table to delete an interface
    If trying to re-initialize an L2 interface, use the function initialize_l2_interface()

    :param interface_name: Name of interface's reference entry in Interface table
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _delete_l2_interface_v1(interface_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_l2_interface(interface_name, **kwargs)


def _delete_l2_interface_v1(interface_name, **kwargs):
    """
    Perform DELETE call to Port Table to delete an L2 interface

    Note: Interface API does not have delete methods.
    To delete an Interface, you remove its reference port.

    :param name: Name of interface's reference entry in Port table
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    return port.delete_port(interface_name, **kwargs)


def _delete_l2_interface(interface_name, **kwargs):
    """
    Perform a PUT call to the Interface Table to reset an interface to it's default values

    :param interface_name: Name of interface's reference entry in Interface table
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    interface_name_percents = common_ops._replace_special_characters(interface_name)
    target_url = kwargs["url"] + "system/interfaces/%s" % interface_name_percents

    interface_data = {}
    interface_data = json.dumps(interface_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=interface_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Deleting Interface '%s' failed with status code %d: %s"
                        % (interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Deleting Interface '%s' succeeded" % interface_name)
        return True


def _port_set_vlan_mode(l2_port_name, vlan_mode, **kwargs):
    """
    Perform GET and PUT calls to set an L2 interface's VLAN mode (native-tagged, native-untagged, or access)

    :param l2_port_name: L2 interface's Interface table entry name
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
    int_data = get_interface(l2_port_name_percents, depth=1, selector="writable", **kwargs)

    int_data['vlan_mode'] = vlan_mode
    int_data['routing'] = False

    target_url = kwargs["url"] + "system/interfaces/%s" % l2_port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

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

    int_data = get_interface(l2_port_name_percents, depth=1, selector="writable", **kwargs)

    int_data['vlan_mode'] = "access"
    int_data['vlan_tag'] = "/rest/v10.04/system/vlans/%s" % vlan_id
    int_data['routing'] = False

    target_url = kwargs["url"] + "system/interfaces/%s" % l2_port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting Port '%s' access VLAN to VLAN ID '%d' failed with status code %d: %s"
              % (l2_port_name, vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting Port '%s' access VLAN to VLAN ID '%d' succeeded"
              % (l2_port_name, vlan_id))
        return True


def _port_add_vlan_trunks(l2_port_name, vlan_trunk_ids={}, **kwargs):
    """
    Perform GET and PUT/POST calls to add specified VLANs to a trunk port. By default, this will also set the port to
    have 'no routing' and if there is not a native VLAN, will set the native VLAN to VLAN 1.

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_trunk_ids: Dictionary of VLANs to specify as allowed on the trunk port.  If empty, the interface will
        allow all VLANs on the trunk.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    l2_port_name_percents = common_ops._replace_special_characters(l2_port_name)

    trunk_list = {}
    for x in vlan_trunk_ids:
        x_keys = {str(x): "/rest/v10.04/system/vlans/%d" % x}
        trunk_list.update(x_keys)

    port_data = get_interface(l2_port_name, depth=1, selector="writable", **kwargs)

    if not port_data['vlan_tag']:
        port_data['vlan_tag'] = "/rest/v10.04/system/vlans/1"
    else:
        # Convert the dictionary to a URI string
        port_data['vlan_tag'] = common_ops._dictionary_to_string(port_data['vlan_tag'])

    if not port_data['vlan_mode']:
        port_data['vlan_mode'] = "native-untagged"
    port_data['routing'] = False

    if not trunk_list:
        port_data['vlan_trunks'] = []
    else:
        for key in trunk_list:
            if key not in port_data['vlan_trunks']:
                port_data['vlan_trunks'].append("/rest/v10.04/system/vlans/%s" % key)

    target_url = kwargs["url"] + "system/interfaces/%s" % l2_port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
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

    l2_port_name_percents = common_ops._replace_special_characters(l2_port_name)
    vlan_uri = "/rest/v10.04/system/vlans/%d" % vlan_id
    vlan_key = {str(vlan_id): vlan_uri}
    port_data = get_interface(l2_port_name_percents, depth=1, selector="writable", **kwargs)

    port_data['vlan_tag'] = vlan_uri
    port_data['routing'] = False
    port_data['vlan_mode'] = vlan_mode

    if (port_data['vlan_trunks']) and (vlan_key not in port_data['vlan_trunks']):
        port_data['vlan_trunks'].update(vlan_key)

    target_url = kwargs["url"] + "system/interfaces/%s" % l2_port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
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

    port_data = get_interface(l2_port_name, depth=1, selector="writable", **kwargs)

    if str(vlan_id) in port_data['vlan_trunks']:
        # remove vlan from 'vlan_trunks'
        port_data['vlan_trunks'].pop(str(vlan_id))

    target_url = kwargs["url"] + "system/interface/%s" % l2_port_name_percents
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


def add_port_to_lag(int_name, lag_id, **kwargs):
    """
    Perform GET and PUT calls to configure a Port as a LAG member, and also enable the port. For v1,
    also perform DELETE call to remove the Port table entry for the port.

    :param int_name: Alphanumeric name of the interface
    :param lag_id: Numeric ID of the LAG to which the port is to be added
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _add_port_to_lag_v1(int_name, lag_id, **kwargs)
    else:  # Updated else for when version is v10.04
        return _add_port_to_lag(int_name, lag_id, **kwargs)


def _add_port_to_lag_v1(int_name, lag_id, **kwargs):
    """
    Perform GET and PUT calls to configure a Port as a LAG member, and also enable the port.
    Also perform DELETE call to remove the Port table entry for the port.

    :param int_name: Alphanumeric name of the interface
    :param lag_id: Numeric ID of the LAG to which the port is to be added
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    int_name_percents = common_ops._replace_special_characters(int_name)

    int_data = get_interface(int_name, 0, "configuration", **kwargs)

    int_data['user_config'] = {"admin": "up"}
    int_data['other_config']['lacp-aggregation-key'] = lag_id

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Adding Interface '%s' to LAG '%d' "
              "failed with status code %d: %s" % (int_name, lag_id, response.status_code, response.text))
        success = False
    else:
        logging.info("SUCCESS: Adding Interface '%s' to LAG '%d' "
              "succeeded" % (int_name, lag_id))
        success = True
    # Delete Port Table entry for the port
    return success and port.delete_port(int_name_percents, **kwargs)


def _add_port_to_lag(int_name, lag_id, **kwargs):
    """
    Perform GET and PUT calls to configure a Port as a LAG member, and also enable the port

    :param int_name: Alphanumeric name of the interface
    :param lag_id: Numeric ID of the LAG to which the port is to be added
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    int_data = get_interface(int_name, 1, "writable", **kwargs)

    int_data['user_config'] = {"admin": "up"}
    int_data['other_config']['lacp-aggregation-key'] = lag_id

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Adding Interface '%s' to LAG '%d' "
              "failed with status code %d: %s" % (int_name, lag_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Adding Interface '%s' to LAG '%d' "
              "succeeded" % (int_name, lag_id))
        return True


def remove_port_from_lag(int_name, lag_id, **kwargs):
    """
    Perform GET and PUT calls to configure a Port as a LAG member, and also disable the port

    :param int_name: Alphanumeric name of the interface
    :param lag_id: Numeric ID of the LAG to which the port is to be added
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _remove_port_from_lag_v1(int_name, lag_id, **kwargs)
    else:  # Updated else for when version is v10.04
        return _remove_port_from_lag(int_name, lag_id, **kwargs)


def _remove_port_from_lag_v1(int_name, lag_id, **kwargs):
    """
    Perform GET and PUT calls to remove a Port from a LAG, and also disable the port

    :param int_name: Alphanumeric name of the interface
    :param lag_id: Numeric ID of the LAG to which the port is to be added
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    # Create Port Table entry for the port
    add_l2_interface(int_name, **kwargs)

    int_name_percents = common_ops._replace_special_characters(int_name)

    int_data = get_interface(int_name, 0, "configuration", **kwargs)

    int_data['user_config'] = {"admin": "down"}
    int_data['other_config'].pop('lacp-aggregation-key', None)

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing interface '%s' from LAG '%d' "
              "failed with status code %d: %s" % (int_name, lag_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing interface '%s' from LAG '%d' "
              "succeeded" % (int_name, lag_id))
        return True


def _remove_port_from_lag(int_name, lag_id, **kwargs):
    """
    Perform GET and PUT calls to remove a Port from a LAG, and also disable the port

    :param int_name: Alphanumeric name of the interface
    :param lag_id: Numeric ID of the LAG to which the port is to be added
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    int_data = get_interface(int_name, 1, "writable", **kwargs)

    int_data['user_config'] = {"admin": "down"}
    int_data['other_config'].pop('lacp-aggregation-key', None)

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing interface '%s' from LAG '%d' "
              "failed with status code %d: %s" % (int_name, lag_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing interface '%s' from LAG '%d' "
              "succeeded" % (int_name, lag_id))
        return True


def _clear_interface_acl(interface_name, acl_type, **kwargs):
    """
    Perform GET and PUT calls to clear an interface's ACL

    :param port_name: Alphanumeric name of the Port
    :param acl_type: Type of ACL: options are 'aclv4_out', 'aclv4_in', 'aclv6_in', or 'aclv6_out'
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if acl_type not in ['aclv4_out', 'aclv4_in', 'aclv6_in', 'aclv6_out']:
        raise Exception("ERROR: acl_type should be 'aclv4_out', 'aclv4_in', 'aclv6_in', or 'aclv6_out'")

    int_name_percents = common_ops._replace_special_characters(interface_name)

    interface_data = get_interface(interface_name, depth=1, selector="writable", **kwargs)

    if interface_name.startswith('lag'):
        if interface_data['interfaces']:
            interface_data['interfaces'] = common_ops._dictionary_to_list_values(interface_data['interfaces'])

    cfg_type = acl_type + '_cfg'
    cfg_version = acl_type + '_cfg_version'

    interface_data.pop(cfg_type, None)
    interface_data.pop(cfg_version, None)

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(interface_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing %s ACL on Interface '%s' failed with status code %d: %s"
              % (cfg_type, interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing %s ACL on Interface '%s' succeeded"
              % (cfg_type, interface_name))
        return True


def initialize_interface_entry(int_name, **kwargs):
    """
    Perform a PUT call on the interface to initialize it to it's default state.

    :param int_name: Alphanumeric name of the system interface
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    int_name_percents = common_ops._replace_special_characters(int_name)
    int_data = {}
    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Initializing interface '%s' failed with status code %d: %s"
                        % (int_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Initializing interface '%s' succeeded" % int_name)
        success = True
        # Remove all IPv6 entries for this interface
        ipv6_list = get_ipv6_addresses(int_name, **kwargs)
        if ipv6_list:
            for ipv6_address in ipv6_list:
                success = success and delete_ipv6_address(int_name, ipv6_address, **kwargs)
        return success


def initialize_interface(interface_name, **kwargs):
    """
    Perform a PUT call to the Interface Table or Port Table to initialize an interface to factory settings

    :param interface_name: Name of interface's reference entry in Interface table
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return port.initialize_port_entry(interface_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return initialize_interface_entry(interface_name, **kwargs)