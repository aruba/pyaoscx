# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0


from pyaoscx import common_ops, port, interface

import json
import logging


def get_all_lldp_neighbors(**kwargs):
    """
    Perform a GET call to get a list of all entries in the lldp_neighbors table.  This is currently only supported in
    v1, so even a v10.04 or later AOS-CX device will use the v1 REST call.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all lldp_neighors in the table
    """
    target_url = kwargs["url"] + "system/interfaces/*/lldp_neighbors"

    if not kwargs["url"].endswith("/v1/"):
        target_url = target_url.replace('v10.04', 'v1')


    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all lldp_neighbors entries failed with status code %d: %s"
              % (response.status_code, response.text))
        lldp_neighbors_list = []
    else:
        logging.info("SUCCESS: Getting list of all lldp_neighbors entries succeeded")
        lldp_neighbors_list = response.json()

    return lldp_neighbors_list


def get_interface_lldp_neighbor_mac_port(int_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve lldp_neighbor MAC and port data for an Interface.  This will return a list if using
    v1, or a dictionary if using v10.04 or later.

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.  If running v10.04 or later, an additional option 'writable' is included.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List/dictionary containing lldp_neighbor MAC and port data
    """
    if kwargs["url"].endswith("/v1/"):
        return _get_interface_lldp_neighbor_mac_port_v1(int_name, depth, selector, **kwargs)
    else:   # Updated else for when version is v10.04
        return _get_interface_lldp_neighbor_mac_port(int_name, depth, selector, **kwargs)


def _get_interface_lldp_neighbor_mac_port_v1(int_name, depth=0, selector=None, **kwargs):
    """
   Perform a GET call to retrieve lldp_neighbor MAC and port data for an Interface

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List containing lldp_neighbor MAC and port data
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    if selector not in ['configuration', 'status', 'statistics', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', or 'statistics'")

    target_url = kwargs["url"] + "system/interfaces/%s/lldp_neighbors" % int_name_percents
    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=3)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting lldp_neighbor MAC and port data for interface '%s' "
                        "failed with status code %d: %s" % (int_name, response.status_code, response.text))
        result = {}
    else:
        logging.info("SUCCESS: Getting lldp_neighbor MAC and port data for interface '%s' succeeded" % int_name)
        result = response.json()

    return result


def _get_interface_lldp_neighbor_mac_port(int_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve lldp_neighbor MAC and port data for an Interface
    Note: Depth removed due to inconsistent behavior
    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', 'statistics' or 'writable'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing lldp_neighbor MAC and port data
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    if selector not in ['configuration', 'status', 'statistics', 'writable', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', 'statistics', or 'writable'")

    target_url = kwargs["url"] + "system/interfaces/%s/lldp_neighbors" % int_name_percents
    payload = {
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=3)
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting lldp_neighbor MAC and port data for interface '%s' "
                        "failed with status code %d: %s" % (int_name, response.status_code, response.text))
        result = {}
    else:
        logging.info("SUCCESS: Getting lldp_neighbor MAC and port data for interface '%s' succeeded" % int_name)
        result = response.json()

    return result


def get_lldp_neighbor_info(int_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieve LLDP neighbor info for an Interface

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.  If running v10.04 or later, an additional option 'writable' is included.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing LLDP neighbor info
    """
    if kwargs["url"].endswith("/v1/"):
        return _get_lldp_neighbor_info_v1(int_name, depth, selector, **kwargs)
    else:   # Updated else for when version is v10.04
        return _get_lldp_neighbor_info(int_name, depth, selector, **kwargs)


def _get_lldp_neighbor_info_v1(int_name, depth=0, selector=None, **kwargs):
    """
   Perform a GET call to retrieve LLDP neighbor info for an Interface

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing LLDP neighbor info
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    if selector not in ['configuration', 'status', 'statistics', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', or 'statistics'")

    mac_port_info = get_interface_lldp_neighbor_mac_port(int_name, **kwargs)
    port_info = mac_port_info[0][mac_port_info[0].rfind('/')+1:]  # Retrieves port from end of URI
    mac_port_info[0] = mac_port_info[0][:mac_port_info[0].rfind('/')]  # Substring to remove the port from URI
    mac_info = mac_port_info[0][mac_port_info[0].rfind('/')+1:]  # Retrieves MAC from end of URI

    target_url = kwargs["url"] + "system/interfaces/%s/lldp_neighbors/%s/%s" % (int_name_percents, mac_info, port_info)

    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=3)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting LLDP Neighbor information for interface '%s' failed with status code %d: %s"
                        % (int_name, response.status_code, response.text))
        result = {}
    else:
        logging.info("SUCCESS: Getting LLDP Neighbor information for interface '%s' succeeded" % int_name)
        result = response.json()

    return result


def _get_lldp_neighbor_info(int_name, depth=0, selector=None, **kwargs):
    """
    Perform a GET call to retrieveLLDP neighbor info for an Interface

    :param int_name: Alphanumeric name of the interface
    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', 'statistics' or 'writable'.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing LLDP neighbor info
    """
    int_name_percents = common_ops._replace_special_characters(int_name)

    if selector not in ['configuration', 'status', 'statistics', 'writable', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', 'statistics', or 'writable'")

    mac_port_info = get_interface_lldp_neighbor_mac_port(int_name, **kwargs)
    unpacked_info = list(mac_port_info)  # Unpacking dictionary to list
    port_info = unpacked_info[0][unpacked_info[0].rfind(',')+1:]  # Retrieves port from end of URI
    unpacked_info[0] = unpacked_info[0][:unpacked_info[0].rfind(',')]  # Substring to remove the port from URI
    mac_info = unpacked_info[0][unpacked_info[0].rfind(',')+1:]  # Retrieves MAC from end of URI

    target_url = kwargs["url"] + "system/interfaces/%s/lldp_neighbors/%s,%s" % (int_name_percents, mac_info, port_info)

    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=3)
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting LLDP Neighbor information for interface '%s' failed with status code %d: %s"
                        % (int_name, response.status_code, response.text))
        result = {}
    else:
        logging.info("SUCCESS: Getting LLDP Neighbor information for interface '%s' succeeded" % int_name)
        result = response.json()

    return result

