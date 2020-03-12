# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops

import json
import logging


def get_dhcp_relay(vrf_name, port_name, **kwargs):
    """
    Perform a GET call to get DHCP data for an interface

    :param vrf_name: Alphanumeric name of VRF
    :param port_name: L3 interface's Port table entry name
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing DHCP Relay data for interface
    """
    if kwargs["url"].endswith("/v1/"):
        dhcp_relays = _get_dhcp_relay_v1(vrf_name, port_name, **kwargs)
    else:  # Updated else for when version is v10.04
        dhcp_relays = _get_dhcp_relay(vrf_name, port_name, **kwargs)
    return dhcp_relays


def _get_dhcp_relay_v1(vrf_name, port_name, **kwargs):
    """
    Perform a GET call to get DHCP data for an interface

    :param vrf_name: Alphanumeric name of VRF
    :param port_name: L3 interface's Port table entry name
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing DHCP Relay data for interface
    """
    payload = {"selector": "configuration"}

    target_url = kwargs["url"] + "system/dhcp_relays/%s/%s" % (vrf_name, port_name)
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting IPv4 DHCP helper(s) for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting IPv4 DHCP helper(s) for Port '%s' succeeded" % port_name)

    return response.json()


def _get_dhcp_relay(vrf_name, port_name, **kwargs):
    """
    Perform a GET call to get DHCP data for an interface

    :param vrf_name: Alphanumeric name of VRF
    :param port_name: L3 interface's Port table entry name
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing DHCP Relay data for interface
    """
    payload = {"selector": "writable"}

    target_url = kwargs["url"] + "system/dhcp_relays/%s,%s" % (vrf_name, port_name)
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting IPv4 DHCP helper(s) for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting IPv4 DHCP helper(s) for Port '%s' succeeded" % port_name)

    return response.json()


def get_all_dhcp_relays(**kwargs):
    """
    Perform a GET call to get a list (or dictionary) of all entries in DHCP Relays table

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List/dict of all DHCP helpers in the table
    """
    target_url = kwargs["url"] + "system/dhcp_relays"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list/dict of all DHCP Relay table entries failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list/dict of all DHCP Relay table entries succeeded")

    dhcp_helpers = response.json()
    return dhcp_helpers


def add_dhcp_relays(port_name, vrf_name, ipv4_helper_addresses, **kwargs):
    """
    Perform a POST call to add IPv4 DHCP helper(s) for an L3 interface. If there are already IPv4 helpers, the new
    helpers are added in addition to the already existing helpers.

    :param port_name: Alphanumeric name of the Port
    :param vrf_name: Alphanumeric name of the VRF
    :param ipv4_helper_addresses: List of IPv4 addresses to add as DHCP helpers
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _add_dhcp_relays_v1(port_name, vrf_name, ipv4_helper_addresses, **kwargs)
    else:  # Updated else for when version is v10.04
        return _add_dhcp_relays(port_name, vrf_name, ipv4_helper_addresses, **kwargs)


def _add_dhcp_relays_v1(port_name, vrf_name, ipv4_helper_addresses, **kwargs):
    """
    Perform a POST call to add IPv4 DHCP helper(s) for an L3 interface. If there are already IPv4 helpers, the new
    helpers are added in addition to the already existing helpers.

    :param port_name: Alphanumeric name of the Port
    :param vrf_name: Alphanumeric name of the VRF
    :param ipv4_helper_addresses: List of IPv4 addresses to add as DHCP helpers
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    dhcp_relays_list = get_all_dhcp_relays(**kwargs)

    if "/rest/v1/system/dhcp_relays/%s/%s" % (vrf_name, port_name) not in dhcp_relays_list:
        dhcp_relays = {
                    "port": kwargs["url"] + "system/ports/%s" % port_name,
                    "vrf": kwargs["url"] + "system/vrfs/%s" % vrf_name,
                    "ipv4_ucast_server": ipv4_helper_addresses
                    }

        target_url = kwargs["url"] + "system/dhcp_relays"
        post_data = json.dumps(dhcp_relays, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding IPv4 DHCP helpers %s to SVI Port '%s' failed with status code %d: %s" %
                  (repr(ipv4_helper_addresses), port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding IPv4 DHCP helpers '%s' to SVI Port '%s' succeeded" %
                  (repr(ipv4_helper_addresses), port_name))
            return True

    else:
        dhcp_data = get_dhcp_relay(vrf_name, port_name, **kwargs)

        dhcp_data['ipv4_ucast_server'] = common_ops._list_remove_duplicates(
            dhcp_data['ipv4_ucast_server'] + ipv4_helper_addresses)

        if len(dhcp_data['ipv4_ucast_server']) > 8:
            raise Exception("Can't have more than 8 IPv4 DHCP helpers per interface!")

        dhcp_data.pop('port', None)  # Must remove this item from json since it can't be modified
        dhcp_data.pop('vrf', None)  # Must remove this item from json since it can't be modified

        target_url = kwargs["url"] + "system/dhcp_relays/%s/%s" % (vrf_name, port_name)
        put_data = json.dumps(dhcp_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Adding IPv4 DHCP helpers %s to SVI Port '%s' failed with status code %d: %s" %
                  (repr(ipv4_helper_addresses), port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding IPv4 DHCP helpers '%s' to SVI Port '%s' succeeded" %
                  (repr(ipv4_helper_addresses), port_name))
            return True


def _add_dhcp_relays(port_name, vrf_name, ipv4_helper_addresses, **kwargs):
    """
    Perform a POST call to add IPv4 DHCP helper(s) for an L3 interface. If there are already IPv4 helpers, the new
    helpers are added in addition to the already existing helpers.

    :param port_name: Alphanumeric name of the Port
    :param vrf_name: Alphanumeric name of the VRF
    :param ipv4_helper_addresses: List of IPv4 addresses to add as DHCP helpers
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    dhcp_relays_dict = get_all_dhcp_relays(**kwargs)

    if "%s,%s" % (vrf_name, port_name) not in dhcp_relays_dict:
        dhcp_relays = {
                    "port": "/rest/v10.04/system/interfaces/%s" % port_name,
                    "vrf": "/rest/v10.04/system/vrfs/%s" % vrf_name,
                    "ipv4_ucast_server": ipv4_helper_addresses
                    }

        target_url = kwargs["url"] + "system/dhcp_relays"
        post_data = json.dumps(dhcp_relays, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding IPv4 DHCP helpers %s to SVI Port '%s' failed with status code %d: %s" %
                  (repr(ipv4_helper_addresses), port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding IPv4 DHCP helpers '%s' to SVI Port '%s' succeeded" %
                  (repr(ipv4_helper_addresses), port_name))
            return True
    else:
        dhcp_data = get_dhcp_relay(vrf_name, port_name, **kwargs)

        dhcp_data['ipv4_ucast_server'] = common_ops._list_remove_duplicates(
            dhcp_data['ipv4_ucast_server'] + ipv4_helper_addresses)

        if len(dhcp_data['ipv4_ucast_server']) > 8:
            raise Exception("Can't have more than 8 IPv4 DHCP helpers per interface!")

        dhcp_data.pop('dhcp_relay_v6_mcast_servers', None)  # Must remove this item from json since it can't be modified

        target_url = kwargs["url"] + "system/dhcp_relays/%s,%s" % (vrf_name, port_name)
        put_data = json.dumps(dhcp_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Adding IPv4 DHCP helpers %s to SVI Port '%s' failed with status code %d: %s" %
                  (repr(ipv4_helper_addresses), port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding IPv4 DHCP helpers '%s' to SVI Port '%s' succeeded" %
                  (repr(ipv4_helper_addresses), port_name))
            return True


def delete_dhcp_relays(port_name, vrf_name="default", **kwargs):
    """
    Perform a DELETE call to delete all the IPv4 DHCP helper(s) for an L3 interface.

    :param port_name: Alphanumeric name of the Port
    :param vrf_name: Alphanumeric name of the VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_dhcp_relays_v1(port_name, vrf_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_dhcp_relays(port_name, vrf_name, **kwargs)


def _delete_dhcp_relays_v1(port_name, vrf_name="default", **kwargs):
    """
    Perform a DELETE call to delete all the IPv4 DHCP helper(s) for an L3 interface.

    :param port_name: Alphanumeric name of the Port
    :param vrf_name: Alphanumeric name of the VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    dhcp_helpers_list = get_all_dhcp_relays(**kwargs)

    if "/rest/v1/system/dhcp_relays/%s/%s" % (vrf_name, port_name) in dhcp_helpers_list:

        target_url = kwargs["url"] + "system/dhcp_relays/%s/%s" % (vrf_name, port_name)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting all DHCP relays from interface Port '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting all DHCP relays from interface Port '%s' succeeded" % port_name)
            return True
    else:
        logging.info("SUCCESS: No need to delete DHCP relays from SVI Port '%s' since they don't exist"
              % port_name)
        return True


def _delete_dhcp_relays(port_name, vrf_name="default", **kwargs):
    """
    Perform a DELETE call to delete all the IPv4 DHCP helper(s) for an L3 interface.

    :param port_name: Alphanumeric name of the Port
    :param vrf_name: Alphanumeric name of the VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    dhcp_helpers_dict = get_all_dhcp_relays(**kwargs)

    if "%s,%s" % (vrf_name, port_name) in dhcp_helpers_dict:

        target_url = kwargs["url"] + "system/dhcp_relays/%s,%s" % (vrf_name, port_name)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting all DHCP relays from interface Port '%s' failed with status code %d: %s"
                  % (port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting all DHCP relays from interface Port '%s' succeeded" % port_name)
            return True
    else:
        logging.info("SUCCESS: No need to delete DHCP relays from SVI Port '%s' since they don't exist"
              % port_name)
        return True
