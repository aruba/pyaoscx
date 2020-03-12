# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops
from pyaoscx import system
from pyaoscx import interface
from pyaoscx import port
from pyaoscx import vrf

import json
import logging


def create_radius_host_config(vrf_name, host, default_group_priority=1, groups=[], passkey=None, **kwargs):
    """
    Perform a POST call to set the RADIUS server host.

    :param vrf_name: Alphanumeric name of VRF through which the RADIUS server is reachable
    :param host: IPv4/IPv6 address or FQDN of the RADIUS server
    :param default_group_priority: Integer priority within the default RADIUS server group. All RADIUS servers will be
        added to this default group. The priority must be at least 1, and defaults to 1 if not specified.
    :param groups: Optional list of additional RADIUS server groups to which this server will be added. Defaults to
        empty list if not specified.
    :param passkey: Optional passkey to be used between RADIUS client and server for authentication.
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_radius_host_config_v1(vrf_name, host, default_group_priority, groups, passkey, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_radius_host_config(vrf_name, host, default_group_priority, groups, passkey, **kwargs)


def _create_radius_host_config_v1(vrf_name, host, default_group_priority=1, groups=[], passkey=None, **kwargs):
    """
    Perform a POST call to set the RADIUS server host.

    :param vrf_name: Alphanumeric name of VRF through which the RADIUS server is reachable
    :param host: IPv4/IPv6 address or FQDN of the RADIUS server
    :param default_group_priority: Integer priority within the default RADIUS server group. All RADIUS servers will be
        added to this default group. The priority must be at least 1, and defaults to 1 if not specified.
    :param groups: Optional list of additional RADIUS server groups to which this server will be added. Defaults to
        empty list if not specified.
    :param passkey: Optional passkey to be used between RADIUS client and server for authentication.
    :return: True if successful, False otherwise
    """

    if default_group_priority < 1:
        raise Exception("Default group priority must be at least 1!")

    radius_server_data = {"address": host,
                          "vrf": "/rest/v1/system/vrfs/%s" % vrf_name,
                          "default_group_priority": default_group_priority,
                          "group": ["/rest/v1/system/aaa_server_groups/radius"] + ["/rest/v1/system/aaa_server_groups/%s" % group for group in groups],
                          }

    if passkey is not None:
        radius_server_data['passkey'] = passkey

    target_url = kwargs["url"] + "system/vrfs/default/radius_servers"
    post_data = json.dumps(radius_server_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Configuring RADIUS server host to '%s' failed with status code %d: %s"
              % (host, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring RADIUS server host to '%s' succeeded" % host)
        return True


def _create_radius_host_config(vrf_name, host, default_group_priority=1, groups=[], passkey=None, **kwargs):
    """
    Perform a POST call to set the RADIUS server host.

    :param vrf_name: Alphanumeric name of VRF through which the RADIUS server is reachable
    :param host: IPv4/IPv6 address or FQDN of the RADIUS server
    :param default_group_priority: Integer priority within the default RADIUS server group. All RADIUS servers will be
        added to this default group. The priority must be at least 1, and defaults to 1 if not specified.
    :param groups: Optional list of additional RADIUS server groups to which this server will be added. Defaults to
        empty list if not specified.
    :param passkey: Optional passkey to be used between RADIUS client and server for authentication.
    :return: True if successful, False otherwise
    """

    if default_group_priority < 1:
        raise Exception("Default group priority must be at least 1!")

    radius_server_data = {"address": host,
                          "vrf": "/rest/v10.04/system/vrfs/%s" % vrf_name,
                          "default_group_priority": default_group_priority,
                          "group": ["/rest/v10.04/system/aaa_server_groups/radius"] + [
                              "/rest/v10.04/system/aaa_server_groups/%s" % group for group in groups],
                          }

    if passkey is not None:
        radius_server_data['passkey'] = passkey

    target_url = kwargs["url"] + "system/vrfs/default/radius_servers"
    post_data = json.dumps(radius_server_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Configuring RADIUS server host to '%s' failed with status code %d: %s"
              % (host, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring RADIUS server host to '%s' succeeded" % host)
        return True


def delete_radius_host_config(vrf_name, host, udp_port=1812, **kwargs):
    """
    Perform a DELETE call to remove the RADIUS server host.

    :param vrf_name: Alphanumeric name of VRF through which the RADIUS server is reachable
    :param host: IPv4/IPv6 address or FQDN of the RADIUS server
    :param udp_port: UDP port number used for authentication. Defaults to 1812 if not specified.
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_radius_host_config_v1(vrf_name, host, udp_port, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_radius_host_config(vrf_name, host, udp_port, **kwargs)


def _delete_radius_host_config_v1(vrf_name, host, udp_port=1812, **kwargs):
    """
    Perform a DELETE call to remove the RADIUS server host.

    :param vrf_name: Alphanumeric name of VRF through which the RADIUS server is reachable
    :param host: IPv4/IPv6 address or FQDN of the RADIUS server
    :param udp_port: UDP port number used for authentication. Defaults to 1812 if not specified.
    :return: True if successful, False otherwise
    """

    target_url = kwargs["url"] + "system/vrfs/%s/radius_servers/%s/%d" % (vrf_name, host, udp_port)

    response = kwargs["s"].delete(target_url, verify=False)

    if not common_ops._response_ok(response, "DELETE"):
        logging.warning("FAIL: Removing RADIUS server host failed with status code %d: %s" % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing RADIUS server host succeeded")
        return True


def _delete_radius_host_config(vrf_name, host, udp_port=1812, **kwargs):
    """
    Perform a DELETE call to remove the RADIUS server host.

    :param vrf_name: Alphanumeric name of VRF through which the RADIUS server is reachable
    :param host: IPv4/IPv6 address or FQDN of the RADIUS server
    :param udp_port: UDP port number used for authentication. Defaults to 1812 if not specified.
    :return: True if successful, False otherwise
    """

    target_url = kwargs["url"] + "system/vrfs/%s/radius_servers/%s,%d" % (vrf_name, host, udp_port)

    response = kwargs["s"].delete(target_url, verify=False)

    if not common_ops._response_ok(response, "DELETE"):
        logging.warning("FAIL: Removing RADIUS server host failed with status code %d: %s" % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing RADIUS server host succeeded")
        return True


def enable_disable_dot1x_globally(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable 802.1X globally

    :param enable: True if 802.1x to be enabled globally, False if 802.1x to be disabled globally. Defaults to True
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _enable_disable_dot1x_globally_v1(enable, **kwargs)
    else:  # Updated else for when version is v10.04
        return _enable_disable_dot1x_globally(enable, **kwargs)


def _enable_disable_dot1x_globally_v1(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable 802.1X globally

    :param enable: True if 802.1x to be enabled globally, False if 802.1x to be disabled globally. Defaults to True
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data['aaa']['dot1x_auth_enable'] = enable

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting 802.1x authentication enabled globally to '%s' failed with status code %d: %s"
              % (enable, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting 802.1x authentication enabled globally to '%s' succeeded" % enable)
        return True


def _enable_disable_dot1x_globally(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable 802.1X globally

    :param enable: True if 802.1x to be enabled globally, False if 802.1x to be disabled globally. Defaults to True
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data['aaa']['dot1x_auth_enable'] = enable

    system_data.pop('syslog_remotes', None)
    system_data.pop('vrfs', None)
    system_data.pop('mirrors', None)
    system_data.pop('all_user_copp_policies', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=2)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting 802.1x authentication enabled globally to '%s' failed with status code %d: %s"
              % (enable, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting 802.1x authentication enabled globally to '%s' succeeded" % enable)
        return True


def configure_dot1x_interface(port_name, auth_enable=True, cached_reauth_enable=True, cached_reauth_period=None,
                              discovery_period=None, eapol_timeout=None, max_requests=None, max_retries=None,
                              quiet_period=None, reauth_enable=True, reauth_period=None, **kwargs):
    """
    Perform a POST call to set 802.1x authentication on a port.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param auth_enable: True if 802.1x is to be enabled on the port, false otherwise. Defaults to True if not specified.
    :param cached_reauth_enable: True if cached reauthentication is to be enabled on the port, false otherwise.
        Defaults to True if not specified.
    :param cached_reauth_period: Time in seconds during which cached reauthentication is allowed on the port.
        Defaults to nothing if not specified.
    :param discovery_period: Time period(in seconds) to wait before an EAPOL request identity frame re-transmission on
        an 802.1X enabled port with no authenticated client. Applicable for 802.1X only. Defaults to nothing if not
        specified.
    :param eapol_timeout: Time period(in seconds) to wait for a response from a client before retransmitting an
        EAPOL PDU. If the value is not set the time period is calculated as per RFC 2988. Defaults to nothing if not
        specified.
    :param max_requests: Number of EAPOL requests to supplicant before authentication fails. Applicable for 802.1X only.
        Defaults to nothing if not specified.
    :param max_retries: Number of authentication attempts before authentication fails. Defaults to nothing if not
        specified.
    :param quiet_period: Time period(in seconds) to wait before processing an authentication request from a client
        that failed authentication. Defaults to nothing if not specified.
    :param reauth_enable: True if periodic reauthentication is to be enabled on the port, false otherwise. Defaults to
        True if not specified.
    :param reauth_period: Time period(in seconds) to enforce periodic re-authentication of clients. Defaults to nothing
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _configure_dot1x_interface_v1(port_name, auth_enable, cached_reauth_enable, cached_reauth_period,
                                      discovery_period, eapol_timeout, max_requests, max_retries,
                                      quiet_period, reauth_enable, reauth_period, **kwargs)
    else:  # Updated else for when version is v10.04
        return _configure_dot1x_interface(port_name, auth_enable, cached_reauth_enable, cached_reauth_period,
                                   discovery_period, eapol_timeout, max_requests, max_retries,
                                   quiet_period, reauth_enable, reauth_period, **kwargs)


def _configure_dot1x_interface_v1(port_name, auth_enable=True, cached_reauth_enable=True, cached_reauth_period=None,
                                  discovery_period=None, eapol_timeout=None, max_requests=None, max_retries=None,
                                  quiet_period=None, reauth_enable=True, reauth_period=None, **kwargs):
    """
    Perform a POST call to set 802.1x authentication on a port.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param auth_enable: True if 802.1x is to be enabled on the port, false otherwise. Defaults to True if not specified.
    :param cached_reauth_enable: True if cached reauthentication is to be enabled on the port, false otherwise.
        Defaults to True if not specified.
    :param cached_reauth_period: Time in seconds during which cached reauthentication is allowed on the port.
        Defaults to nothing if not specified.
    :param discovery_period: Time period(in seconds) to wait before an EAPOL request identity frame re-transmission on
        an 802.1X enabled port with no authenticated client. Applicable for 802.1X only. Defaults to nothing if not
        specified.
    :param eapol_timeout: Time period(in seconds) to wait for a response from a client before retransmitting an
        EAPOL PDU. If the value is not set the time period is calculated as per RFC 2988. Defaults to nothing if not
        specified.
    :param max_requests: Number of EAPOL requests to supplicant before authentication fails. Applicable for 802.1X only.
        Defaults to nothing if not specified.
    :param max_retries: Number of authentication attempts before authentication fails. Defaults to nothing if not
        specified.
    :param quiet_period: Time period(in seconds) to wait before processing an authentication request from a client
        that failed authentication. Defaults to nothing if not specified.
    :param reauth_enable: True if periodic reauthentication is to be enabled on the port, false otherwise. Defaults to
        True if not specified.
    :param reauth_period: Time period(in seconds) to enforce periodic re-authentication of clients. Defaults to nothing
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_access_auth_data = {
        "authentication_method": "dot1x",
        "auth_enable": auth_enable,
        "cached_reauth_enable": cached_reauth_enable,
        "reauth_enable": reauth_enable
    }

    if cached_reauth_period is not None:
        port_access_auth_data['cached_reauth_period'] = cached_reauth_period

    if discovery_period is not None:
        port_access_auth_data['discovery_period'] = discovery_period

    if eapol_timeout is not None:
        port_access_auth_data['eapol_timeout'] = eapol_timeout

    if max_requests is not None:
        port_access_auth_data['max_requests'] = max_requests

    if max_retries is not None:
        port_access_auth_data['max_retries'] = max_retries

    if quiet_period is not None:
        port_access_auth_data['quiet_period'] = quiet_period

    if reauth_period is not None:
        port_access_auth_data['reauth_period'] = reauth_period

    target_url = kwargs["url"] + "system/ports/%s/port_access_auth_configurations" % port_name_percents
    post_data = json.dumps(port_access_auth_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Configuring 802.1x for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring 802.1x for Port '%s' succeeded" % port_name)
        return True


def _configure_dot1x_interface(port_name, auth_enable=True, cached_reauth_enable=True, cached_reauth_period=None,
                               discovery_period=None, eapol_timeout=None, max_requests=None, max_retries=None,
                               quiet_period=None, reauth_enable=True, reauth_period=None, **kwargs):
    """
    Perform a POST call to set 802.1x authentication on a port.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param auth_enable: True if 802.1x is to be enabled on the port, false otherwise. Defaults to True if not specified.
    :param cached_reauth_enable: True if cached reauthentication is to be enabled on the port, false otherwise.
        Defaults to True if not specified.
    :param cached_reauth_period: Time in seconds during which cached reauthentication is allowed on the port.
        Defaults to nothing if not specified.
    :param discovery_period: Time period(in seconds) to wait before an EAPOL request identity frame re-transmission on
        an 802.1X enabled port with no authenticated client. Applicable for 802.1X only. Defaults to nothing if not
        specified.
    :param eapol_timeout: Time period(in seconds) to wait for a response from a client before retransmitting an
        EAPOL PDU. If the value is not set the time period is calculated as per RFC 2988. Defaults to nothing if not
        specified.
    :param max_requests: Number of EAPOL requests to supplicant before authentication fails. Applicable for 802.1X only.
        Defaults to nothing if not specified.
    :param max_retries: Number of authentication attempts before authentication fails. Defaults to nothing if not
        specified.
    :param quiet_period: Time period(in seconds) to wait before processing an authentication request from a client
        that failed authentication. Defaults to nothing if not specified.
    :param reauth_enable: True if periodic reauthentication is to be enabled on the port, false otherwise. Defaults to
        True if not specified.
    :param reauth_period: Time period(in seconds) to enforce periodic re-authentication of clients. Defaults to nothing
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_access_auth_data = {
        "authentication_method": "802.1x",
        "auth_enable": auth_enable,
        "cached_reauth_enable": cached_reauth_enable,
        "reauth_enable": reauth_enable
    }

    if cached_reauth_period is not None:
        port_access_auth_data['cached_reauth_period'] = cached_reauth_period

    if discovery_period is not None:
        port_access_auth_data['discovery_period'] = discovery_period

    if eapol_timeout is not None:
        port_access_auth_data['eapol_timeout'] = eapol_timeout

    if max_requests is not None:
        port_access_auth_data['max_requests'] = max_requests

    if max_retries is not None:
        port_access_auth_data['max_retries'] = max_retries

    if quiet_period is not None:
        port_access_auth_data['quiet_period'] = quiet_period

    if reauth_period is not None:
        port_access_auth_data['reauth_period'] = reauth_period

    target_url = kwargs["url"] + "system/interfaces/%s/port_access_auth_configurations" % port_name_percents
    post_data = json.dumps(port_access_auth_data)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Configuring 802.1x for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring 802.1x for Port '%s' succeeded" % port_name)
        return True


def enable_disable_mac_auth_globally(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable MAC authentication globally

    :param enable: True if MAC authentication to be enabled globally, False if MAC authentication to be disabled globally. Defaults to True if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _enable_disable_mac_auth_globally_v1(enable, **kwargs)
    else:  # Updated else for when version is v10.04
        return _enable_disable_mac_auth_globally(enable, **kwargs)


def _enable_disable_mac_auth_globally_v1(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable MAC authentication globally

    :param enable: True if MAC authentication to be enabled globally, False if MAC authentication to be disabled globally. Defaults to True if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data['aaa']['mac_auth_enable'] = enable

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting MAC authentication enabled globally to '%s' failed with status code %d: %s"
              % (enable, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting MAC authentication enabled globally to '%s' succeeded" % enable)
        return True


def _enable_disable_mac_auth_globally(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable MAC authentication globally

    :param enable: True if MAC authentication to be enabled globally, False if MAC authentication to be disabled globally. Defaults to True if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data['aaa']['mac_auth_enable'] = enable

    system_data.pop('syslog_remotes', None)
    system_data.pop('vrfs', None)
    system_data.pop('mirrors', None)
    system_data.pop('all_user_copp_policies', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting MAC authentication enabled globally to '%s' failed with status code %d: %s"
              % (enable, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting MAC authentication enabled globally to '%s' succeeded" % enable)
        return True


def configure_mac_auth_interface(port_name, auth_enable=True, cached_reauth_enable=True, cached_reauth_period=None,
                                 discovery_period=None, max_retries=None,
                                 quiet_period=None, reauth_enable=True, reauth_period=None, **kwargs):
    """
    Perform a POST call to set MAC authentication on a port.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param auth_enable: True if authentication is to be enabled on the port, false otherwise. Defaults to True if not
        specified.
    :param cached_reauth_enable: True if cached reauthentication is to be enabled on the port, false otherwise.
        Defaults to True if not specified.
    :param cached_reauth_period: Time in seconds during which cached reauthentication is allowed on the port. Defaults
        to nothing if not specified.
    :param discovery_period: Time period(in seconds) to wait before an EAPOL request identity frame re-transmission on
        an 802.1X enabled port with no authenticated client. Applicable for 802.1X only. Defaults to nothing if not
        specified.
    :param max_retries: Number of authentication attempts before authentication fails. Defaults to nothing if not
        specified.
    :param quiet_period: Time period(in seconds) to wait before processing an authentication request from a client
        that failed authentication. Defaults to nothing if not specified.
    :param reauth_enable: True if periodic reauthentication is to be enabled on the port, false otherwise. Defaults to
        True if not specified.
    :param reauth_period: Time period(in seconds) to enforce periodic re-authentication of clients. Defaults to nothing
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _configure_mac_auth_interface_v1(port_name, auth_enable, cached_reauth_enable, cached_reauth_period,
                                         discovery_period, max_retries,
                                         quiet_period, reauth_enable, reauth_period, **kwargs)
    else:  # Updated else for when version is v10.04
        return _configure_mac_auth_interface(port_name, auth_enable, cached_reauth_enable, cached_reauth_period,
                                      discovery_period, max_retries,
                                      quiet_period, reauth_enable, reauth_period, **kwargs)


def _configure_mac_auth_interface_v1(port_name, auth_enable=True, cached_reauth_enable=True, cached_reauth_period=None,
                                     discovery_period=None, max_retries=None,
                                     quiet_period=None, reauth_enable=True, reauth_period=None, **kwargs):
    """
    Perform a POST call to set MAC authentication on a port.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param auth_enable: True if authentication is to be enabled on the port, false otherwise. Defaults to True if not
        specified.
    :param cached_reauth_enable: True if cached reauthentication is to be enabled on the port, false otherwise.
        Defaults to True if not specified.
    :param cached_reauth_period: Time in seconds during which cached reauthentication is allowed on the port. Defaults
        to nothing if not specified.
    :param discovery_period: Time period(in seconds) to wait before an EAPOL request identity frame re-transmission on
        an 802.1X enabled port with no authenticated client. Applicable for 802.1X only. Defaults to nothing if not
        specified.
    :param max_retries: Number of authentication attempts before authentication fails. Defaults to nothing if not
        specified.
    :param quiet_period: Time period(in seconds) to wait before processing an authentication request from a client
        that failed authentication. Defaults to nothing if not specified.
    :param reauth_enable: True if periodic reauthentication is to be enabled on the port, false otherwise. Defaults to
        True if not specified.
    :param reauth_period: Time period(in seconds) to enforce periodic re-authentication of clients. Defaults to nothing
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_access_auth_data = {
        "authentication_method": "mac-auth",
        "auth_enable": auth_enable,
        "cached_reauth_enable": cached_reauth_enable,
        "reauth_enable": reauth_enable
    }

    if cached_reauth_period is not None:
        port_access_auth_data['cached_reauth_period'] = cached_reauth_period

    if discovery_period is not None:
        port_access_auth_data['discovery_period'] = discovery_period

    if max_retries is not None:
        port_access_auth_data['max_retries'] = max_retries

    if quiet_period is not None:
        port_access_auth_data['quiet_period'] = quiet_period

    if reauth_period is not None:
        port_access_auth_data['reauth_period'] = reauth_period

    target_url = kwargs["url"] + "system/ports/%s/port_access_auth_configurations" % port_name_percents
    post_data = json.dumps(port_access_auth_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Configuring MAC authentication for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring MAC authentication for Port '%s' succeeded" % port_name)
        return True


def _configure_mac_auth_interface(port_name, auth_enable=True, cached_reauth_enable=True, cached_reauth_period=None,
                                  discovery_period=None, max_retries=None,
                                  quiet_period=None, reauth_enable=True, reauth_period=None, **kwargs):
    """
    Perform a POST call to set MAC authentication on a port.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param auth_enable: True if authentication is to be enabled on the port, false otherwise. Defaults to True if not
        specified.
    :param cached_reauth_enable: True if cached reauthentication is to be enabled on the port, false otherwise.
        Defaults to True if not specified.
    :param cached_reauth_period: Time in seconds during which cached reauthentication is allowed on the port. Defaults
        to nothing if not specified.
    :param discovery_period: Time period(in seconds) to wait before an EAPOL request identity frame re-transmission on
        an 802.1X enabled port with no authenticated client. Applicable for 802.1X only. Defaults to nothing if not
        specified.
    :param max_retries: Number of authentication attempts before authentication fails. Defaults to nothing if not
        specified.
    :param quiet_period: Time period(in seconds) to wait before processing an authentication request from a client
        that failed authentication. Defaults to nothing if not specified.
    :param reauth_enable: True if periodic reauthentication is to be enabled on the port, false otherwise. Defaults to
        True if not specified.
    :param reauth_period: Time period(in seconds) to enforce periodic re-authentication of clients. Defaults to nothing
        if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_access_auth_data = {
        "authentication_method": "mac-auth",
        "auth_enable": auth_enable,
        "cached_reauth_enable": cached_reauth_enable,
        "reauth_enable": reauth_enable
    }

    if cached_reauth_period is not None:
        port_access_auth_data['cached_reauth_period'] = cached_reauth_period

    if discovery_period is not None:
        port_access_auth_data['discovery_period'] = discovery_period

    if max_retries is not None:
        port_access_auth_data['max_retries'] = max_retries

    if quiet_period is not None:
        port_access_auth_data['quiet_period'] = quiet_period

    if reauth_period is not None:
        port_access_auth_data['reauth_period'] = reauth_period

    target_url = kwargs["url"] + "system/interfaces/%s/port_access_auth_configurations" % port_name_percents
    post_data = json.dumps(port_access_auth_data)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Configuring MAC authentication for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Configuring MAC authentication for Port '%s' succeeded" % port_name)
        return True


def enable_disable_port_security_globally(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable port security globally

    :param enable: True if port security to be enabled globally, False if port security to be disabled globally. Defaults to True if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _enable_disable_port_security_globally_v1(enable, **kwargs)
    else:  # Updated else for when version is v10.04
        return _enable_disable_port_security_globally(enable, **kwargs)


def _enable_disable_port_security_globally_v1(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable port security globally

    :param enable: True if port security to be enabled globally, False if port security to be disabled globally. Defaults to True if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data['port_security_enable'] = enable

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting port security enabled globally to '%s' failed with status code %d: %s"
              % (enable, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting port security enabled globally to '%s' succeeded" % enable)
        return True


def _enable_disable_port_security_globally(enable=True, **kwargs):
    """
    Perform GET and PUT calls to either enable or disable port security globally

    :param enable: True if port security to be enabled globally, False if port security to be disabled globally. Defaults to True if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data['port_security_enable'] = enable

    system_data.pop('syslog_remotes', None)
    system_data.pop('vrfs', None)
    system_data.pop('mirrors', None)
    system_data.pop('all_user_copp_policies', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting port security enabled globally to '%s' failed with status code %d: %s"
              % (enable, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting port security enabled globally to '%s' succeeded" % enable)
        return True


def get_all_auth_methods_interface(port_name, **kwargs):
    """
    Perform a GET call to get a list/dict of all authentication methods on a port

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List/dictionary containing all authentication methods on the port
    """
    if kwargs["url"].endswith("/v1/"):
        return _get_all_auth_methods_interface_v1(port_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _get_all_auth_methods_interface(port_name, **kwargs)


def _get_all_auth_methods_interface_v1(port_name, **kwargs):
    """
    Perform a GET call to get a list/dict of all authentication methods on a port

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List/dictionary containing all authentication methods on the port
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    target_url = kwargs["url"] + "system/ports/%s/port_access_auth_configurations" % port_name_percents

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list/dict of all authentication methods on port %s failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        auth_methods = []
    else:
        logging.info("SUCCESS: Getting list/dict of all authentication methods on port %s succeeded" % port_name)
        auth_methods = response.json()
    
    return auth_methods


def _get_all_auth_methods_interface(port_name, **kwargs):
    """
    Perform a GET call to get a dictionary containing all authentication methods on a port

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing all authentication methods on the port
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    target_url = kwargs["url"] + "system/interfaces/%s/port_access_auth_configurations" % port_name_percents

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dict of all authentication methods on port %s failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        auth_methods = []
    else:
        logging.info("SUCCESS: Getting dict of all authentication methods on port %s succeeded" % port_name)
        auth_methods = response.json()

    return auth_methods


def remove_auth_method_interface(port_name, auth_method, **kwargs):
    """
    Perform a DELETE call to remove an authentication method from a port

    :param port_name: Alphanumeric name of the Port on which the authentication method is to be removed
    :param auth_method: Authentication method to be removed from the Port. Should be either "802.1x" or "mac-auth"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _remove_auth_method_interface_v1(port_name, auth_method, **kwargs)
    else:  # Updated else for when version is v10.04
        return _remove_auth_method_interface(port_name, auth_method, **kwargs)


def _remove_auth_method_interface_v1(port_name, auth_method, **kwargs):
    """
    Perform a DELETE call to remove an authentication method from a port

    :param port_name: Alphanumeric name of the Port on which the authentication method is to be removed
    :param auth_method: Authentication method to be removed from the Port. Should be either "802.1x" or "mac-auth"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    port_name_percents = common_ops._replace_special_characters(port_name)

    auth_methods = get_all_auth_methods_interface(port_name, **kwargs)

    if auth_method in auth_methods:

        target_url = kwargs["url"] + "system/ports/%s/port_access_auth_configurations/%s" \
                     % (port_name_percents, auth_method)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Removing authentication method '%s' from Port '%s' failed with status code %d: %s"
                  % (auth_method, port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Removing authentication method '%s' from Port '%s' succeeded" % (auth_method, port_name))
            return True
    else:
        logging.info("SUCCESS: No need to remove authentication method '%s' from Port '%s' since it doesn't exist"
              % (auth_method, port_name))
        return True


def _remove_auth_method_interface(port_name, auth_method, **kwargs):
    """
    Perform a DELETE call to remove an authentication method from a port

    :param port_name: Alphanumeric name of the Port on which the authentication method is to be removed
    :param auth_method: Authentication method to be removed from the Port. Should be either "802.1x" or "mac-auth"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    port_name_percents = common_ops._replace_special_characters(port_name)

    auth_methods = get_all_auth_methods_interface(port_name, **kwargs)

    if auth_method in auth_methods:

        target_url = kwargs["url"] + "system/interfaces/%s/port_access_auth_configurations/%s" \
                     % (port_name_percents, auth_method)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Removing authentication method '%s' from Port '%s' failed with status code %d: %s"
                  % (auth_method, port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Removing authentication method '%s' from Port '%s' succeeded" % (auth_method, port_name))
            return True
    else:
        logging.info("SUCCESS: No need to remove authentication method '%s' from Port '%s' since it doesn't exist"
              % (auth_method, port_name))
        return True


def set_ubt_client_vlan(vlan_id, **kwargs):
    """
    Perform GET and PUT calls to set the reserved VLAN for tunneled clients.

    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _set_ubt_client_vlan_v1(vlan_id, **kwargs)
    else:  # Updated else for when version is v10.04
        return _set_ubt_client_vlan(vlan_id, **kwargs)


def _set_ubt_client_vlan_v1(vlan_id, **kwargs):
    """
    Perform GET and PUT calls to set the reserved VLAN for tunneled clients.

    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data['ubt_client_vid'] = "/rest/v1/system/vlans/%d" % vlan_id

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting the VLAN reserved for tunneled clients to '%d' failed with status code %d: %s"
              % (vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting the VLAN reserved for tunneled clients to '%d' succeeded" % vlan_id)
        return True


def _set_ubt_client_vlan(vlan_id, **kwargs):
    """
    Perform GET and PUT calls to set the reserved VLAN for tunneled clients.

    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data['ubt_client_vid'] = "/rest/v10.04/system/vlans/%d" % vlan_id

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting the VLAN reserved for tunneled clients to '%d' failed with status code %d: %s"
              % (vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting the VLAN reserved for tunneled clients to '%d' succeeded" % vlan_id)
        return True


def create_ubt_zone(zone_name, vrf_name, enable=True, pri_ctrlr_ip_addr=None, backup_ctrlr_ip_addr=None,
                    sac_heartbeat_interval=1, uac_keepalive_interval=60, papi_security_key=None, **kwargs):
    """
    Perform a POST call to create User-Based-Tunneling (UBT) zone on a VRF

    :param zone_name: Alphanumeric name of UBT zone
    :param vrf_name: Alphanumeric name of VRF
    :param enable: True if UBT functionality to be enabled on this zone, False otherwise. Default to True if not
        specified.
    :param pri_ctrlr_ip_addr: IP address of primary controller node. Defaults to nothing if not specified.
    :param backup_ctrlr_ip_addr: IP address of backup controller node. Defaults to nothing if not specified.
    :param sac_heartbeat_interval: Time interval (in seconds) between successive heartbeat messages to the switch
        anchor node. Defaults to 1 if not specified.
    :param uac_keepalive_interval: Time interval (in seconds) between successive keep-alive messages sent to the user
        anchor node. Defaults to 60 if not specified.
    :param papi_security_key: Shared security key used to encrypt UBT PAPI messages exchanged between the switch and the
        controller cluster corresponding to this zone. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_ubt_zone_v1(zone_name, vrf_name, enable, pri_ctrlr_ip_addr, backup_ctrlr_ip_addr,
                            sac_heartbeat_interval, uac_keepalive_interval, papi_security_key, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_ubt_zone(zone_name, vrf_name, enable, pri_ctrlr_ip_addr, backup_ctrlr_ip_addr,
                         sac_heartbeat_interval, uac_keepalive_interval, papi_security_key, **kwargs)


def _create_ubt_zone_v1(zone_name, vrf_name, enable=True, pri_ctrlr_ip_addr=None, backup_ctrlr_ip_addr=None,
                        sac_heartbeat_interval=1, uac_keepalive_interval=60, papi_security_key=None, **kwargs):
    """
    Perform a POST call to create User-Based-Tunneling (UBT) zone on a VRF

    :param zone_name: Alphanumeric name of UBT zone
    :param vrf_name: Alphanumeric name of VRF
    :param enable: True if UBT functionality to be enabled on this zone, False otherwise. Default to True if not
        specified.
    :param pri_ctrlr_ip_addr: IP address of primary controller node. Defaults to nothing if not specified.
    :param backup_ctrlr_ip_addr: IP address of backup controller node. Defaults to nothing if not specified.
    :param sac_heartbeat_interval: Time interval (in seconds) between successive heartbeat messages to the switch
        anchor node. Defaults to 1 if not specified.
    :param uac_keepalive_interval: Time interval (in seconds) between successive keep-alive messages sent to the user
        anchor node. Defaults to 60 if not specified.
    :param papi_security_key: Shared security key used to encrypt UBT PAPI messages exchanged between the switch and the
        controller cluster corresponding to this zone. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    ubt_zone_data = {
        "enable": enable,
        "name": zone_name,
        "vrf": "/rest/v1/system/vrfs/%s" % vrf_name,
        "controller_nodes": {}
    }

    if pri_ctrlr_ip_addr is not None:
        ubt_zone_data['controller_nodes']['primary'] = pri_ctrlr_ip_addr

    if backup_ctrlr_ip_addr is not None:
        ubt_zone_data['controller_nodes']['backup'] = backup_ctrlr_ip_addr

    if sac_heartbeat_interval is not None:
        ubt_zone_data['sac_heartbeat_interval'] = sac_heartbeat_interval

    if uac_keepalive_interval is not None:
        ubt_zone_data['uac_keepalive_interval'] = uac_keepalive_interval

    if papi_security_key is not None:
        ubt_zone_data['papi_security_key'] = papi_security_key

    target_url = kwargs["url"] + "system/vrfs/%s/ubt_zone" % vrf_name
    post_data = json.dumps(ubt_zone_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating UBT zone '%s' on VRF '%s' failed with status code %d: %s"
              % (zone_name, vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating UBT zone '%s' on VRF '%s' succeeded" % (zone_name, vrf_name))
        return True


def _create_ubt_zone(zone_name, vrf_name, enable=True, pri_ctrlr_ip_addr=None, backup_ctrlr_ip_addr=None,
                     sac_heartbeat_interval=1, uac_keepalive_interval=60, papi_security_key=None, **kwargs):
    """
    Perform a POST call to create User-Based-Tunneling (UBT) zone on a VRF

    :param zone_name: Alphanumeric name of UBT zone
    :param vrf_name: Alphanumeric name of VRF
    :param enable: True if UBT functionality to be enabled on this zone, False otherwise. Default to True if not
        specified.
    :param pri_ctrlr_ip_addr: IP address of primary controller node. Defaults to nothing if not specified.
    :param backup_ctrlr_ip_addr: IP address of backup controller node. Defaults to nothing if not specified.
    :param sac_heartbeat_interval: Time interval (in seconds) between successive heartbeat messages to the switch
        anchor node. Defaults to 1 if not specified.
    :param uac_keepalive_interval: Time interval (in seconds) between successive keep-alive messages sent to the user
        anchor node. Defaults to 60 if not specified.
    :param papi_security_key: Shared security key used to encrypt UBT PAPI messages exchanged between the switch and the
        controller cluster corresponding to this zone. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    ubt_zone_data = {
        "enable": enable,
        "name": zone_name,
        "vrf": "/rest/v10.04/system/vrfs/%s" % vrf_name,
        "controller_nodes": {}
    }

    if pri_ctrlr_ip_addr is not None:
        ubt_zone_data['controller_nodes']['primary'] = pri_ctrlr_ip_addr

    if backup_ctrlr_ip_addr is not None:
        ubt_zone_data['controller_nodes']['backup'] = backup_ctrlr_ip_addr

    if sac_heartbeat_interval is not None:
        ubt_zone_data['sac_heartbeat_interval'] = sac_heartbeat_interval

    if uac_keepalive_interval is not None:
        ubt_zone_data['uac_keepalive_interval'] = uac_keepalive_interval

    if papi_security_key is not None:
        ubt_zone_data['papi_security_key'] = papi_security_key

    target_url = kwargs["url"] + "system/vrfs/%s/ubt_zone" % vrf_name
    post_data = json.dumps(ubt_zone_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating UBT zone '%s' on VRF '%s' failed with status code %d: %s"
              % (zone_name, vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating UBT zone '%s' on VRF '%s' succeeded" % (zone_name, vrf_name))
        return True


def create_port_access_role(role_name, desc=None, gateway_zone=None, ubt_gateway_role=None, vlan_mode=None,
                            vlan_tag=None, vlan_trunks=None, **kwargs):
    """
    Perform a POST call to create a port access role

    :param role_name: Alphanumeric name of port access role
    :param desc: Optional description for role. Defaults to nothing if not specified.
    :param gateway_zone: Gateway zone associated with this role. Defaults to nothing if not specified.
    :param ubt_gateway_role: Role to be assigned to tunneled clients on the UBT cluster side. Defaults to nothing if not
        specified.
    :param vlan_mode: VLAN mode should be one of "access," "native-tagged," "native-untagged," or "trunk." Defaults to
        nothing if not specified.
    :param vlan_tag: The untagged VLAN to which users of this access role has to be assigned to.
    :param vlan_trunks: The tagged VLAN(s) to which users of this access role has to be assigned to.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_port_access_role_v1(role_name, desc, gateway_zone, ubt_gateway_role, vlan_mode,
                                    vlan_tag, vlan_trunks, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_port_access_role(role_name, desc, gateway_zone, ubt_gateway_role, vlan_mode,
                                 vlan_tag, vlan_trunks, **kwargs)


def _create_port_access_role_v1(role_name, desc=None, gateway_zone=None, ubt_gateway_role=None, vlan_mode=None,
                                vlan_tag=None, vlan_trunks=None, **kwargs):
    """
    Perform a POST call to create a port access role

    :param role_name: Alphanumeric name of port access role
    :param desc: Optional description for role. Defaults to nothing if not specified.
    :param gateway_zone: Gateway zone associated with this role. Defaults to nothing if not specified.
    :param ubt_gateway_role: Role to be assigned to tunneled clients on the UBT cluster side. Defaults to nothing if not
        specified.
    :param vlan_mode: VLAN mode should be one of "access," "native-tagged," "native-untagged," or "trunk." Defaults to
        nothing if not specified.
    :param vlan_tag: The untagged VLAN to which users of this access role has to be assigned to.
    :param vlan_trunks: The tagged VLAN(s) to which users of this access role has to be assigned to.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """


    role_data = {
        "name": role_name,
    }

    if desc is not None:
        role_data['desc'] = desc

    if gateway_zone is not None:
        role_data['gateway_zone'] = gateway_zone

    if ubt_gateway_role is not None:
        role_data['ubt_gateway_role'] = ubt_gateway_role

    if vlan_mode is not None:
        role_data['vlan_mode'] = vlan_mode

    if vlan_tag is not None:
        role_data['vlan_tag'] = vlan_tag

    if vlan_trunks is not None:
        role_data['vlan_trunks'] = vlan_trunks

    target_url = kwargs["url"] + "system/port_access_roles"
    post_data = json.dumps(role_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating port access role '%s' failed with status code %d: %s"
              % (role_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating port access role '%s' succeeded" % role_name)
        return True


def _create_port_access_role(role_name, desc=None, gateway_zone=None, ubt_gateway_role=None, vlan_mode=None,
                             vlan_tag=None, vlan_trunks=None, **kwargs):
    """
    Perform a POST call to create a port access role

    :param role_name: Alphanumeric name of port access role
    :param desc: Optional description for role. Defaults to nothing if not specified.
    :param gateway_zone: Gateway zone associated with this role. Defaults to nothing if not specified.
    :param ubt_gateway_role: Role to be assigned to tunneled clients on the UBT cluster side. Defaults to nothing if not
        specified.
    :param vlan_mode: VLAN mode should be one of "access," "native-tagged," "native-untagged," or "trunk." Defaults to
        nothing if not specified.
    :param vlan_tag: The untagged VLAN to which users of this access role has to be assigned to.
    :param vlan_trunks: The tagged VLAN(s) to which users of this access role has to be assigned to.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    role_data = {
        "name": role_name,
    }

    if desc is not None:
        role_data['desc'] = desc

    if gateway_zone is not None:
        role_data['gateway_zone'] = gateway_zone

    if ubt_gateway_role is not None:
        role_data['ubt_gateway_role'] = ubt_gateway_role

    if vlan_mode is not None:
        role_data['vlan_mode'] = vlan_mode

    if vlan_tag is not None:
        role_data['vlan_tag'] = vlan_tag

    if vlan_trunks is not None:
        role_data['vlan_trunks'] = vlan_trunks

    target_url = kwargs["url"] + "system/port_access_roles"
    post_data = json.dumps(role_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating port access role '%s' failed with status code %d: %s"
              % (role_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating port access role '%s' succeeded" % role_name)
        return True


def set_port_access_clients_limit(port_name, clients_limit, **kwargs):
    """
    Perform GET and PUT calls to set a port's maximum allowed number of authorized clients.

    :param port_name: Alphanumeric name of Port
    :param clients_limit: Numeric ID of VLAN to add to trunk port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _set_port_access_clients_limit_v1(port_name, clients_limit, **kwargs)
    else:  # Updated else for when version is v10.04
        return _set_port_access_clients_limit(port_name, clients_limit, **kwargs)


def _set_port_access_clients_limit_v1(port_name, clients_limit, **kwargs):
    """
    Perform GET and PUT calls to set a port's maximum allowed number of authorized clients.

    :param port_name: Alphanumeric name of Port
    :param clients_limit: Numeric ID of VLAN to add to trunk port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data.pop('name', None)
    port_data.pop('origin', None)
    port_data.pop('vrf', None)

    port_data['port_access_clients_limit'] = clients_limit

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting maximum allowable clients limit on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting maximum allowable clients limit on Port '%s' succeeded"
              % port_name)
        return True


def _set_port_access_clients_limit(port_name, clients_limit, **kwargs):
    """
    Perform GET and PUT calls to set a port's maximum allowed number of authorized clients.

    :param port_name: Alphanumeric name of Port
    :param clients_limit: Numeric ID of VLAN to add to trunk port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    int_data = interface.get_interface(port_name_percents, depth=2, selector="writable", **kwargs)

    int_data.pop('portfilter', None)  # Have to remove this because of bug?

    int_data['port_access_clients_limit'] = clients_limit

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting maximum allowable clients limit on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting maximum allowable clients limit on Port '%s' succeeded"
              % port_name)
        return True


def set_source_ip_ubt(vrf_name, source_ip, **kwargs):
    """
    Perform GET and PUT calls to set the source IP address for UBT on a VRF.

    :param vrf_name: Alphanumeric name of VRF
    :param source_ip: IP address for UBT
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _set_source_ip_ubt_v1(vrf_name, source_ip, **kwargs)
    else:   # Updated else for when version is v10.04
        return _set_source_ip_ubt(vrf_name, source_ip, **kwargs)


def _set_source_ip_ubt_v1(vrf_name, source_ip, **kwargs):
    """
    Perform GET and PUT calls to set the source IP address for UBT on a VRF.

    :param vrf_name: Alphanumeric name of VRF
    :param source_ip: IP address for UBT
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    vrf_data = vrf.get_vrf(vrf_name, depth=0, selector="configuration", **kwargs)

    vrf_data['source_ip']['ubt'] = source_ip

    target_url = kwargs["url"] + "system/vrfs/%s" % vrf_name
    put_data = json.dumps(vrf_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating UBT source IP address on VRF '%s' failed with status code %d: %s"
              % (vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating UBT source IP address on VRF '%s' succeeded"
              % vrf_name)
        return True


def _set_source_ip_ubt(vrf_name, source_ip, **kwargs):
    """
    Perform GET and PUT calls to set the source IP address for UBT on a VRF.

    :param vrf_name: Alphanumeric name of VRF
    :param source_ip: IP address for UBT
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    vrf_data = vrf.get_vrf(vrf_name, depth=1, selector="writable", **kwargs)

    vrf_data['source_ip']['ubt'] = source_ip

    target_url = kwargs["url"] + "system/vrfs/%s" % vrf_name
    put_data = json.dumps(vrf_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating UBT source IP address on VRF '%s' failed with status code %d: %s"
              % (vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating UBT source IP address on VRF '%s' succeeded"
              % vrf_name)
        return True


def clear_ubt_client_vlan(**kwargs):
    """
    Perform GET and PUT calls to clear the reserved VLAN for tunneled clients.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _clear_ubt_client_vlan_v1(**kwargs)
    else:  # Updated else for when version is v10.04
        return _clear_ubt_client_vlan(**kwargs)


def _clear_ubt_client_vlan_v1(**kwargs):
    """
    Perform GET and PUT calls to clear the reserved VLAN for tunneled clients.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data.pop('ubt_client_vid', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing the VLAN reserved for tunneled clients failed with status code %d: %s"
              % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing the VLAN reserved for tunneled clients succeeded")
        return True


def _clear_ubt_client_vlan(**kwargs):
    """
    Perform GET and PUT calls to clear the reserved VLAN for tunneled clients.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data.pop('ubt_client_vid', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing the VLAN reserved for tunneled clients failed with status code %d: %s"
              % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing the VLAN reserved for tunneled clients succeeded")
        return True


def remove_ubt_zone(vrf_name, **kwargs):
    """
    Perform a DELETE call to delete the User-Based-Tunneling (UBT) zone on a VRF

    :param vrf_name: Alphanumeric name of VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _remove_ubt_zone_v1(vrf_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _remove_ubt_zone(vrf_name, **kwargs)


def _remove_ubt_zone_v1(vrf_name, **kwargs):
    """
    Perform a DELETE call to delete the User-Based-Tunneling (UBT) zone on a VRF

    :param vrf_name: Alphanumeric name of VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    target_url = kwargs["url"] + "system/vrfs/%s/ubt_zone" % vrf_name

    response = kwargs["s"].delete(target_url, verify=False)

    if not common_ops._response_ok(response, "DELETE"):
        logging.warning("FAIL: Deleting UBT zone on VRF '%s' failed with status code %d: %s"
                        % (vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Deleting UBT zone on VRF '%s' succeeded" % vrf_name)
        return True


# same as _remove_ubt_zone_v1
def _remove_ubt_zone(vrf_name, **kwargs):
    """
    Perform a DELETE call to delete the User-Based-Tunneling (UBT) zone on a VRF

    :param vrf_name: Alphanumeric name of VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    target_url = kwargs["url"] + "system/vrfs/%s/ubt_zone" % vrf_name

    response = kwargs["s"].delete(target_url, verify=False)

    if not common_ops._response_ok(response, "DELETE"):
        logging.warning("FAIL: Deleting UBT zone on VRF '%s' failed with status code %d: %s"
                        % (vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Deleting UBT zone on VRF '%s' succeeded" % vrf_name)
        return True


def remove_port_access_role(role_name, **kwargs):
    """
    Perform a DELETE call to delete a port access role

    :param role_name: Alphanumeric name of port access role
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _remove_port_access_role_v1(role_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _remove_port_access_role(role_name, **kwargs)


def _remove_port_access_role_v1(role_name, **kwargs):
    """
    Perform a DELETE call to delete a port access role

    :param role_name: Alphanumeric name of port access role
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    target_url = kwargs["url"] + "system/port_access_roles/%s" % role_name

    response = kwargs["s"].delete(target_url, verify=False)

    if not common_ops._response_ok(response, "DELETE"):
        logging.warning("FAIL: Removing port access role '%s' failed with status code %d: %s"
              % (role_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing port access role '%s' succeeded" % role_name)
        return True


# same as _remove_port_access_role_v1
def _remove_port_access_role(role_name, **kwargs):
    """
    Perform a DELETE call to delete a port access role

    :param role_name: Alphanumeric name of port access role
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    target_url = kwargs["url"] + "system/port_access_roles/%s" % role_name

    response = kwargs["s"].delete(target_url, verify=False)

    if not common_ops._response_ok(response, "DELETE"):
        logging.warning("FAIL: Removing port access role '%s' failed with status code %d: %s"
              % (role_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing port access role '%s' succeeded" % role_name)
        return True


def clear_port_access_clients_limit(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a port's limit of maximum allowed number of authorized clients.

    :param port_name: Alphanumeric name of Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _clear_port_access_clients_limit_v1(port_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _clear_port_access_clients_limit(port_name, **kwargs)


def _clear_port_access_clients_limit_v1(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a port's limit of maximum allowed number of authorized clients.

    :param port_name: Alphanumeric name of Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data.pop('port_access_clients_limit', None)

    port_data.pop('name', None)
    port_data.pop('origin', None)
    port_data.pop('vrf', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing maximum allowable clients limit on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing maximum allowable clients limit on Port '%s' succeeded"
              % port_name)
        return True


def _clear_port_access_clients_limit(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a port's limit of maximum allowed number of authorized clients.

    :param port_name: Alphanumeric name of Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    int_data = interface.get_interface(port_name_percents, depth=2, selector="writable", **kwargs)

    int_data.pop('port_access_clients_limit', None)

    int_data.pop('portfilter', None)  # Have to remove this because of bug

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing maximum allowable clients limit on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing maximum allowable clients limit on Port '%s' succeeded"
              % port_name)
        return True


def remove_source_ip_ubt(vrf_name, **kwargs):
    """
    Perform GET and PUT calls to remove the source IP address for UBT on a VRF.

    :param vrf_name: Alphanumeric name of VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _remove_source_ip_ubt_v1(vrf_name, **kwargs)
    else:   # Updated else for when version is v10.04
        return _remove_source_ip_ubt(vrf_name, **kwargs)


def _remove_source_ip_ubt_v1(vrf_name, **kwargs):
    """
    Perform GET and PUT calls to remove the source IP address for UBT on a VRF.

    :param vrf_name: Alphanumeric name of VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vrf_data = vrf.get_vrf(vrf_name, depth=0, selector="configuration", **kwargs)

    vrf_data['source_ip'].pop('ubt', None)

    target_url = kwargs["url"] + "system/vrfs/%s" % vrf_name
    put_data = json.dumps(vrf_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing UBT source IP address on VRF '%s' failed with status code %d: %s"
              % (vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing UBT source IP address on VRF '%s' succeeded"
              % vrf_name)
        return True


def _remove_source_ip_ubt(vrf_name, **kwargs):
    """
    Perform GET and PUT calls to remove the source IP address for UBT on a VRF.

    :param vrf_name: Alphanumeric name of VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    vrf_data = vrf.get_vrf(vrf_name, depth=1, selector="writable", **kwargs)

    vrf_data['source_ip'].pop('ubt', None)

    target_url = kwargs["url"] + "system/vrfs/%s" % vrf_name
    put_data = json.dumps(vrf_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing UBT source IP address on VRF '%s' failed with status code %d: %s"
              % (vrf_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing UBT source IP address on VRF '%s' succeeded"
              % vrf_name)
        return True
