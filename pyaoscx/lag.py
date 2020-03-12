# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops
from pyaoscx import port
from pyaoscx import interface

import json
import re
import logging


def create_l2_lag_interface(name, phys_ports, lacp_mode="passive", mc_lag=False, fallback_enabled=False,
                            vlan_ids_list=[], desc=None, admin_state="up", **kwargs):
    """
    Perform a POST call to create a Port table entry for L2 LAG interface.

    :param name: Alphanumeric name of LAG Port
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param lacp_mode: Should be either "passive" or "active." Defaults to "passive" if not specified.
    :param mc_lag: Boolean to determine if the LAG is multi-chassis. Defaults to False if not specified.
    :param fallback_enabled: Boolean to determine if the LAG uses LACP fallback. Defaults to False if not specified.
    :param vlan_ids_list: Optional list of integer VLAN IDs to add as trunk VLANS. Defaults to empty list if not specified.
    :param desc: Optional description for the interface. Defaults to nothing if not specified.
    :param admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_l2_lag_interface_v1(name, phys_ports, lacp_mode, mc_lag, fallback_enabled, vlan_ids_list, desc,
                                           admin_state, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_l2_lag_interface(name, phys_ports, lacp_mode, mc_lag, fallback_enabled, vlan_ids_list, desc,
                                        admin_state, **kwargs)


def _create_l2_lag_interface_v1(name, phys_ports, lacp_mode="passive", mc_lag=False, fallback_enabled=False,
                                vlan_ids_list=[], desc=None, admin_state="up", **kwargs):
    """
    Perform a POST call to create a Port table entry for L2 LAG interface.

    :param name: Alphanumeric name of LAG Port
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param lacp_mode: Should be either "passive" or "active." Defaults to "passive" if not specified.
    :param mc_lag: Boolean to determine if the LAG is multi-chassis. Defaults to False if not specified.
    :param fallback_enabled: Boolean to determine if the LAG uses LACP fallback. Defaults to False if not specified.
    :param vlan_ids_list: Optional list of integer VLAN IDs to add as trunk VLANS. Defaults to empty list if not specified.
    :param desc: Optional description for the interface. Defaults to nothing if not specified.
    :param admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = port.get_all_ports(**kwargs)

    port_name_percents = common_ops._replace_special_characters(name)
    if "/rest/v1/system/ports/%s" % port_name_percents not in ports_list:

        # Extract LAG ID from LAG name
        lag_id = int(re.search('\d+', name).group())

        # For each port, add LAG ID to the Interface table entry, and delete the Port table entry
        for phys_port in phys_ports:
            interface.add_port_to_lag(phys_port, lag_id, **kwargs)

        interfaces = ["/rest/v1/system/interfaces/%s" % common_ops._replace_special_characters(phys_port)
                      for phys_port in phys_ports]
        port_data = {"admin": admin_state,
                     "interfaces": interfaces,
                     "name": name,
                     "routing": False,
                     "vlan_trunks": ["/rest/v1/system/vlans/%d" % vlan_id for vlan_id in vlan_ids_list],
                     "lacp": lacp_mode,
                     "other_config": {
                         "mclag_enabled": mc_lag,
                         "lacp-fallback": fallback_enabled
                        },
                     "vlan_mode": "native-untagged",
                     "vlan_tag": "/rest/v1/system/vlans/1"
                     }

        if desc is not None:
            port_data['description'] = desc

        target_url = kwargs["url"] + "system/ports"
        post_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Port table entry '%s' failed with status code %d: %s"
                  % (name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Port table entry '%s' succeeded" % name)
            return True
    else:
        logging.info("SUCCESS: No need to add Port table entry '%s' because it already exists"
              % name)
        return True


def _create_l2_lag_interface(name, phys_ports, lacp_mode="passive", mc_lag=False, fallback_enabled=False,
                             vlan_ids_list=[], desc=None, admin_state="up", **kwargs):
    """
    Perform a POST call to create a Port table entry for L2 LAG interface.

    :param name: Alphanumeric name of LAG Port
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param lacp_mode: Should be either "passive" or "active." Defaults to "passive" if not specified.
    :param mc_lag: Boolean to determine if the LAG is multi-chassis. Defaults to False if not specified.
    :param fallback_enabled: Boolean to determine if the LAG uses LACP fallback. Defaults to False if not specified.
    :param vlan_ids_list: Optional list of integer VLAN IDs to add as trunk VLANS. Defaults to empty list if not specified.
    :param desc: Optional description for the interface. Defaults to nothing if not specified.
    :param admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ints_dict = interface.get_all_interfaces(**kwargs)

    if name not in ints_dict:

        # Extract LAG ID from LAG name
        lag_id = int(re.search('\d+', name).group())

        # For each port, add LAG ID to the Interface table entry
        for phys_port in phys_ports:
            interface.add_port_to_lag(phys_port, lag_id, **kwargs)

        interfaces = ["/rest/v10.04/system/interfaces/%s" % common_ops._replace_special_characters(phys_port)
                      for phys_port in phys_ports]
        int_data = {"admin": admin_state,
                    "interfaces": interfaces,
                    "name": name,
                    "type": "lag",
                    "routing": False,
                    "vlan_trunks": ["/rest/v10.04/system/vlans/%d" % vlan_id for vlan_id in vlan_ids_list],
                    "lacp": lacp_mode,
                    "other_config": {
                        "lacp-aggregation-key": lag_id,
                        "lacp-port-id": 0,
                        "lacp-port-priority": 0,
                        "lldp_dot3_macphy_disable": True,
                        "lldp_dot3_poe_disable": True,
                        "lldp_enable_dir": "off",
                        "lldp_med_capability_disable": True,
                        "lldp_med_network_policy_disable": True,
                        "lldp_med_poe_disable": True,
                        "lldp_med_poe_priority_override": True,
                        "lldp_med_topology_notification_disable": True
                    },
                    "vlan_mode": "native-untagged",
                    "vlan_tag": {"1": "/rest/v10.04/system/vlans/1"}
                    }

        if desc is not None:
            int_data['description'] = desc

        target_url = kwargs["url"] + "system/interfaces"
        post_data = json.dumps(int_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Interface table entry '%s' failed with status code %d: %s"
                  % (name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Interface table entry '%s' succeeded" % name)
            return True
    else:
        logging.info("SUCCESS: No need to add Interface table entry '%s' because it already exists"
              % name)
        return True


def create_l3_lag_interface(name, phys_ports, ipv4, lacp_mode="passive", mc_lag=False, fallback_enabled=False,
                            desc=None, admin_state="up", vrf="default", **kwargs):
    """
    Perform a POST call to create a Port table entry for L3 LAG interface.

    :param name: Alphanumeric Port name
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param ipv4: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param lacp_mode: Should be either "passive" or "active." Defaults to "passive" if not specified.
    :param mc_lag: Boolean to determine if the LAG is multi-chassis. Defaults to False if not specified.
    :param fallback_enabled: Boolean to determine if the LAG uses LACP fallback. Defaults to False if not specified.
    :param desc: Optional description for the interface. Defaults to nothing if not specified.
    :param admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_l3_lag_interface_v1(name, phys_ports, ipv4, lacp_mode, mc_lag, fallback_enabled,
                                           desc, admin_state, vrf, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_l3_lag_interface(name, phys_ports, ipv4, lacp_mode, mc_lag, fallback_enabled,
                                        desc, admin_state, vrf, **kwargs)


def _create_l3_lag_interface_v1(name, phys_ports, ipv4, lacp_mode="passive", mc_lag=False, fallback_enabled=False,
                                desc=None, admin_state="up", vrf="default", **kwargs):
    """
    Perform a POST call to create a Port table entry for L3 LAG interface.

    :param name: Alphanumeric Port name
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param ipv4: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param lacp_mode: Should be either "passive" or "active." Defaults to "passive" if not specified.
    :param mc_lag: Boolean to determine if the LAG is multi-chassis. Defaults to False if not specified.
    :param fallback_enabled: Boolean to determine if the LAG uses LACP fallback. Defaults to False if not specified.
    :param desc: Optional description for the interface. Defaults to nothing if not specified.
    :param admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    ports_list = port.get_all_ports(**kwargs)

    port_name_percents = common_ops._replace_special_characters(name)
    if "/rest/v1/system/ports/%s" % port_name_percents not in ports_list:

        # Extract LAG ID from LAG name
        lag_id = int(re.search('\d+', name).group())

        # For each port, add LAG ID to the Interface table entry, and delete the Port table entry
        for phys_port in phys_ports:
            interface.add_port_to_lag(phys_port, lag_id, **kwargs)

        interfaces = ["/rest/v1/system/interfaces/%s" % common_ops._replace_special_characters(phys_port)
                      for phys_port in phys_ports]
        port_data = {"admin": admin_state,
                     "interfaces": interfaces,
                     "name": name,
                     "routing": True,
                     "vrf": "/rest/v1/system/vrfs/%s" % vrf,
                     "ip4_address": ipv4,
                     "lacp": lacp_mode,
                     "other_config": {
                        "mclag_enabled": mc_lag,
                        "lacp-fallback": fallback_enabled
                        },
                     }

        if desc is not None:
            port_data['description'] = desc

        if ipv4 is not None:
            port_data['ip4_address'] = ipv4

        target_url = kwargs["url"] + "system/ports"
        post_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Port table entry '%s' failed with status code %d: %s"
                  % (name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Port table entry '%s' succeeded" % name)
            return True
    else:
        logging.info("SUCCESS: No need to add Port table entry '%s' because it already exists"
              % name)
        return True


def _create_l3_lag_interface(name, phys_ports, ipv4, lacp_mode="passive", mc_lag=False, fallback_enabled=False,
                             desc=None, admin_state="up", vrf="default", **kwargs):
    """
    Perform a POST call to create a Port table entry for L3 LAG interface.

    :param name: Alphanumeric Port name
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param ipv4: IPv4 address to assign to the interface. Defaults to nothing if not specified.
    :param lacp_mode: Should be either "passive" or "active." Defaults to "passive" if not specified.
    :param mc_lag: Boolean to determine if the LAG is multi-chassis. Defaults to False if not specified.
    :param fallback_enabled: Boolean to determine if the LAG uses LACP fallback. Defaults to False if not specified.
    :param desc: Optional description for the interface. Defaults to nothing if not specified.
    :param admin_state: Optional administratively-configured state of the port.
        Defaults to "up" if not specified
    :param vrf: Name of the VRF to which the Port belongs. Defaults to "default" if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    ints_dict = interface.get_all_interfaces(**kwargs)

    if name not in ints_dict:

        interfaces = ["/rest/v10.04/system/interfaces/%s" % common_ops._replace_special_characters(phys_port)
                      for phys_port in phys_ports]
        int_data = {"admin": admin_state,
                    "interfaces": interfaces,
                    "name": name,
                    "type": "lag",
                    "vrf": "/rest/v10.04/system/vrfs/%s" % vrf,
                    "routing": True,
                    "ip4_address": ipv4,
                    "lacp": lacp_mode,
                    # "other_config": {
                    #    "mclag_enabled": mc_lag,
                    #    "lacp-fallback": fallback_enabled
                    #    }

                    }
        """commented out the other_config since it causes error"""

        if desc is not None:
            int_data['description'] = desc

        target_url = kwargs["url"] + "system/interfaces"
        post_data = json.dumps(int_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding Interface table entry '%s' failed with status code %d: %s"
                  % (name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding Interface table entry '%s' succeeded" % name)
            return True
    else:
        logging.info("SUCCESS: No need to add Interface table entry '%s' because it already exists"
              % name)
        return True


def delete_lag_interface(name, phys_ports, **kwargs):
    """
    Perform a DELETE call to delete a LAG interface. For v1, also remove the LAG ID from the port's Interface,
    and create the associated Port table entry.

    :param name: Alphanumeric name of LAG interface
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _delete_lag_interface_v1(name, phys_ports, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_lag_interface(name,  phys_ports, **kwargs)


def _delete_lag_interface_v1(name, phys_ports, **kwargs):
    """
    Perform a DELETE call to delete a LAG interface. Also, for each physical port, create the associated Port table
    entry, and remove the LAG ID from the Port and Interface entries by initializing them to default state.

    :param name: Alphanumeric name of LAG interface
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    success = interface.delete_interface(name, **kwargs)

    # For each port, create a Port table entry, then initialize the Port and Interface entries to remove LAG
    for phys_port in phys_ports:
        success = success and interface.add_l2_interface(phys_port, **kwargs)
        success = success and port.initialize_port_entry(phys_port, **kwargs)

    return success


def _delete_lag_interface(name, phys_ports, **kwargs):
    """
    Perform a DELETE call to delete a LAG interface.  Also, for each physical port, remove the LAG ID from the Interface
    entries by initializing them to default state.

    :param name: Alphanumeric name of LAG interface
    :param phys_ports: List of physical ports to aggregate (e.g. ["1/1/1", "1/1/2", "1/1/3"])
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    success = interface.delete_interface(name, **kwargs)

    # For each port, initialize the Interface entry to remove LAG
    for phys_port in phys_ports:
        success = success and interface.initialize_interface_entry(phys_port, **kwargs)

    return success
