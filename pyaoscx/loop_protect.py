# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops, interface, port

import json
import logging


def update_port_loop_protect(interface_name, action=None, vlan_list=[], **kwargs):
    """
    Perform GET and PUT calls to apply Loop-protect options on an interface.

    :param interface_name: Alphanumeric String that is the name of the interface that will apply loop-protect options
    :param action: Alphanumeric String that will specify the actions for the Loop-protect interface.  The options are
        "do-not-disable", "tx-disable", "tx-rx-disable", or None.
    :param vlan_list: List of VLANs that will be configured for Loop-protect on the interface
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if action not in ['do-not-disable', 'tx-disable', 'tx-rx-disable', None]:
        raise Exception("ERROR: Action should be 'do-not-disable', 'tx-disable', 'tx-rx-disable' or None")

    if kwargs["url"].endswith("/v1/"):
        return _update_port_loop_protect_v1(interface_name, action, vlan_list, **kwargs)
    else:   # Updated else for when version is v10.04
        return _update_port_loop_protect(interface_name, action, vlan_list, **kwargs)


def _update_port_loop_protect_v1(interface_name, action="", vlan_list=[], **kwargs):
    """
    Perform GET and PUT calls to apply Loop-protect options on an interface.  Note that Loop-protect requires that
    the interface is L2, so this function will also update the interface to reflect that.

    :param interface_name: Alphanumeric String that is the name of the interface that will apply loop-protect options
    :param action: Alphanumeric String that will specify the actions for the Loop-protect interface.  The options are
        "do-not-disable", "tx-disable", "tx-rx-disable", or None.
    :param vlan_list: List of VLANs that will be configured for Loop-protect on the interface
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(interface_name)

    port_data = port.get_port(port_name_percents, depth=0, selector="configuration", **kwargs)

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    port_data['loop_protect_enable'] = True
    # make interface L2
    port_data['routing'] = False

    # strings appended to output prints for status
    action_output = ""
    vlan_output = ""

    if action not in ['do-not-disable', 'tx-disable', 'tx-rx-disable', None]:
        raise Exception("ERROR: Action should be 'do-not-disable', 'tx-disable', 'tx-rx-disable' or None")
    elif action:
        port_data['loop_protect_action'] = action
        action_output = " with Action %s " % action

    if vlan_list:
        vlan_output = " with VLAN(s) ["
        for vlan in vlan_list:
            vlan_url = "/rest/v1/system/vlans/%s" % vlan
            if vlan_url not in port_data['loop_protect_vlan']:
                port_data['loop_protect_vlan'].append(vlan_url)
                vlan_output += (" " + str(vlan))
        vlan_output += "] "

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Applying Loop-protect to Interface '%s'%s%s failed with status code %d: %s"
              % (interface_name, action_output, vlan_output, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Applying Loop-protect to Interface '%s'%s%s succeeded"
              % (interface_name, action_output, vlan_output))
        return True


def _update_port_loop_protect(interface_name, action="", vlan_list=[], **kwargs):
    """
    Perform GET and PUT calls to apply Loop-protect options on an interface.  Note that Loop-protect requires that
    the interface is L2, so this function will also update the interface to reflect that.

    :param interface_name: Alphanumeric String that is the name of the interface that will apply loop-protect options
    :param action: Alphanumeric String that will specify the actions for the Loop-protect interface.  The options are
        "do-not-disable", "tx-disable", "tx-rx-disable", or None.
    :param vlan_list: List of VLANs that will be configured for Loop-protect on the interface
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    int_name_percents = common_ops._replace_special_characters(interface_name)
    int_data = interface.get_interface(int_name_percents, depth=1, selector="writable", **kwargs)

    if interface_name.startswith('lag'):
        if int_data['interfaces']:
            int_data['interfaces'] = common_ops._dictionary_to_list_values(int_data['interfaces'])

    if int_data['vlan_trunks']:
        int_data['vlan_trunks'] = common_ops._dictionary_to_list_values(int_data['vlan_trunks'])
    if int_data['loop_protect_vlan']:
        int_data['loop_protect_vlan'] = common_ops._dictionary_to_list_values(int_data['loop_protect_vlan'])

    int_data['loop_protect_enable'] = True
    # make interface L2
    int_data['routing'] = False

    # strings appended to output prints for status
    action_output = ""
    vlan_output = ""

    if action not in ['do-not-disable', 'tx-disable', 'tx-rx-disable', None]:
        raise Exception("ERROR: Action should be 'do-not-disable', 'tx-disable', 'tx-rx-disable' or None")
    elif action:
        int_data['loop_protect_action'] = action
        action_output = " with Action %s " % action

    if vlan_list:
        vlan_output = " with VLAN(s) ["
        for vlan in vlan_list:
            vlan_url = "/rest/v10.04/system/vlans/%s" % vlan
            if vlan_url not in int_data['loop_protect_vlan']:
                int_data['loop_protect_vlan'].append(vlan_url)
                vlan_output += (str(vlan) + " ")
        vlan_output += "] "

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Applying Loop-protect to Interface '%s'%s%s failed with status code %d: %s"
              % (interface_name, action_output, vlan_output, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Applying Loop-protect to Interface '%s'%s%s succeeded"
              % (interface_name, action_output, vlan_output))
        return True


def clear_port_loop_protect(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's Loop-protect settings

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _clear_port_loop_protect_v1(port_name, **kwargs)
    else:   # Updated else for when version is v10.04
        return _clear_port_loop_protect(port_name, **kwargs)


def _clear_port_loop_protect_v1(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's Loop-protect settings

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name, depth=0, selector="configuration", **kwargs)

    port_data.pop('loop_protect_enable', None)
    port_data.pop('loop_protect_action', None)
    port_data['loop_protect_vlan'] = []

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing Loop-protect options on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing the Loop-protect options on Port '%s' succeeded"
              % (port_name))
        return True


def _clear_port_loop_protect(interface_name, **kwargs):
    """
    Perform GET and PUT calls to clear an Interface's Loop-protect settings

    :param interface_name: Alphanumeric name of the Interface
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    int_name_percents = common_ops._replace_special_characters(interface_name)

    int_data = interface.get_interface(interface_name, depth=1, selector="writable", **kwargs)

    if interface_name.startswith('lag'):
        if int_data['interfaces']:
            int_data['interfaces'] = common_ops._dictionary_to_list_values(int_data['interfaces'])

    if int_data['vlan_trunks']:
        int_data['vlan_trunks'] = common_ops._dictionary_to_list_values(int_data['vlan_trunks'])

    int_data['loop_protect_enable'] = None
    int_data['loop_protect_action'] = "tx-disable"
    int_data['loop_protect_vlan'] = []

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing Loop-protect options on Interface '%s' failed with status code %d: %s"
              % (interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing the Loop-protect options on Interface '%s' succeeded"
              % (interface_name))
        return True
