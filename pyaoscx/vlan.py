# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import interface, common_ops
from pyaoscx import common_ops
from pyaoscx import port
from pyaoscx import mac

import json
import random
import logging


def get_vlan(vlan_id, depth=0, selector="configuration", **kwargs):
    """
    Perform a GET call to retrieve data for a VLAN table entry

    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.  If running v10.04 or later, an additional option 'writable' is included.
    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing port data
    """
    if kwargs["url"].endswith("/v1/"):
        return _get_vlan_v1(vlan_id, depth, selector, **kwargs)
    else:   # Updated else for when version is v10.04
        return _get_vlan(vlan_id, depth, selector, **kwargs)


def _get_vlan_v1(vlan_id, depth=0, selector="configuration", **kwargs):
    """
    Perform a GET call to retrieve data for a VLAN table entry

    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.  If running v10.04 or later, an additional option 'writable' is included.
    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing port data
    """
    if selector not in ['configuration', 'status', 'statistics', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', or 'statistics'")

    target_url = kwargs["url"] + "system/vlans/%d" % vlan_id

    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting VLAN ID '%d' table entry failed with status code %d: %s"
                        % (vlan_id, response.status_code, response.text))
        output = {}
    else:
        logging.info("SUCCESS: Getting VLAN ID '%d' table entry succeeded" % vlan_id)
        output = response.json()

    return output


def _get_vlan(vlan_id, depth=1, selector="writable", **kwargs):
    """
    Perform a GET call to retrieve data for a VLAN table entry

    :param depth: Integer deciding how many levels into the API JSON that references will be returned.
    :param selector: Alphanumeric option to select specific information to return.  The options are 'configuration',
        'status', or 'statistics'.  If running v10.04 or later, an additional option 'writable' is included.
    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing port data
    """
    if selector not in ['configuration', 'status', 'statistics', 'writable', None]:
        raise Exception("ERROR: Selector should be 'configuration', 'status', 'statistics', or 'writable'")

    target_url = kwargs["url"] + "system/vlans/%d" % vlan_id
    payload = {
        "depth": depth,
        "selector": selector
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)
    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting VLAN ID '%d' table entry failed with status code %d: %s"
                        % (vlan_id, response.status_code, response.text))
        output = {}
    else:
        logging.info("SUCCESS: Getting VLAN ID '%d' table entry succeeded" % vlan_id)
        output = response.json()

    return output


def vlan_get_all_mac_info(vlan_id, **kwargs):
    """
    Perform GET calls to get info for all MAC address(es) of VLAN

    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of dictionaries containing MAC info
    """

    mac_uris_percents = mac.get_all_mac_addrs(vlan_id, **kwargs)

    mac_data_list = []
    for mac_uri_percent in mac_uris_percents:
        uri_split = mac_uri_percent.split('/')
        mac_addr = common_ops._replace_percents(uri_split[-1])
        mac_type = uri_split[-2]
        vlan_id = int(uri_split[-4])

        mac_data = mac.get_mac_info(vlan_id, mac_type, mac_addr, **kwargs)
        mac_data_list.append(mac_data)

    return mac_data_list


def get_all_vlans(**kwargs):
    """
    Perform a GET call to get a list (or dictionary)  of all entries in VLANs table

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List/dict of all VLANs in the table
    """
    target_url = kwargs["url"] + "system/vlans"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list/dict of all VLAN table entries failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list/dict of all VLAN table entries succeeded")

    vlans = response.json()
    return vlans


def create_vlan(vlan_id, vlan_name, vlan_desc=None, vlan_type="static", admin_conf_state="up", **kwargs):
    """
    Perform a POST call to create a new VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Alphanumeric name of VLAN
    :param vlan_desc: Optional description to add to VLAN
    :param vlan_type: VLAN type. Defaults to "static" if not specified
    :param admin_conf_state: Optional administratively-configured state of VLAN.
        Only configurable for static VLANs. Defaults to "up" for static VLANs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_vlan_v1(vlan_id, vlan_name, vlan_desc, vlan_type, admin_conf_state, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_vlan(vlan_id, vlan_name, vlan_desc, vlan_type, admin_conf_state, **kwargs)


def _create_vlan_v1(vlan_id, vlan_name, vlan_desc=None, vlan_type="static", admin_conf_state="up", **kwargs):
    """
    Perform a POST call to create a new VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Alphanumeric name of VLAN
    :param vlan_desc: Optional description to add to VLAN
    :param vlan_type: VLAN type. Defaults to "static" if not specified
    :param admin_conf_state: Optional administratively-configured state of VLAN.
        Only configurable for static VLANs. Defaults to "up" for static VLANs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vlans_list = get_all_vlans(**kwargs)

    if "/rest/v1/system/vlans/%s" % vlan_id not in vlans_list:
        vlan_data = {"id": vlan_id, "name": vlan_name, "type": vlan_type}

        if vlan_desc is not None:
            vlan_data["description"] = vlan_desc

        if vlan_type == "static":
            # admin-configured state can only be set on static VLANs
            vlan_data["admin"] = admin_conf_state

        target_url = kwargs["url"] + "system/vlans"
        post_data = json.dumps(vlan_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding VLAN table entry '%s' failed with status code %d: %s"
                  % (vlan_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding VLAN table entry '%s' succeeded" % vlan_name)
            return True
    else:
        logging.info("SUCCESS: No need to create VLAN ID '%d' since it already exists" % vlan_id)
        return True


def _create_vlan(vlan_id, vlan_name, vlan_desc=None, vlan_type="static", admin_conf_state="up", **kwargs):
    """
    Perform a POST call to create a new VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Alphanumeric name of VLAN
    :param vlan_desc: Optional description to add to VLAN
    :param vlan_type: VLAN type. Defaults to "static" if not specified
    :param admin_conf_state: Optional administratively-configured state of VLAN.
        Only configurable for static VLANs. Defaults to "up" for static VLANs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vlans_dict = get_all_vlans(**kwargs)

    if str(vlan_id) not in vlans_dict:
        vlan_data = {"id": vlan_id, "name": vlan_name, "type": vlan_type}

        if vlan_desc is not None:
            vlan_data["description"] = vlan_desc

        if vlan_type == "static":
            # admin-configured state can only be set on static VLANs
            vlan_data["admin"] = admin_conf_state

        target_url = kwargs["url"] + "system/vlans"
        post_data = json.dumps(vlan_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Adding VLAN table entry '%s' failed with status code %d: %s"
                  % (vlan_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Adding VLAN table entry '%s' succeeded" % vlan_name)
            return True
    else:
        logging.info("SUCCESS: No need to create VLAN ID '%d' since it already exists" % vlan_id)
        return True


def modify_vlan(vlan_id, vlan_name=None, vlan_desc=None, admin_conf_state=None, **kwargs):
    """
    Perform GET and PUT calls to modify an existing VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Optional Alphanumeric name of VLAN. Won't be modified if not specified.
    :param vlan_desc: Optional description to add to VLAN. Won't be modified if not specified.
    :param admin_conf_state: Optional administratively-configured state of VLAN. Won't be modified if not specified.
        Only configurable for static VLANs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _modify_vlan_v1(vlan_id, vlan_name, vlan_desc, admin_conf_state, **kwargs)
    else:  # Updated else for when version is v10.04
        return _modify_vlan(vlan_id, vlan_name, vlan_desc, admin_conf_state, **kwargs)


def _modify_vlan_v1(vlan_id, vlan_name=None, vlan_desc=None, admin_conf_state=None, **kwargs):
    """
    Perform GET and PUT calls to modify an existing VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Optional Alphanumeric name of VLAN. Won't be modified if not specified.
    :param vlan_desc: Optional description to add to VLAN. Won't be modified if not specified.
    :param admin_conf_state: Optional administratively-configured state of VLAN. Won't be modified if not specified.
        Only configurable for static VLANs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    vlan_data = get_vlan(vlan_id, depth=0, selector="configuration",  **kwargs)
    vlan_data.pop('id', None)  # id cannot be modified

    if vlan_name is not None:
        vlan_data["name"] = vlan_name

    if vlan_desc is not None:
        vlan_data["description"] = vlan_desc

    if vlan_data['type'] == "static" and admin_conf_state is not None:
        # admin-configured state can only be set on static VLANs
        vlan_data["admin"] = admin_conf_state

    target_url = kwargs["url"] + "system/vlans/%d" % vlan_id
    put_data = json.dumps(vlan_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Modifying VLAN ID '%d' failed with status code %d: %s"
                        % (vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Modifying VLAN ID '%d' succeeded" % vlan_id)
        return True


def _modify_vlan(vlan_id, vlan_name=None, vlan_desc=None, admin_conf_state=None, **kwargs):
    """
    Perform GET and PUT calls to modify an existing VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Optional Alphanumeric name of VLAN. Won't be modified if not specified.
    :param vlan_desc: Optional description to add to VLAN. Won't be modified if not specified.
    :param admin_conf_state: Optional administratively-configured state of VLAN. Won't be modified if not specified.
        Only configurable for static VLANs.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    vlan_data = get_vlan(vlan_id, depth=1, selector="writable",  **kwargs)

    if vlan_name is not None:
        vlan_data["name"] = vlan_name

    if vlan_desc is not None:
        vlan_data["description"] = vlan_desc

    if vlan_data['type'] == "static" and admin_conf_state is not None:
        # admin-configured state can only be set on static VLANs
        vlan_data["admin"] = admin_conf_state

    target_url = kwargs["url"] + "system/vlans/%d" % vlan_id
    put_data = json.dumps(vlan_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Modifying VLAN ID '%d' failed with status code %d: %s"
                        % (vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Modifying VLAN ID '%d' succeeded" % vlan_id)
        return True


def create_vlan_and_svi(vlan_id, vlan_name, vlan_port_name, vlan_int_name, vlan_desc=None, ipv4=None,
                        vrf_name="default", vlan_port_desc=None, **kwargs):
    """
    Perform POST and PUT calls to create a new VLAN and SVI.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Alphanumeric name of VLAN
    :param vlan_port_name: Alphanumeric Port name
    :param vlan_int_name: Alphanumeric name for the VLAN interface
    :param vlan_desc: Optional description to add to VLAN
    :param ipv4: Optional IPv4 address to assign to the interface.Defaults to nothing if not specified.
    :param vrf_name: VRF to attach the SVI to. Defaults to "default" if not specified
    :param vlan_port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_vlan_and_svi_v1(vlan_id, vlan_name, vlan_port_name, vlan_int_name, vlan_desc, ipv4,
                                vrf_name, vlan_port_desc, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_vlan_and_svi(vlan_id, vlan_name, vlan_port_name, vlan_int_name, vlan_desc, ipv4,
                             vrf_name, vlan_port_desc, **kwargs)


def _create_vlan_and_svi_v1(vlan_id, vlan_name, vlan_port_name, vlan_int_name, vlan_desc=None, ipv4=None,
                            vrf_name="default", vlan_port_desc=None, **kwargs):
    """
    Perform POST and PUT calls to create a new VLAN and SVI.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Alphanumeric name of VLAN
    :param vlan_port_name: Alphanumeric Port name
    :param vlan_int_name: Alphanumeric name for the VLAN interface
    :param vlan_desc: Optional description to add to VLAN
    :param ipv4: Optional IPv4 address to assign to the interface.Defaults to nothing if not specified.
    :param vrf_name: VRF to attach the SVI to. Defaults to "default" if not specified
    :param vlan_port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    # Add a new VLAN to the VLAN table
    success = create_vlan(vlan_id, vlan_name, vlan_desc, **kwargs)

    # Add a new entry to the Port table
    success = success and port.add_vlan_port(vlan_port_name, vlan_id, ipv4, vrf_name, vlan_port_desc, **kwargs)

    # Add a new entry to the Interface table
    return success and interface.add_vlan_interface(vlan_int_name, vlan_port_name, vlan_id, ipv4, vrf_name, vlan_port_desc, **kwargs)


def _create_vlan_and_svi(vlan_id, vlan_name, vlan_port_name, vlan_int_name, vlan_desc=None, ipv4=None,
                        vrf_name="default", vlan_port_desc=None, **kwargs):
    """
    Perform POST and PUT calls to create a new VLAN and SVI.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_name: Alphanumeric name of VLAN
    :param vlan_port_name: Alphanumeric Port name
    :param vlan_int_name: Alphanumeric name for the VLAN interface
    :param vlan_desc: Optional description to add to VLAN
    :param ipv4: Optional IPv4 address to assign to the interface.Defaults to nothing if not specified.
    :param vrf_name: VRF to attach the SVI to. Defaults to "default" if not specified
    :param vlan_port_desc: Optional description for the interface. Defaults to nothing if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    # Add a new VLAN to the VLAN table
    success = create_vlan(vlan_id, vlan_name, vlan_desc, **kwargs)

    # Add a new entry to the Interface table
    return success and interface.add_vlan_interface(vlan_int_name, vlan_port_name, vlan_id, ipv4, vrf_name, vlan_port_desc, **kwargs)


def delete_vlan(vlan_id, **kwargs):
    """
    Perform a DELETE call to delete VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_vlan_v1(vlan_id, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_vlan(vlan_id, **kwargs)


def _delete_vlan_v1(vlan_id, **kwargs):
    """
    Perform a DELETE call to delete VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    vlans_list = get_all_vlans(**kwargs)

    if "/rest/v1/system/vlans/%s" % vlan_id in vlans_list:

        target_url = kwargs["url"] + "system/vlans/%s" % vlan_id

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting VLAN ID: '%s' failed with status code %d: %s"
                            % (vlan_id, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting VLAN ID: '%s' succeeded" % vlan_id)
            return True
    else:
        logging.info("SUCCESS: No need to remove VLAN ID '%d' since it doesn't exist" % vlan_id)
        return True


def _delete_vlan(vlan_id, **kwargs):
    """
    Perform a DELETE call to delete VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    vlans_dict = get_all_vlans(**kwargs)

    if str(vlan_id) in vlans_dict:

        target_url = kwargs["url"] + "system/vlans/%s" % vlan_id

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting VLAN ID: '%s' failed with status code %d: %s"
                            % (vlan_id, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting VLAN ID: '%s' succeeded" % vlan_id)
            return True
    else:
        logging.info("SUCCESS: No need to remove VLAN ID '%d' since it doesn't exist" % vlan_id)
        return True


def delete_vlan_and_svi(vlan_id, vlan_port_name, **kwargs):
    """
    Perform PUT and DELETE calls to delete SVI and VLAN.

    :param vlan_id: Numeric ID of VLAN
    :param vlan_port_name: Name of SVI's entry in Port table
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    # Delete VLAN SVI
    success = interface.delete_interface(vlan_port_name, **kwargs)

    # Delete VLAN
    return success and delete_vlan(vlan_id, **kwargs)


def attach_vlan_acl(vlan_id, list_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to attach an ACL to a VLAN

    :param vlan_id: Numeric ID of VLAN
    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _attach_vlan_acl_v1(vlan_id, list_name, list_type, **kwargs)
    else:  # Updated else for when version is v10.04
        return _attach_vlan_acl(vlan_id, list_name, list_type, **kwargs)


def _attach_vlan_acl_v1(vlan_id, list_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to attach an ACL to a VLAN

    :param vlan_id: Numeric ID of VLAN
    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vlan_data = get_vlan(vlan_id, depth=0, selector="configuration", **kwargs)

    if list_type == "ipv4":
        vlan_data['aclv4_in_cfg'] = "/rest/v1/system/acls/%s/%s" % (list_name, list_type)
        vlan_data['aclv4_in_cfg_version'] = random.randrange(9007199254740991)

    if list_type == "ipv6":
        vlan_data['aclv6_in_cfg'] = "/rest/v1/system/acls/%s/%s" % (list_name, list_type)
        vlan_data['aclv6_in_cfg_version'] = random.randrange(9007199254740991)

    if list_type == "mac":
        vlan_data['aclmac_in_cfg'] = "/rest/v1/system/acls/%s/%s" % (list_name, list_type)
        vlan_data['aclmac_in_cfg_version'] = random.randrange(9007199254740991)

    # must remove these fields from the data since they can't be modified
    vlan_data.pop('id', None)
    vlan_data.pop('type', None)

    target_url = kwargs["url"] + "system/vlans/%s" % vlan_id
    put_data = json.dumps(vlan_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating %s ACL on VLAN %d to '%s' failed with status code %d: %s"
              % (list_type, vlan_id, list_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating %s ACL on VLAN %d to '%s' succeeded"
              % (list_type, vlan_id, list_name))
        return True


def _attach_vlan_acl(vlan_id, list_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to attach an ACL to a VLAN

    :param vlan_id: Numeric ID of VLAN
    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vlan_data = get_vlan(vlan_id, depth=2, selector="writable", **kwargs)

    if list_type == "ipv4":
        vlan_data['aclv4_in_cfg'] = "/rest/v10.04/system/acls/%s,%s" % (list_name, list_type)
        vlan_data['aclv4_in_cfg_version'] = random.randrange(9007199254740991)

    if list_type == "ipv6":
        vlan_data['aclv6_in_cfg'] = "/rest/v10.04/system/acls/%s,%s" % (list_name, list_type)
        vlan_data['aclv6_in_cfg_version'] = random.randrange(9007199254740991)

    if list_type == "mac":
        vlan_data['aclmac_in_cfg'] = "/rest/v10.04/system/acls/%s,%s" % (list_name, list_type)
        vlan_data['aclmac_in_cfg_version'] = random.randrange(9007199254740991)

    # must remove these fields from the data since they can't be modified
    vlan_data.pop('id', None)
    vlan_data.pop('type', None)

    target_url = kwargs["url"] + "system/vlans/%s" % vlan_id
    put_data = json.dumps(vlan_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating %s ACL on VLAN %d to '%s' failed with status code %d: %s"
              % (list_type, vlan_id, list_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating %s ACL on VLAN %d to '%s' succeeded"
              % (list_type, vlan_id, list_name))
        return True


def detach_vlan_acl(vlan_id, list_type, **kwargs):
    """
    Perform GET and PUT calls to detach ACL from a VLAN

    :param vlan_id: Numeric ID of VLAN
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _detach_vlan_acl_v1(vlan_id, list_type, **kwargs)
    else:  # Updated else for when version is v10.04
        return _detach_vlan_acl(vlan_id, list_type, **kwargs)


def _detach_vlan_acl_v1(vlan_id, list_type, **kwargs):
    """
    Perform GET and PUT calls to detach ACL from a VLAN

    :param vlan_id: Numeric ID of VLAN
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vlan_data = get_vlan(vlan_id, depth=0, selector="configuration", **kwargs)

    if list_type == "ipv4":
        vlan_data.pop('aclv4_in_cfg', None)
        vlan_data.pop('aclv4_in_cfg_version', None)

    if list_type == "ipv6":
        vlan_data.pop('aclv6_in_cfg', None)
        vlan_data.pop('aclv6_in_cfg_version', None)

    if list_type == "mac":
        vlan_data.pop('aclmac_in_cfg', None)
        vlan_data.pop('aclmac_in_cfg_version', None)

    # must remove these fields from the data since they can't be modified
    vlan_data.pop('id', None)
    vlan_data.pop('type', None)

    target_url = kwargs["url"] + "system/vlans/%s" % vlan_id
    put_data = json.dumps(vlan_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing %s ACL from VLAN %d failed with status code %d: %s"
              % (list_type, vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing %s ACL from VLAN %d succeeded"
              % (list_type, vlan_id))
        return True


def _detach_vlan_acl(vlan_id, list_type, **kwargs):
    """
    Perform GET and PUT calls to detach ACL from a VLAN

    :param vlan_id: Numeric ID of VLAN
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    vlan_data = get_vlan(vlan_id, depth=1, selector="writable", **kwargs)

    if list_type == "ipv4":
        vlan_data.pop('aclv4_in_cfg', None)
        vlan_data.pop('aclv4_in_cfg_version', None)

    if list_type == "ipv6":
        vlan_data.pop('aclv6_in_cfg', None)
        vlan_data.pop('aclv6_in_cfg_version', None)

    if list_type == "mac":
        vlan_data.pop('aclmac_in_cfg', None)
        vlan_data.pop('aclmac_in_cfg_version', None)

    target_url = kwargs["url"] + "system/vlans/%s" % vlan_id
    put_data = json.dumps(vlan_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing %s ACL from VLAN %d failed with status code %d: %s"
              % (list_type, vlan_id, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing %s ACL from VLAN %d succeeded"
              % (list_type, vlan_id))
        return True


def port_set_vlan_mode(l2_port_name, vlan_mode, **kwargs):
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
    if kwargs["url"].endswith("/v1/"):
        return port._port_set_vlan_mode(l2_port_name, vlan_mode, **kwargs)
    else:  # Updated else for when version is v10.04
        return interface._port_set_vlan_mode(l2_port_name, vlan_mode, **kwargs)


def port_add_vlan_trunks(l2_port_name, vlan_trunk_ids=[], **kwargs):
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
    if kwargs["url"].endswith("/v1/"):
        return port._port_add_vlan_trunks(l2_port_name, vlan_trunk_ids, **kwargs)
    else:  # Updated else for when version is v10.04
        return interface._port_add_vlan_trunks(l2_port_name, vlan_trunk_ids, **kwargs)


def port_set_native_vlan(l2_port_name, vlan_id, tagged=True, **kwargs):
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
    if kwargs["url"].endswith("/v1/"):
        return port._port_set_native_vlan(l2_port_name, vlan_id, tagged, **kwargs)
    else:  # Updated else for when version is v10.04
        return interface._port_set_native_vlan(l2_port_name, vlan_id, tagged, **kwargs)


def port_delete_vlan_port(l2_port_name, vlan_id, **kwargs):
    """
    Perform GET and PUT calls to remove a VLAN from a trunk port

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_id: Numeric ID of VLAN to remove from trunk port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return port._delete_vlan_port(l2_port_name, vlan_id, **kwargs)
    else:  # Updated else for when version is v10.04
        return interface._delete_vlan_port(l2_port_name, vlan_id, **kwargs)


def port_set_untagged_vlan(l2_port_name, vlan_id, **kwargs):
    """
    Perform GET and PUT/POST calls to set a VLAN on an access port

    :param l2_port_name: L2 interface's Port table entry name
    :param vlan_id: Numeric ID of VLAN to set on access port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return port._port_set_untagged_vlan(l2_port_name, vlan_id, **kwargs)
    else:  # Updated else for when version is v10.04
        return interface._port_set_untagged_vlan(l2_port_name, vlan_id, **kwargs)