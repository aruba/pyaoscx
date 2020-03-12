# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops, interface, port

import json
import random
import logging


def get_all_acls(**kwargs):
    """
    Perform a GET call to get a list of all ACLs

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all ACLs in the table
    """
    target_url = kwargs["url"] + "system/acls"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all ACLs failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all ACLs succeeded")

    acls_list = response.json()
    return acls_list


def create_acl(list_name, list_type, **kwargs):
    """
    Perform a POST call to create an ACL with no entries

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_acl_v1(list_name, list_type, **kwargs)
    else:   # Updated else for when version is v10.04
        return _create_acl(list_name, list_type, **kwargs)


def _create_acl_v1(list_name, list_type, **kwargs):
    """
    Perform a POST call to create an ACL with no entries

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    acls_list = get_all_acls(**kwargs)

    # ACL doesn't exist; create it
    if "/rest/v1/system/acls/%s/%s" % (list_name, list_type) not in acls_list:

        acl_data = {
            "name": list_name,
            "list_type": list_type
        }

        target_url = kwargs["url"] + "system/acls"
        post_data = json.dumps(acl_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating %s ACL '%s' failed with status code %d: %s"
                  % (list_type, list_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating %s ACL '%s' succeeded" % (list_type, list_name))
            return True
    else:
        logging.info("SUCCESS: No need to create %s ACL '%s' since it already exists"
              % (list_type, list_name))
        return True


def _create_acl(list_name, list_type, **kwargs):
    """
    Perform a POST call to create an ACL with no entries

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    acls_list = get_all_acls(**kwargs)

    acl_key = "{},{}".format(list_name,list_type)
    acl_value = "/rest/v10.04/system/acls/" + acl_key

    # ACL doesn't exist; create it
    if acl_value not in acls_list.values():
        acl_data = {
            "name": list_name,
            "list_type": list_type
        }

        target_url = kwargs["url"] + "system/acls"
        post_data = json.dumps(acl_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating %s ACL '%s' failed with status code %d: %s"
                  % (list_type, list_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating %s ACL '%s' succeeded" % (list_type, list_name))
            return True
    else:
        logging.info("SUCCESS: No need to create %s ACL '%s' since it already exists"
              % (list_type, list_name))
        return True


def get_all_acl_entries(list_name, list_type, **kwargs):
    """
    Perform a GET call to get all entries of an ACL

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing queue profile entry URIs
    """
    if kwargs["url"].endswith("/v1/"):
        acl_entries = _get_all_acl_entries_v1(list_name, list_type, **kwargs)
    else:   # Updated else for when version is v10.04
        acl_entries = _get_all_acl_entries(list_name, list_type, **kwargs)

    return acl_entries


def _get_all_acl_entries_v1(list_name, list_type, **kwargs):
    """
    Perform a GET call to get all entries of an ACL

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing queue profile entry URIs
    """
    target_url = kwargs["url"] + "system/acls/%s/%s/cfg_aces" % (list_name, list_type)

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of URIS of entries in %s ACL '%s' failed with status code %d: %s"
              % (list_type, list_name, response.status_code, response.text))
        acl_entries = {}
    else:
        logging.info("SUCCESS: Getting dictionary of URIs of entries in %s ACL '%s' succeeded" % (list_type, list_name))
        acl_entries = response.json()

    # for some reason, this API returns a list when empty, and a dictionary when there is data
    # make this function always return a dictionary,
    if not acl_entries:
        return {}
    else:
        return acl_entries


def _get_all_acl_entries(list_name, list_type, **kwargs):
    """
    Perform a GET call to get all entries of an ACL

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing queue profile entry URIs
    """

    target_url = kwargs["url"] + "system/acls/%s,%s?attributes=cfg_aces" % (list_name, list_type)

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of URIS of entries in %s ACL '%s' failed with status code %d: %s"
              % (list_type, list_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting dictionary of URIs of entries in %s ACL '%s' succeeded" % (list_type, list_name))

    acl_entries = response.json()

    # for some reason, this API returns a list when empty, and a dictionary when there is data
    # make this function always return a dictionary,
    if not acl_entries:
        return {}
    else:
        return acl_entries


def create_acl_entry(list_name, list_type, sequence_num, action, count=None, ip_protocol=None, src_ip=None, dst_ip=None,
                     dst_l4_port_min=None, dst_l4_port_max=None, src_mac=None, dst_mac=None, ethertype=None, **kwargs):
    """
    Perform a POST call to create an ACL entry

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer number of the sequence
    :param action: Action should be either "permit" or "deny"
    :param count: Optional boolean flag that when true, will make entry increment hit count for matched packets
    :param ip_protocol: Optional integer IP protocol number
    :param src_ip: Optional source IP address
    :param dst_ip: Optional destination IP address
    :param dst_l4_port_min: Optional minimum L4 port number in range; used in conjunction with dst_l4_port_max.
    :param dst_l4_port_max: Optional maximum L4 port number in range; used in conjunction with dst_l4_port_min.
    :param src_mac: Optional source MAC address
    :param dst_mac: Optional destination MAC address
    :param ethertype: Optional integer EtherType number
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_acl_entry_v1(list_name, list_type, sequence_num, action, count, ip_protocol, src_ip, dst_ip,
                     dst_l4_port_min, dst_l4_port_max, src_mac, dst_mac, ethertype, **kwargs)
    else:   # Updated else for when version is v10.04
        return _create_acl_entry(list_name, list_type, sequence_num, action, count, ip_protocol, src_ip, dst_ip,
                     dst_l4_port_min, dst_l4_port_max, src_mac, dst_mac, ethertype, **kwargs)


def _create_acl_entry_v1(list_name, list_type, sequence_num, action, count=None, ip_protocol=None, src_ip=None, dst_ip=None,
                     dst_l4_port_min=None, dst_l4_port_max=None, src_mac=None, dst_mac=None, ethertype=None, **kwargs):
    """
    Perform a POST call to create an ACL entry

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer number of the sequence
    :param action: Action should be either "permit" or "deny"
    :param count: Optional boolean flag that when true, will make entry increment hit count for matched packets
    :param ip_protocol: Optional integer IP protocol number
    :param src_ip: Optional source IP address
    :param dst_ip: Optional destination IP address
    :param dst_l4_port_min: Optional minimum L4 port number in range; used in conjunction with dst_l4_port_max.
    :param dst_l4_port_max: Optional maximum L4 port number in range; used in conjunction with dst_l4_port_min.
    :param src_mac: Optional source MAC address
    :param dst_mac: Optional destination MAC address
    :param ethertype: Optional integer EtherType number
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    acl_entries_dict = get_all_acl_entries(list_name, list_type, **kwargs)

    if "/rest/v1/system/acls/%s/%s/cfg_aces/%d" % (list_name, list_type, sequence_num) not in acl_entries_dict.values():
        acl_entry_data = {
            "sequence_number": sequence_num,
            "action": action
        }

        if count is not None:
            acl_entry_data["count"] = count

        if ip_protocol is not None:
            acl_entry_data["protocol"] = ip_protocol

        if src_ip is not None:
            acl_entry_data["src_ip"] = src_ip

        if dst_ip is not None:
            acl_entry_data["dst_ip"] = dst_ip

        if dst_l4_port_min is not None:
            acl_entry_data["dst_l4_port_min"] = dst_l4_port_min

        if dst_l4_port_max is not None:
            acl_entry_data["dst_l4_port_max"] = dst_l4_port_max

        if src_mac is not None:
            acl_entry_data["src_mac"] = src_mac

        if dst_mac is not None:
            acl_entry_data["dst_mac"] = dst_mac

        if ethertype is not None:
            acl_entry_data["ethertype"] = ethertype

        target_url = kwargs["url"] + "system/acls/%s/%s/cfg_aces" % (list_name, list_type)
        post_data = json.dumps(acl_entry_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating entry %d for %s ACL '%s' failed with status code %d: %s"
                  % (sequence_num, list_type, list_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating entry %d for %s ACL '%s' succeeded" % (sequence_num, list_type, list_name))
            return True
    else:
        logging.info("SUCCESS: No need to create entry %d for %s ACL '%s' since it already exists"
              % (sequence_num, list_type, list_name))
        return True


def _create_acl_entry(list_name, list_type, sequence_num, action, count=None, ip_protocol=None, src_ip=None, dst_ip=None,
                     dst_l4_port_min=None, dst_l4_port_max=None, src_mac=None, dst_mac=None, ethertype=None, **kwargs):
    """
    Perform a POST call to create an ACL entry

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer number of the sequence
    :param action: Action should be either "permit" or "deny"
    :param count: Optional boolean flag that when true, will make entry increment hit count for matched packets
    :param ip_protocol: Optional integer IP protocol number
    :param src_ip: Optional source IP address
    :param dst_ip: Optional destination IP address
    :param dst_l4_port_min: Optional minimum L4 port number in range; used in conjunction with dst_l4_port_max.
    :param dst_l4_port_max: Optional maximum L4 port number in range; used in conjunction with dst_l4_port_min.
    :param src_mac: Optional source MAC address
    :param dst_mac: Optional destination MAC address
    :param ethertype: Optional integer EtherType number
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    acl_entries_dict = get_all_acl_entries(list_name, list_type, **kwargs)

    ace_key = "{},{}".format(list_name,list_type)
    ace_value = "/rest/v10.04/system/acls/" + ace_key + "/" + str(sequence_num)

    if ace_value not in acl_entries_dict.values():
        acl_entry_data = {
            "sequence_number": sequence_num,
            "action": action,
        }

        if count is not None:
            acl_entry_data["count"] = count

        if ip_protocol is not None:
            acl_entry_data["protocol"] = ip_protocol

        if src_ip is not None:
            acl_entry_data["src_ip"] = src_ip

        if dst_ip is not None:
            acl_entry_data["dst_ip"] = dst_ip

        if dst_l4_port_min is not None:
            acl_entry_data["dst_l4_port_min"] = dst_l4_port_min

        if dst_l4_port_max is not None:
            acl_entry_data["dst_l4_port_max"] = dst_l4_port_max

        if src_mac is not None:
            acl_entry_data["src_mac"] = src_mac

        if dst_mac is not None:
            acl_entry_data["dst_mac"] = dst_mac

        if ethertype is not None:
            acl_entry_data["ethertype"] = ethertype

        target_url = kwargs["url"] + "system/acls/%s/cfg_aces" % ace_key
        post_data = json.dumps(acl_entry_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating entry %d for %s ACL '%s' failed with status code %d: %s"
                  % (sequence_num, list_type, list_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating entry %d for %s ACL '%s' succeeded" % (sequence_num, list_type, list_name))
            return True
    else:
        logging.info("SUCCESS: No need to create entry %d for %s ACL '%s' since it already exists"
              % (sequence_num, list_type, list_name))
        return True


def get_acl(list_name, list_type, **kwargs):
    """
    Perform a GET call to get details of a particular ACL

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular ACL
    """

    if kwargs["url"].endswith("/v1/"):
        acl = _get_acl_v1(list_name, list_type, **kwargs)
    else:   # Updated else for when version is v10.04
        acl = _get_acl(list_name, list_type, **kwargs)
    return acl


def _get_acl_v1(list_name, list_type, **kwargs):
    """
    Perform a GET call to get details of a particular ACL

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular ACL
    """
    target_url = kwargs["url"] + "system/acls/%s/%s" % (list_name, list_type)

    payload = {"selector": "configuration"}

    response = kwargs["s"].get(target_url, params=payload, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting %s ACL '%s' failed with status code %d: %s"
              % (list_type, list_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting %s ACL '%s' succeeded" % (list_type, list_name))

    acl = response.json()
    return acl


def _get_acl(list_name, list_type, **kwargs):
    """
    Perform a GET call to get details of a particular ACL

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular ACL
    """
    acl_key = "{},{}".format(list_name, list_type)
    target_url = kwargs["url"] + "system/acls/%s?depth=2&selector=writable" % acl_key

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting %s ACL '%s' failed with status code %d: %s"
              % (list_type, list_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting %s ACL '%s' succeeded" % (list_type, list_name))

    acl = response.json()
    return acl


def update_acl(list_name, list_type, **kwargs):
    """
    Perform a PUT call to version-up an ACL. This is required whenever entries of an ACL are changed
    in any way.

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _update_acl_v1(list_name, list_type, **kwargs)
    else:   # Updated else for when version is v10.04
        return _update_acl(list_name, list_type, **kwargs)


def _update_acl_v1(list_name, list_type, **kwargs):
    """
    Perform a PUT call to version-up an ACL. This is required whenever entries of an ACL are changed
    in any way.

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    acl_data = get_acl(list_name, list_type, **kwargs)

    # must remove these fields from the data since they can't be modified
    acl_data.pop('name', None)
    acl_data.pop('list_type', None)

    acl_data['cfg_version'] = random.randint(-9007199254740991, 9007199254740991)

    target_url = kwargs["url"] + "system/acls/%s/%s" % (list_name, list_type)
    put_data = json.dumps(acl_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating %s ACL '%s' failed with status code %d: %s"
              % (list_type, list_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating %s ACL '%s' succeeded" % (list_type, list_name))
        return True


def _update_acl(list_name, list_type, **kwargs):
    """
    Perform a PUT call to version-up an ACL. This is required whenever entries of an ACL are changed
    in any way.

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    acl_data = get_acl(list_name, list_type, **kwargs)
    acl_key = "{},{}".format(list_name, list_type)

    acl_data['cfg_version'] = random.randint(-9007199254740991, 9007199254740991)
    target_url = kwargs["url"] + "system/acls/%s" % acl_key
    put_data = json.dumps(acl_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating %s ACL '%s' failed with status code %d: %s"
              % (list_type, list_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating %s ACL '%s' succeeded" % (list_type, list_name))
        return True


def delete_acl(list_name, list_type, **kwargs):
    """
    Perform a DELETE call to delete an ACL

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    acls_list = get_all_acls(**kwargs)

    if "/rest/v1/system/acls/%s/%s" % (list_name, list_type) in acls_list:

        target_url = kwargs["url"] + "system/acls/%s/%s" % (list_name, list_type)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting %s ACL '%s' failed with status code %d: %s"
                  % (list_type, list_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting %s ACL '%s' succeeded" % (list_type, list_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete %s ACL '%s' since it doesn't exist"
              % (list_type, list_name))
        return True


def delete_acl_entry(list_name, list_type, sequence_num, **kwargs):
    """
    Perform a DELETE call to delete an ACL entry

    :param list_name: Alphanumeric name of the ACL
    :param list_type: Type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer ID for the entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    acl_entries_dict = get_all_acl_entries(list_name, list_type, **kwargs)

    if "/rest/v1/system/acls/%s/%s/cfg_aces/%d" % (list_name, list_type, sequence_num) in acl_entries_dict.values():

        target_url = kwargs["url"] + "system/acls/%s/%s/cfg_aces/%d" % (list_name, list_type, sequence_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in %s ACL '%s' failed with status code %d: %s"
                  % (sequence_num, list_type, list_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in %s ACL '%s' succeeded"
                  % (sequence_num, list_type, list_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in %s ACL '%s' since it doesn't exist"
              % (sequence_num, list_type, list_name))
        return True


def update_port_acl_in(interface_name, acl_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to apply ACL on an interface. This function specifically applies an ACL
    to Ingress traffic of the interface

    :param interface_name: Alphanumeric String that is the name of the interface on which the ACL
        is applied to
    :param acl_name: Alphanumeric String that is the name of the ACL
    :param list_type: Alphanumeric String of ipv4 or ipv6 to specify the type of ACL
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _update_port_acl_in_v1(interface_name, acl_name, list_type, **kwargs)
    else:   # Updated else for when version is v10.04
        return _update_port_acl_in(interface_name, acl_name, list_type, **kwargs)


def _update_port_acl_in_v1(interface_name, acl_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to apply ACL on an interface. This function specifically applies an ACL
    to Ingress traffic of the interface

    :param interface_name: Alphanumeric String that is the name of the interface on which the ACL
        is applied to
    :param acl_name: Alphanumeric String that is the name of the ACL
    :param list_type: Alphanumeric String of ipv4 or ipv6 to specify the type of ACL
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

    acl_url = "/rest/v1/system/acls/%s/%s" % (acl_name, list_type)

    if list_type is "ipv6":
        port_data['aclv6_in_cfg'] = acl_url
        port_data['aclv6_in_cfg_version'] = random.randint(-9007199254740991, 9007199254740991)
    elif list_type is "ipv4":
        port_data['aclv4_in_cfg'] = acl_url
        port_data['aclv4_in_cfg_version'] = random.randint(-9007199254740991, 9007199254740991)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Applying ACL '%s' to Ingress of Interface '%s' failed with status code %d: %s"
              % (acl_name, interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Applying ACL '%s' to Ingress of Interface '%s' succeeded"
              % (acl_name, interface_name))
        return True


def _update_port_acl_in(interface_name, acl_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to apply ACL on an interface. This function specifically applies an ACL
    to Ingress traffic of the interface.  This function's minimum supported version is v10.04 and later

    :param interface_name: Alphanumeric name of the interface on which the ACL is applied to
    :param acl_name: Alphanumeric name of the ACL
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    int_name_percents = common_ops._replace_special_characters(interface_name)
    int_data = interface.get_interface(int_name_percents, depth=1, selector="writable", **kwargs)

    acl_key = "{},{}".format(acl_name,list_type)
    acl_value = kwargs["url"] + "system/acls/" + acl_key

    if interface_name.startswith('lag'):
        if int_data['interfaces']:
            int_data['interfaces'] = common_ops._dictionary_to_list_values(int_data['interfaces'])

    if list_type is "ipv6":
        int_data['aclv6_in_cfg'] = {acl_key: acl_value}
        int_data['aclv6_in_cfg_version'] = random.randint(-9007199254740991, 9007199254740991)
    elif list_type is "ipv4":
        int_data['aclv4_in_cfg'] = {acl_key: acl_value}
        int_data['aclv4_in_cfg_version'] = random.randint(-9007199254740991, 9007199254740991)

    target_url = kwargs["url"] + "system/interfaces/%s" % int_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating ACL %s on Ingress for Port '%s' failed with status code %d: %s"
              % (acl_name, interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating ACL %s on Ingress for Port '%s' succeeded"
              % (acl_name, interface_name))
        return True


def clear_port_acl_in(port_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's Ingress ACL

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _clear_port_acl_in_v1(port_name, list_type, **kwargs)
    else:   # Updated else for when version is v10.04
        return _clear_port_acl_in(port_name, list_type, **kwargs)


def _clear_port_acl_in_v1(port_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's Ingress ACL

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name, depth=0, selector="configuration", **kwargs)

    if not port_data:
        logging.warning("FAIL: Unable to clear %s Ingress ACL on Port '%s' because Port not found"
              % (list_type, port_name))
        return False
    else:
        if list_type is "ipv6":
            port_data.pop('aclv6_in_cfg', None)
            port_data.pop('aclv6_in_cfg_version', None)
        elif list_type is "ipv4":
            port_data.pop('aclv4_in_cfg', None)
            port_data.pop('aclv4_in_cfg_version', None)
        # must remove these fields from the data since they can't be modified
        port_data.pop('name', None)
        port_data.pop('origin', None)

        target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
        put_data = json.dumps(port_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Clearing %s Ingress ACL on Port '%s' failed with status code %d: %s"
                  % (list_type, port_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Clearing %s Ingress ACL on Port '%s' succeeded"
                  % (list_type, port_name))
            return True


def _clear_port_acl_in(port_name, list_type, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's Ingress ACL

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = interface.get_interface(port_name, depth=1, selector="writable", **kwargs)
    if list_type is "ipv6":
        port_data.pop('aclv6_in_cfg', None)
        port_data.pop('aclv6_in_cfg_version', None)
    elif list_type is "ipv4":
        port_data.pop('aclv4_in_cfg', None)
        port_data.pop('aclv4_in_cfg_version', None)

    target_url = kwargs["url"] + "system/interface/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)
    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing %s Ingress ACL on Port '%s' failed with status code %d: %s"
              % (list_type, port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing %s Ingress ACL on Port '%s' succeeded"
              % (list_type, port_name))
        return True


def update_port_acl_out(interface_name, acl_name, **kwargs):
    """
    Perform GET and PUT calls to apply ACL on an L3 interface. This function specifically applies an ACL
    to Egress traffic of the interface, which must be a routing interface

    :param interface_name: Alphanumeric String that is the name of the interface on which the ACL
        is applied to
    :param acl_name: Alphanumeric String that is the name of the ACL
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _update_port_acl_out_v1(interface_name, acl_name, **kwargs)
    else:   # Updated else for when version is v10.04
        return _update_port_acl_out(interface_name, acl_name, **kwargs)


def _update_port_acl_out_v1(interface_name, acl_name, **kwargs):
    """
    Perform GET and PUT calls to apply ACL on an L3 interface. This function specifically applies an ACL
    to Egress traffic of the interface, which must be a routing interface.  This function will set the interface
    to enable routing.

    :param interface_name: Alphanumeric String that is the name of the interface on which the ACL
        is applied to
    :param acl_name: Alphanumeric String that is the name of the ACL
    :param list_type: Alphanumeric String of ipv4 or ipv6 to specify the type of ACL
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

    acl_url = "/rest/v1/system/acls/%s/ipv4" % acl_name

    port_data['aclv4_out_cfg'] = acl_url
    port_data['aclv4_out_cfg_version'] = random.randint(-9007199254740991, 9007199254740991)
    port_data['routing'] = True

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Applying ACL '%s' to Egress on Interface '%s' failed with status code %d: %s"
              % (acl_name, interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Applying ACL '%s' to Egress on Interface '%s' succeeded"
              % (acl_name, interface_name))
        return True


def _update_port_acl_out(interface_name, acl_name, **kwargs):
    """
    Perform GET and PUT calls to apply ACL on an interface. This function specifically applies an ACL
    to Egress traffic of the interface, which must be a routing interface.  This function will set the interface
    to enable routing.

    :param interface_name: Alphanumeric name of the interface on which the ACL is applied to
    :param acl_name: Alphanumeric name of the ACL
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(interface_name)
    port_data = interface.get_interface(port_name_percents, depth=1, selector="writable", **kwargs)

    acl_key = "{},ipv4".format(acl_name)
    acl_value = kwargs["url"] + "system/acls/" + acl_key
    port_data['aclv4_out_cfg'] = {acl_key: acl_value}
    port_data['aclv4_out_cfg_version'] = random.randint(-9007199254740991, 9007199254740991)
    port_data['routing'] = True

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Applying ACL '%s' to Egress on Interface '%s' failed with status code %d: %s"
              % (acl_name, interface_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Applying ACL '%s' to Egress on Interface '%s' succeeded"
              % (acl_name, interface_name))
        return True


def clear_interface_acl(interface_name, acl_type="aclv4_out", **kwargs):
    """
    Perform GET and PUT calls to clear an interface's ACL

    :param interface_name: Alphanumeric name of the interface
    :param acl_type: Type of ACL, options are between 'aclv4_out', 'aclv4_in', and 'aclv6_in'
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return port._clear_port_acl(interface_name, acl_type, **kwargs)
    else:   # Updated else for when version is v10.04
        return interface._clear_interface_acl(interface_name, acl_type, **kwargs)
