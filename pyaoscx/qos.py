# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops
from pyaoscx import system
from pyaoscx import port
from pyaoscx import interface

import json
import random
import logging


def get_all_queue_profiles(**kwargs):
    """
    Perform a GET call to get a list of all QoS queue profiles

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all QoS queue profiles in the table
    """

    if kwargs["url"].endswith("/v1/"):
        queue_profiles = _get_all_queue_profiles_v1(**kwargs)
    else:   # Updated else for when version is v10.04
        queue_profiles = _get_all_queue_profiles(**kwargs)
    return queue_profiles


def _get_all_queue_profiles_v1(**kwargs):
    """
    Perform a GET call to get a list of all QoS queue profiles

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all QoS queue profiles in the table
    """
    target_url = kwargs["url"] + "system/q_profiles"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all QoS queue profiles failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all QoS queue profiles succeeded")

    queue_profiles_list = response.json()
    return queue_profiles_list


def _get_all_queue_profiles(**kwargs):
    """
    Perform a GET call to get a dictionary containing all QoS queue profiles

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all QoS queue profiles in the table
    """
    target_url = kwargs["url"] + "system/q_profiles"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all QoS queue profiles failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all QoS queue profiles succeeded")

    queue_profiles_dict = response.json()
    return queue_profiles_dict


def create_queue_profile(profile_name, **kwargs):
    """
    Perform a POST call to create a QoS queue profile with no entries

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_queue_profile_v1(profile_name, **kwargs)
    else:   # Updated else for when version is v10.04
        return _create_queue_profile(profile_name, **kwargs)


def _create_queue_profile_v1(profile_name, **kwargs):
    """
    Perform a POST call to create a QoS queue profile with no entries

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    queue_profiles_list = get_all_queue_profiles(**kwargs)

    # Queue profile doesn't exist; create it
    if "/rest/v1/system/q_profiles/%s" % profile_name not in queue_profiles_list:

        queue_profile_data = {
            "name": profile_name
        }

        target_url = kwargs["url"] + "system/q_profiles"
        post_data = json.dumps(queue_profile_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating queue profile '%s' failed with status code %d: %s"
                            % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating queue profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to create queue profile '%s' since it already exists"
              % profile_name)
        return True


def _create_queue_profile(profile_name, **kwargs):
    """
    Perform a POST call to create a QoS queue profile with no entries

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    queue_profiles_dict = _get_all_queue_profiles(**kwargs)

    # Queue profile doesn't exist; create it
    if profile_name not in queue_profiles_dict:

        queue_profile_data = {
            "name": profile_name
        }

        target_url = kwargs["url"] + "system/q_profiles"
        post_data = json.dumps(queue_profile_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating queue profile '%s' failed with status code %d: %s"
                            % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating queue profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to create queue profile '%s' since it already exists"
              % profile_name)
        return True


def get_all_queue_profile_entries(profile_name, **kwargs):
    """
    Perform a GET call to get all entries of a QoS queue profile

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing queue profile entry URIs
    """

    if kwargs["url"].endswith("/v1/"):
        queue_profile_entries = _get_all_queue_profile_entries_v1(profile_name, **kwargs)
    else:  # Updated else for when version is v10.04
        queue_profile_entries = _get_all_queue_profile_entries(profile_name, **kwargs)
    return queue_profile_entries


def _get_all_queue_profile_entries_v1(profile_name, **kwargs):
    """
    Perform a GET call to get all entries of a QoS queue profile

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing queue profile entry URIs
    """

    target_url = kwargs["url"] + "system/q_profiles/%s/q_profile_entries" % profile_name

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of URIs of entries in QoS queue profile '%s' failed with status code %d: %s"
              % (profile_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting dictionary of URIs of entries in QoS queue profile '%s' succeeded" % profile_name)

    queue_profile_entries = response.json()

    # for some reason, this API returns a list when empty, and a dictionary when there is data
    # make this function always return a dictionary,
    if not queue_profile_entries:
        return {}
    else:
        return queue_profile_entries


def _get_all_queue_profile_entries(profile_name, **kwargs):
    """
    Perform a GET call to get all entries of a QoS queue profile

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing queue profile entry URIs
    """

    target_url = kwargs["url"] + "system/q_profiles/%s/q_profile_entries" % profile_name

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of URIs of entries in QoS queue profile '%s' failed with status code %d: %s"
              % (profile_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting dictionary of URIs of entries in QoS queue profile '%s' succeeded" % profile_name)

    queue_profile_entries_dict = response.json()

    return queue_profile_entries_dict


# Same for both v1 and v3?
def create_queue_profile_entry(profile_name, queue_num, local_priorities, desc=None, **kwargs):
    """
    Perform a POST call to create a QoS queue profile entry

    :param profile_name: Alphanumeric name of the queue profile
    :param queue_num: Integer number of the entry
    :param local_priorities: List of integers, each item being a local priority
    :param desc: Optional description for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    queue_profile_entry_data = {
        "queue_number": queue_num,
        "local_priorities": local_priorities
    }

    if desc is not None:
        queue_profile_entry_data["description"] = desc

    target_url = kwargs["url"] + "system/q_profiles/%s/q_profile_entries" % profile_name
    post_data = json.dumps(queue_profile_entry_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating entry %d for queue profile '%s' failed with status code %d: %s"
              % (queue_num, profile_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating entry %d for queue profile '%s' succeeded" % (queue_num, profile_name))
        return True


def get_all_schedule_profiles(**kwargs):
    """
    Perform a GET call to get a list of all QoS schedule profiles

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all QoS schedule profiles in the table
    """

    if kwargs["url"].endswith("/v1/"):
        schedule_profiles = _get_all_schedule_profiles_v1(**kwargs)
    else:  # Updated else for when version is v10.04
        schedule_profiles = _get_all_schedule_profiles(**kwargs)
    return schedule_profiles


def _get_all_schedule_profiles_v1(**kwargs):
    """
    Perform a GET call to get a list of all QoS schedule profiles

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all QoS schedule profiles in the table
    """
    target_url = kwargs["url"] + "system/qos"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all QoS schedule profiles failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all QoS schedule profiles succeeded")

    schedule_profiles_list = response.json()
    return schedule_profiles_list


def _get_all_schedule_profiles(**kwargs):
    """
    Perform a GET call to get a dictionary containing all QoS schedule profiles

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all QoS schedule profiles in the table
    """
    target_url = kwargs["url"] + "system/qos"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all QoS schedule profiles failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all QoS schedule profiles succeeded")

    schedule_profiles_dict = response.json()
    return schedule_profiles_dict


def create_schedule_profile(profile_name, **kwargs):
    """
    Perform a POST call to create a QoS schedule profile with no entries

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_schedule_profile_v1(profile_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_schedule_profile(profile_name, **kwargs)


def _create_schedule_profile_v1(profile_name, **kwargs):
    """
    Perform a POST call to create a QoS schedule profile with no entries

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    schedule_profiles_list = get_all_schedule_profiles(**kwargs)

    # Schedule profile doesn't exist; create it
    if "/rest/v1/system/qos/%s" % profile_name not in schedule_profiles_list:

        schedule_profile_data = {
            "name": profile_name
        }

        target_url = kwargs["url"] + "system/qos"
        post_data = json.dumps(schedule_profile_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating schedule profile '%s' failed with status code %d: %s"
                  % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating schedule profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to create schedule profile '%s' since it already exists"
              % profile_name)
        return True


def _create_schedule_profile(profile_name, **kwargs):
    """
    Perform a POST call to create a QoS schedule profile with no entries

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    schedule_profiles_dict = _get_all_schedule_profiles(**kwargs)

    # Schedule profile doesn't exist; create it
    if profile_name not in schedule_profiles_dict:

        schedule_profile_data = {
            "name": profile_name
        }

        target_url = kwargs["url"] + "system/qos"
        post_data = json.dumps(schedule_profile_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating schedule profile '%s' failed with status code %d: %s"
                  % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating schedule profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to create schedule profile '%s' since it already exists"
              % profile_name)
        return True


def get_all_schedule_profile_entries(profile_name, **kwargs):
    """
    Perform a GET call to get all entries of a QoS schedule profile

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing schedule profile entry URIs
    """

    if kwargs["url"].endswith("/v1/"):
        schedule_profile_entries = _get_all_schedule_profile_entries_v1(profile_name, **kwargs)
    else:  # Updated else for when version is v10.04
        schedule_profile_entries = _get_all_schedule_profile_entries(profile_name, **kwargs)
    return schedule_profile_entries


def _get_all_schedule_profile_entries_v1(profile_name, **kwargs):
    """
    Perform a GET call to get all entries of a QoS schedule profile

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing schedule profile entry URIs
    """

    target_url = kwargs["url"] + "system/qos/%s/queues" % profile_name

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of URIs of entries in QoS schedule profile '%s' failed with status code %d: %s"
              % (profile_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting dictionary of URIs of entries in QoS schedule profile '%s' succeeded" % profile_name)

    schedule_profile_entries = response.json()

    # for some reason, this API returns a list when empty, and a dictionary when there is data
    # make this function always return a dictionary
    if not schedule_profile_entries:
        return {}
    else:
        return schedule_profile_entries


def _get_all_schedule_profile_entries(profile_name, **kwargs):
    """
    Perform a GET call to get all entries of a QoS schedule profile

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing schedule profile entry URIs
    """

    target_url = kwargs["url"] + "system/qos/%s/queues" % profile_name

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of URIs of entries in QoS schedule profile '%s' failed with status code %d: %s"
              % (profile_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting dictionary of URIs of entries in QoS schedule profile '%s' succeeded" % profile_name)

    schedule_profile_entries = response.json()

    return schedule_profile_entries


def create_schedule_profile_entry(profile_name, queue_num, algorithm="strict", bandwidth=None,
                                  burst_size=None, weight=None, **kwargs):
    """
    Perform a POST call to create a QoS schedule profile entry

    :param profile_name: Alphanumeric name of the schedule profile
    :param queue_num: Integer number of queue
    :param algorithm: Algorithm type should be "strict," "dwrr," or "wfq." Defaults to "strict" if not specified.
    :param bandwidth: Optional bandwidth limit (in kilobits/s) to apply to egress queue traffic
    :param burst_size: Optional burst size (in kilobytes) allowed per bandwidth-limited queue
    :param weight: Optional weight value for the queue. The maximum weight is hardware-dependent.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    schedule_profile_entry_data = {
        "queue_number": queue_num,
        "algorithm": algorithm
    }

    if bandwidth is not None:
        schedule_profile_entry_data['bandwidth'] = bandwidth

    if burst_size is not None:
        schedule_profile_entry_data['burst'] = burst_size

    if weight is not None:
        schedule_profile_entry_data['weight'] = weight

    target_url = kwargs["url"] + "system/qos/%s/queues" % profile_name
    post_data = json.dumps(schedule_profile_entry_data, sort_keys=True, indent=4)

    response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

    if not common_ops._response_ok(response, "POST"):
        logging.warning("FAIL: Creating entry %d for schedule profile '%s' failed with status code %d: %s"
              % (queue_num, profile_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Creating entry %d for schedule profile '%s' succeeded" % (queue_num, profile_name))
        return True


def apply_profiles_globally(queue_profile_name, schedule_profile_name, **kwargs):
    """
    Perform GET and PUT calls to apply a QoS queue profile and schedule profile on all interfaces.

    :param queue_profile_name: Alphanumeric name of the queue profile
    :param schedule_profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _apply_profiles_globally_v1(queue_profile_name, schedule_profile_name, **kwargs)
    else:   # Updated else for when version is v10.04
        return _apply_profiles_globally(queue_profile_name, schedule_profile_name, **kwargs)


def _apply_profiles_globally_v1(queue_profile_name, schedule_profile_name, **kwargs):
    """
    Perform GET and PUT calls to apply a QoS queue profile and schedule profile on all interfaces.

    :param queue_profile_name: Alphanumeric name of the queue profile
    :param schedule_profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data['q_profile_default'] = queue_profile_name
    system_data['qos_default'] = schedule_profile_name

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Applying queue profile '%s' and schedule profile '%s' globally failed with status code %d: %s"
              % (queue_profile_name, schedule_profile_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Applying queue profile '%s' and schedule profile '%s' globally succeeded"
              % (queue_profile_name, schedule_profile_name))
        return True


def _apply_profiles_globally(queue_profile_name, schedule_profile_name, **kwargs):
    """
    Perform GET and PUT calls to apply a QoS queue profile and schedule profile on all interfaces.

    :param queue_profile_name: Alphanumeric name of the queue profile
    :param schedule_profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data['q_profile_default'] = queue_profile_name
    system_data['qos_default'] = schedule_profile_name

    system_data.pop('syslog_remotes', None)
    system_data.pop('vrfs', None)
    system_data.pop('mirrors', None)
    system_data.pop('all_user_copp_policies', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Applying queue profile '%s' and schedule profile '%s' globally failed with status code %d: %s"
              % (queue_profile_name, schedule_profile_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Applying queue profile '%s' and schedule profile '%s' globally succeeded"
              % (queue_profile_name, schedule_profile_name))
        return True


def apply_profile_interface(port_name, schedule_profile_name, **kwargs):
    """
    Perform GET and PUT calls to apply QoS schedule profile on an interface. If there is a globally applied
    schedule profile, this function will override the specified interface with the specified schedule profile.

    :param port_name: Alphanumeric name of the Port on which the schedule profile is to be applied
    :param schedule_profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _apply_profile_interface_v1(port_name, schedule_profile_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _apply_profile_interface(port_name, schedule_profile_name, **kwargs)


def _apply_profile_interface_v1(port_name, schedule_profile_name, **kwargs):
    """
    Perform GET and PUT calls to apply QoS schedule profile on an interface. If there is a globally applied
    schedule profile, this function will override the specified interface with the specified schedule profile.

    :param port_name: Alphanumeric name of the Port on which the schedule profile is to be applied
    :param schedule_profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    port_data = port.get_port(port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data['qos'] = schedule_profile_name

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating QoS schedule profile for Port '%s' to '%s' failed with status code %d: %s"
              % (port_name, schedule_profile_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating QoS schedule profile for Port '%s' to '%s' succeeded"
              % (port_name, schedule_profile_name))
        return True


# This is going to have to change since it's a port-interface thing
def _apply_profile_interface(port_name, schedule_profile_name, **kwargs):
    """
    Perform GET and PUT calls to apply QoS schedule profile on an interface. If there is a globally applied
    schedule profile, this function will override the specified interface with the specified schedule profile.

    :param port_name: Alphanumeric name of the Port on which the schedule profile is to be applied
    :param schedule_profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    port_data = port.get_port(port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data['qos'] = schedule_profile_name

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating QoS schedule profile for Port '%s' to '%s' failed with status code %d: %s"
              % (port_name, schedule_profile_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating QoS schedule profile for Port '%s' to '%s' succeeded"
              % (port_name, schedule_profile_name))
        return True


def set_trust_globally(trust_mode, **kwargs):
    """
    Perform GET and PUT calls to set QoS trust mode on all interfaces.

    :param trust_mode: Trust mode should be one of "none," "cos," or "dscp."
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _set_trust_globally_v1(trust_mode, **kwargs)
    else:  # Updated else for when version is v10.04
        return _set_trust_globally(trust_mode, **kwargs)


def _set_trust_globally_v1(trust_mode, **kwargs):
    """
    Perform GET and PUT calls to set QoS trust mode on all interfaces.

    :param trust_mode: Trust mode should be one of "none," "cos," or "dscp."
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data['qos_config'] = {"qos_trust": trust_mode}

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting QoS trust mode globally to '%s' failed with status code %d: %s"
              % (trust_mode, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting QoS trust mode globally to '%s' succeeded" % trust_mode)
        return True


def _set_trust_globally(trust_mode, **kwargs):
    """
    Perform GET and PUT calls to set QoS trust mode on all interfaces.

    :param trust_mode: Trust mode should be one of "none," "cos," or "dscp."
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data['qos_config'] = {"qos_trust": trust_mode}

    system_data.pop('syslog_remotes', None)
    system_data.pop('vrfs', None)
    system_data.pop('mirrors', None)
    system_data.pop('all_user_copp_policies', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Setting QoS trust mode globally to '%s' failed with status code %d: %s"
              % (trust_mode, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Setting QoS trust mode globally to '%s' succeeded" % trust_mode)
        return True


def set_trust_interface(port_name, trust_mode, **kwargs):
    """
    Perform GET and PUT calls to set QoS trust mode on an interface. If there is a globally applied
    trust mode, this function will override the specified interface with the specified trust mode.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param trust_mode: Trust mode should be one of "none," "cos," or "dscp."
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _set_trust_interface_v1(port_name, trust_mode, **kwargs)
    else:  # Updated else for when version is v10.04
        return _set_trust_interface(port_name, trust_mode, **kwargs)

        
def _set_trust_interface_v1(port_name, trust_mode, **kwargs):
    """
    Perform GET and PUT calls to set QoS trust mode on an interface. If there is a globally applied
    trust mode, this function will override the specified interface with the specified trust mode.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param trust_mode: Trust mode should be one of "none," "cos," or "dscp."
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    port_data = port.get_port(port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data['qos_config'] = {'qos_trust': trust_mode}

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating QoS trust mode for Port '%s' to '%s' failed with status code %d: %s"
              % (port_name, trust_mode, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating QoS trust mode for Port '%s' to '%s' succeeded"
              % (port_name, trust_mode))
        return True


def _set_trust_interface(port_name, trust_mode, **kwargs):
    """
    Perform GET and PUT calls to set QoS trust mode on an interface. If there is a globally applied
    trust mode, this function will override the specified interface with the specified trust mode.

    :param port_name: Alphanumeric name of the Interface on which the trust mode is to be set
    :param trust_mode: Trust mode should be one of "none," "cos," or "dscp."
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    int_data = interface.get_interface(port_name_percents, 1, "writable", **kwargs)

    if port_name.startswith('lag'):
        if int_data['interfaces']:
            int_data['interfaces'] = common_ops._dictionary_to_list_values(int_data['interfaces'])

    int_data['qos_config'] = {'qos_trust': trust_mode}

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating QoS trust mode for Interface '%s' to '%s' failed with status code %d: %s"
              % (port_name, trust_mode, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating QoS trust mode for Interface '%s' to '%s' succeeded"
              % (port_name, trust_mode))
        return True

# Same for v1 and v3?
def remap_dscp_entry(code_point, color=None, desc=None, local_priority=None, **kwargs):
    """
    Perform PUT call to modify the DSCP code point entry.

    :param code_point: Integer identifying the DSCP map code point entry.
    :param color: Optional color used for packet-drop decisions. Should be one of "red," "yellow," or "green."
        If not specified, defaults to the factory default color for the given code point.
    :param desc: Optional description for the DSCP code point entry. If not specified, defaults to the factory default
        description for the given code point.
    :param local_priority: Optional local priority to associate to incoming packets. If not specified, defaults to the
        factory default local priority for the given code point.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    code_point_entry_data = {}
    if color is not None:
        code_point_entry_data['color'] = color

    if desc is not None:
        code_point_entry_data['description'] = desc

    if local_priority is not None:
        code_point_entry_data['local_priority'] = local_priority

    target_url = kwargs["url"] + "system/qos_dscp_map_entries/%d" % code_point
    put_data = json.dumps(code_point_entry_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating QoS DSCP map entry for code point '%d' failed with status code %d: %s"
              % (code_point, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating QoS DSCP map entry for code point '%d' succeeded"
              % code_point)
        return True


def get_all_classes(**kwargs):
    """
    Perform a GET call to get a list of all traffic classes

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all traffic classes in the table
    """

    if kwargs["url"].endswith("/v1/"):
        traffic_classes = _get_all_classes_v1(**kwargs)
    else:  # Updated else for when version is v10.04
        traffic_classes = _get_all_classes(**kwargs)
    return traffic_classes


def _get_all_classes_v1(**kwargs):
    """
    Perform a GET call to get a list of all traffic classes

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all traffic classes in the table
    """
    target_url = kwargs["url"] + "system/classes"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all traffic classes failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all traffic classes succeeded")

    traffic_classes_list = response.json()
    return traffic_classes_list


def _get_all_classes(**kwargs):
    """
    Perform a GET call to get a dictionary containing all traffic classes

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all traffic classes in the table
    """
    target_url = kwargs["url"] + "system/classes"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all traffic classes failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all traffic classes succeeded")

    traffic_classes_dict = response.json()
    return traffic_classes_dict


def get_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a GET call to get details of a particular traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular traffic class
    """
    if kwargs["url"].endswith("/v1/"):
        traffic_class = _get_traffic_class_v1(class_name, class_type, **kwargs)
    else:  # Updated else for when version is v10.04
        traffic_class = _get_traffic_class(class_name, class_type, **kwargs)
    return traffic_class


def _get_traffic_class_v1(class_name, class_type, **kwargs):
    """
    Perform a GET call to get details of a particular traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular traffic class
    """
    target_url = kwargs["url"] + "system/classes/%s/%s" % (class_name, class_type)

    payload = {"selector": "configuration"}

    response = kwargs["s"].get(target_url, params=payload, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting '%s' traffic class '%s' failed with status code %d: %s"
              % (class_type, class_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting '%s' traffic class '%s' succeeded" % (class_type, class_name))

    traffic_class = response.json()
    return traffic_class


def _get_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a GET call to get details of a particular traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular traffic class
    """
    target_url = kwargs["url"] + "system/classes/%s,%s" % (class_name, class_type)

    payload = {"selector": "writable", "depth": 2}

    response = kwargs["s"].get(target_url, params=payload, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting '%s' traffic class '%s' failed with status code %d: %s"
              % (class_type, class_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting '%s' traffic class '%s' succeeded" % (class_type, class_name))

    traffic_class = response.json()
    return traffic_class


def create_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a POST call to create a traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_traffic_class_v1(class_name, class_type, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_traffic_class(class_name, class_type, **kwargs)


def _create_traffic_class_v1(class_name, class_type, **kwargs):
    """
    Perform a POST call to create a traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_classes_list = get_all_classes(**kwargs)

    # Traffic class doesn't exist; create it
    if "/rest/v1/system/classes/%s/%s" % (class_name, class_type) not in traffic_classes_list:

        traffic_class_data = {
            "name": class_name,
            "type": class_type
        }

        target_url = kwargs["url"] + "system/classes"
        post_data = json.dumps(traffic_class_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating %s traffic class '%s' failed with status code %d: %s"
                  % (class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating %s traffic class '%s' succeeded"
                  % (class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to create %s traffic class '%s' since it already exists"
              % (class_type, class_name))
        return True


def _create_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a POST call to create a traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_classes_dict = _get_all_classes(**kwargs)

    # Traffic class doesn't exist; create it
    if "%s,%s" % (class_name, class_type) not in traffic_classes_dict:

        traffic_class_data = {
            "name": class_name,
            "type": class_type
        }

        target_url = kwargs["url"] + "system/classes"
        post_data = json.dumps(traffic_class_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating %s traffic class '%s' failed with status code %d: %s"
                  % (class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating %s traffic class '%s' succeeded"
                  % (class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to create %s traffic class '%s' since it already exists"
              % (class_type, class_name))
        return True


def update_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a PUT call to version-up a traffic class. This is required whenever entries of a traffic class are changed
    in any way.

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _update_traffic_class_v1(class_name, class_type, **kwargs)
    else:  # Updated else for when version is v10.04
        return _update_traffic_class(class_name, class_type, **kwargs)


def _update_traffic_class_v1(class_name, class_type, **kwargs):
    """
    Perform a PUT call to version-up a traffic class. This is required whenever entries of a traffic class are changed
    in any way.

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    traffic_class_data = get_traffic_class(class_name, class_type, **kwargs)

    # must remove these fields from the data since they can't be modified
    traffic_class_data.pop('origin', None)
    traffic_class_data.pop('name', None)
    traffic_class_data.pop('type', None)

    traffic_class_data['cfg_version'] = random.randrange(9007199254740991)

    target_url = kwargs["url"] + "system/classes/%s/%s" % (class_name, class_type)
    put_data = json.dumps(traffic_class_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating %s traffic class '%s' failed with status code %d: %s"
              % (class_type, class_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating %s traffic class '%s' succeeded" % (class_type, class_name))
        return True


def _update_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a PUT call to version-up a traffic class. This is required whenever entries of a traffic class are changed
    in any way.

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    traffic_class_data = _get_traffic_class(class_name, class_type, **kwargs)

    # # must remove these fields from the data since they can't be modified
    # traffic_class_data.pop('origin', None)
    # traffic_class_data.pop('name', None)
    # traffic_class_data.pop('type', None)

    traffic_class_data['cfg_version'] = random.randrange(9007199254740991)

    target_url = kwargs["url"] + "system/classes/%s,%s" % (class_name, class_type)
    put_data = json.dumps(traffic_class_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating %s traffic class '%s' failed with status code %d: %s"
              % (class_type, class_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating %s traffic class '%s' succeeded" % (class_type, class_name))
        return True


def get_all_traffic_class_entries(class_name, class_type, **kwargs):
    """
    Perform a GET call to get a list of all traffic class entries

    :param class_name: Alphanumeric name of traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all traffic class entries in the table
    """

    if kwargs["url"].endswith("/v1/"):
        traffic_class_entries = _get_all_traffic_class_entries_v1(class_name, class_type, **kwargs)
    else:  # Updated else for when version is v10.04
        traffic_class_entries = _get_all_traffic_class_entries(class_name, class_type, **kwargs)
    return traffic_class_entries


def _get_all_traffic_class_entries_v1(class_name, class_type, **kwargs):
    """
    Perform a GET call to get a list of all traffic class entries

    :param class_name: Alphanumeric name of traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all traffic class entries in the table
    """
    target_url = kwargs["url"] + "system/classes/%s/%s/cfg_entries" % (class_name, class_type)

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all entries of %s traffic class '%s' failed with status code %d: %s"
              % (class_type, class_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all entries of %s traffic class '%s' succeeded" % (class_type, class_name))

    traffic_class_entries_list = response.json()

    # for some reason, this API returns a list when empty, and a dictionary when there is data
    # make this function always return a dictionary
    if not traffic_class_entries_list:
        return {}
    else:
        return traffic_class_entries_list


def _get_all_traffic_class_entries(class_name, class_type, **kwargs):
    """
    Perform a GET call to get a dictionary containing all traffic class entries

    :param class_name: Alphanumeric name of traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all traffic class entries in the table
    """
    target_url = kwargs["url"] + "system/classes/%s,%s/cfg_entries" % (class_name, class_type)

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all entries of %s traffic class '%s' failed with status code %d: %s"
              % (class_type, class_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all entries of %s traffic class '%s' succeeded" % (class_type, class_name))

    traffic_class_entries_dict = response.json()

    return traffic_class_entries_dict


def create_traffic_class_entry(class_name, class_type, action, sequence_num, ip_protocol=None, src_ip=None,
                               dest_ip=None, **kwargs):
    """
    Perform a POST call to create a traffic class entry

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param action: Action should be either "match" or "ignore"
    :param sequence_num: Integer ID for the entry.
    :param ip_protocol: Optional integer IP protocol number. Defaults to None if not specified. Excluding this parameter
        will make the entry associate to all IP protocols.
    :param src_ip: Optional source IP address. Defaults to None if not specified.
    :param dest_ip:  Optional destination IP address. Defaults to None if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _create_traffic_class_entry_v1(class_name, class_type, action, sequence_num, ip_protocol, src_ip,
                                       dest_ip, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_traffic_class_entry(class_name, class_type, action, sequence_num, ip_protocol, src_ip,
                                    dest_ip, **kwargs)


def _create_traffic_class_entry_v1(class_name, class_type, action, sequence_num, ip_protocol=None, src_ip=None,
                                   dest_ip=None, **kwargs):
    """
    Perform a POST call to create a traffic class entry

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param action: Action should be either "match" or "ignore"
    :param sequence_num: Integer ID for the entry.
    :param ip_protocol: Optional integer IP protocol number. Defaults to None if not specified. Excluding this parameter
        will make the entry associate to all IP protocols.
    :param src_ip: Optional source IP address. Defaults to None if not specified.
    :param dest_ip:  Optional destination IP address. Defaults to None if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_class_entries_dict = get_all_traffic_class_entries(class_name, class_type, **kwargs)

    # Traffic class entry doesn't exist; create it
    if "/rest/v1/system/classes/%s/%s/cfg_entries/%d" % (class_name, class_type, sequence_num) \
            not in traffic_class_entries_dict.values():

        traffic_class_entry_data = {
            "type": action,
            "sequence_number": sequence_num
        }

        if ip_protocol is not None:
            traffic_class_entry_data['protocol'] = ip_protocol

        if src_ip is not None:
            traffic_class_entry_data['src_ip'] = src_ip

        if dest_ip is not None:
            traffic_class_entry_data['dst_ip'] = dest_ip

        target_url = kwargs["url"] + "system/classes/%s/%s/cfg_entries" % (class_name, class_type)
        post_data = json.dumps(traffic_class_entry_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating traffic class entry %d for '%s' traffic class '%s' failed with status code %d: %s"
                  % (sequence_num, class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating traffic class entry %d for '%s' traffic class '%s' succeeded"
                  % (sequence_num, class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to create entry %d for %s traffic class '%s' since it already exists"
              % (sequence_num, class_type, class_name))
        return True


def _create_traffic_class_entry(class_name, class_type, action, sequence_num, ip_protocol=None, src_ip=None,
                                dest_ip=None, **kwargs):
    """
    Perform a POST call to create a traffic class entry

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param action: Action should be either "match" or "ignore"
    :param sequence_num: Integer ID for the entry.
    :param ip_protocol: Optional integer IP protocol number. Defaults to None if not specified. Excluding this parameter
        will make the entry associate to all IP protocols.
    :param src_ip: Optional source IP address. Defaults to None if not specified.
    :param dest_ip:  Optional destination IP address. Defaults to None if not specified.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_class_entries_dict = _get_all_traffic_class_entries(class_name, class_type, **kwargs)

    # Traffic class entry doesn't exist; create it
    if "%d" % sequence_num not in traffic_class_entries_dict:

        traffic_class_entry_data = {
            "type": action,
            "sequence_number": sequence_num
        }

        if ip_protocol is not None:
            traffic_class_entry_data['protocol'] = ip_protocol

        if src_ip is not None:
            traffic_class_entry_data['src_ip'] = src_ip

        if dest_ip is not None:
            traffic_class_entry_data['dst_ip'] = dest_ip

        target_url = kwargs["url"] + "system/classes/%s,%s/cfg_entries" % (class_name, class_type)
        post_data = json.dumps(traffic_class_entry_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating traffic class entry %d for '%s' traffic class '%s' failed with status code %d: %s"
                  % (sequence_num, class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating traffic class entry %d for '%s' traffic class '%s' succeeded"
                  % (sequence_num, class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to create entry %d for %s traffic class '%s' since it already exists"
              % (sequence_num, class_type, class_name))
        return True


def get_all_policies(**kwargs):
    """
    Perform a GET call to get a list of all classifier policies

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all classifier policies in the table
    """

    if kwargs["url"].endswith("/v1/"):
        policies = _get_all_policies_v1(**kwargs)
    else:  # Updated else for when version is v10.04
        policies = _get_all_policies(**kwargs)
    return policies


def _get_all_policies_v1(**kwargs):
    """
    Perform a GET call to get a list of all classifier policies

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all classifier policies in the table
    """
    target_url = kwargs["url"] + "system/policies"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all classifier policies failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all classifier policies succeeded")

    policies_list = response.json()
    return policies_list


def _get_all_policies(**kwargs):
    """
    Perform a GET call to get a dictionary containing all classifier policies

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing all classifier policies in the table
    """
    target_url = kwargs["url"] + "system/policies"

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all classifier policies failed with status code %d: %s"
              % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all classifier policies succeeded")

    policies_dict = response.json()
    return policies_dict


def create_policy(policy_name, **kwargs):
    """
    Perform a POST call to create a classifier policy

    :param policy_name: Alphanumeric name of policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_policy_v1(policy_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_policy(policy_name, **kwargs)


def _create_policy_v1(policy_name, **kwargs):
    """
    Perform a POST call to create a classifier policy

    :param policy_name: Alphanumeric name of policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policies_list = get_all_policies(**kwargs)

    # Policy doesn't exist; create it
    if "/rest/v1/system/policies/%s" % policy_name not in policies_list:

        policy_data = {"name": policy_name}

        target_url = kwargs["url"] + "system/policies"
        post_data = json.dumps(policy_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating classifier policy '%s' failed with status code %d: %s"
                  % (policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating classifier policy '%s' succeeded" % policy_name)
            return True
    else:
        logging.info("SUCCESS: No need to create classifier policy '%s' since it already exists"
              % policy_name)
        return True


def _create_policy(policy_name, **kwargs):
    """
    Perform a POST call to create a classifier policy

    :param policy_name: Alphanumeric name of policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policies_dict = _get_all_policies(**kwargs)

    # Policy doesn't exist; create it
    if policy_name not in policies_dict:

        policy_data = {"name": policy_name}

        target_url = kwargs["url"] + "system/policies"
        post_data = json.dumps(policy_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating classifier policy '%s' failed with status code %d: %s"
                  % (policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating classifier policy '%s' succeeded" % policy_name)
            return True
    else:
        logging.info("SUCCESS: No need to create classifier policy '%s' since it already exists"
              % policy_name)
        return True


def get_all_policy_entries(policy_name, **kwargs):
    """
    Perform a GET call to get a list of all policy entries

    :param policy_name: Alphanumeric name of the classifier policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all policy entries in the table
    """
    if kwargs["url"].endswith("/v1/"):
        policy_entries = _get_all_policy_entries_v1(policy_name, **kwargs)
    else:  # Updated else for when version is v10.04
        policy_entries = _get_all_policy_entries(policy_name, **kwargs)
    return policy_entries


def _get_all_policy_entries_v1(policy_name, **kwargs):
    """
    Perform a GET call to get a list of all policy entries

    :param policy_name: Alphanumeric name of the classifier policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all policy entries in the table
    """
    target_url = kwargs["url"] + "system/policies/%s/cfg_entries" % policy_name

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all entries of policy '%s' failed with status code %d: %s"
              % (policy_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all entries of policy '%s' succeeded" % policy_name)

    policy_entries_list = response.json()

    # for some reason, this API returns a list when empty, and a dictionary when there is data
    # make this function always return a dictionary
    if not policy_entries_list:
        return {}
    else:
        return policy_entries_list


def _get_all_policy_entries(policy_name, **kwargs):
    """
    Perform a GET call to get a dictionary containing all policy entries

    :param policy_name: Alphanumeric name of the classifier policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing all policy entries in the table
    """
    target_url = kwargs["url"] + "system/policies/%s/cfg_entries" % policy_name

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting list of all entries of policy '%s' failed with status code %d: %s"
              % (policy_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting list of all entries of policy '%s' succeeded" % policy_name)

    policy_entries_dict = response.json()

    return policy_entries_dict


def create_policy_entry(policy_name, class_name, class_type, sequence_num, **kwargs):
    """
    Perform a POST call to create a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_policy_entry_v1(policy_name, class_name, class_type, sequence_num, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_policy_entry(policy_name, class_name, class_type, sequence_num, **kwargs)


def _create_policy_entry_v1(policy_name, class_name, class_type, sequence_num, **kwargs):
    """
    Perform a POST call to create a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policy_entries_dict = get_all_policy_entries(policy_name, **kwargs)

    # Policy entry doesn't exist; create it
    if "/rest/v1/system/policies/%s/cfg_entries/%d" % (policy_name, sequence_num) not in policy_entries_dict.values():

        policy_entry_data = {
            "class": "/rest/v1/system/classes/%s/%s" % (class_name, class_type),
            "sequence_number": sequence_num
        }

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries" % policy_name
        post_data = json.dumps(policy_entry_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating entry %d for policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating entry %d for policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to create entry %d for policy '%s' since it already exists"
              % (sequence_num, policy_name))
        return True


def _create_policy_entry(policy_name, class_name, class_type, sequence_num, **kwargs):
    """
    Perform a POST call to create a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policy_entries_dict = _get_all_policy_entries(policy_name, **kwargs)

    # Policy entry doesn't exist; create it
    if "%d" % sequence_num not in policy_entries_dict:

        policy_entry_data = {
            "class": "/rest/v10.04/system/classes/%s,%s" % (class_name, class_type),
            "sequence_number": sequence_num
        }

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries" % policy_name
        post_data = json.dumps(policy_entry_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating entry %d for policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating entry %d for policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to create entry %d for policy '%s' since it already exists"
              % (sequence_num, policy_name))
        return True


def get_policy_entry_action(policy_name, sequence_num, **kwargs):
    """
    Perform a GET call to get the action set on a particular policy entry

    :param policy_name: Alphanumeric name of policy
    :param sequence_num: Integer ID for the entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about the action of a particular policy entry
    """
    if kwargs["url"].endswith("/v1/"):
        policy_entry_action = _get_policy_entry_action_v1(policy_name, sequence_num, **kwargs)
    else:  # Updated else for when version is v10.04
        policy_entry_action = _get_policy_entry_action(policy_name, sequence_num, **kwargs)
    return policy_entry_action


def _get_policy_entry_action_v1(policy_name, sequence_num, **kwargs):
    """
    Perform a GET call to get the action set on a particular policy entry

    :param policy_name: Alphanumeric name of policy
    :param sequence_num: Integer ID for the entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about the action of a particular policy entry
    """
    target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%s/policy_action_set" % (policy_name, sequence_num)

    response = kwargs["s"].get(target_url, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting action of entry %d in policy '%s' failed with status code %d: %s"
              % (sequence_num, policy_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting action of entry %d in policy '%s' succeeded" % (sequence_num, policy_name))

    policy_entry_action = response.json()

    # for some reason, the GET API for policy entry action returns an list if there is no data,
    # and a dictionary if there is data
    # make it always returna dictionary
    if not policy_entry_action:
        return {}
    else:
        return policy_entry_action


def _get_policy_entry_action(policy_name, sequence_num, **kwargs):
    """
    Perform a GET call to get the action set on a particular policy entry

    :param policy_name: Alphanumeric name of policy
    :param sequence_num: Integer ID for the entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about the action of a particular policy entry
    """
    target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%s/policy_action_set" % (policy_name, sequence_num)

    payload = {
        "depth": 2,
        "selector": "writable"
    }
    response = kwargs["s"].get(target_url, verify=False, params=payload, timeout=2)

    if response:
        policy_entry_action_dict = response.json()
        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Getting action of entry %d in policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
        else:
            logging.info("SUCCESS: Getting action of entry %d in policy '%s' succeeded" % (sequence_num, policy_name))
    else:
        policy_entry_action_dict = {}
        logging.info("SUCCESS: Getting action of entry %d in policy '%s' succeeded with an empty value"
              % (sequence_num, policy_name))

    return policy_entry_action_dict


def create_policy_entry_action(policy_name, sequence_num, dscp=None, pcp=None, **kwargs):
    """
    Perform a POST call to create a policy entry action

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param dscp: Optional integer DSCP value to set matched packets to
    :param pcp: Optional integer PCP value to set matched packets to
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _create_policy_entry_action_v1(policy_name, sequence_num, dscp, pcp, **kwargs)
    else:  # Updated else for when version is v10.04
        return _create_policy_entry_action(policy_name, sequence_num, dscp, pcp, **kwargs)


def _create_policy_entry_action_v1(policy_name, sequence_num, dscp=None, pcp=None, **kwargs):
    """
    Perform a POST call to create a policy entry action

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param dscp: Optional integer DSCP value to set matched packets to
    :param pcp: Optional integer PCP value to set matched packets to
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    policy_entry_action = get_policy_entry_action(policy_name, sequence_num, **kwargs)

    # Policy entry action doesn't exist; create it
    if policy_entry_action == {}:

        policy_entry_action_data = {}

        if dscp is not None:
            policy_entry_action_data['dscp'] = dscp

        if pcp is not None:
            policy_entry_action_data['pcp'] = pcp

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%s/policy_action_set" % (policy_name, sequence_num)
        post_data = json.dumps(policy_entry_action_data, sort_keys=True, indent=4)

        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating action for entry %d in policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating action for entry %d in policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to create action for entry %d in policy '%s' since it already exists"
              % (sequence_num, policy_name))
        return True


def _create_policy_entry_action(policy_name, sequence_num, dscp=None, pcp=None, **kwargs):
    """
    Perform a POST call to create a policy entry action

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param dscp: Optional integer DSCP value to set matched packets to
    :param pcp: Optional integer PCP value to set matched packets to
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    policy_entry_action = get_policy_entry_action(policy_name, sequence_num, **kwargs)

    # Policy entry action doesn't exist; create it
    if policy_entry_action == {}:

        policy_entry_action_data = {}

        if dscp is not None:
            policy_entry_action_data['dscp'] = dscp

        if pcp is not None:
            policy_entry_action_data['pcp'] = pcp

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%s/policy_action_set" % (policy_name, sequence_num)
        post_data = json.dumps(policy_entry_action_data, sort_keys=True, indent=4)
        response = kwargs["s"].post(target_url, data=post_data, verify=False, timeout=2)

        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Creating action for entry %d in policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Creating action for entry %d in policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to create action for entry %d in policy '%s' since it already exists"
              % (sequence_num, policy_name))
        return True


def get_policy(policy_name, **kwargs):
    """
    Perform a GET call to get details of a particular policy

    :param policy_name: Alphanumeric name of the policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular policy
    """

    if kwargs["url"].endswith("/v1/"):
        policy = _get_policy_v1(policy_name, **kwargs)
    else:  # Updated else for when version is v10.04
        policy = _get_policy(policy_name, **kwargs)
    return policy


def _get_policy_v1(policy_name, **kwargs):
    """
    Perform a GET call to get details of a particular policy

    :param policy_name: Alphanumeric name of the policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular policy
    """
    target_url = kwargs["url"] + "system/policies/%s" % policy_name

    payload = {"selector": "configuration"}

    response = kwargs["s"].get(target_url, params=payload, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting policy '%s' failed with status code %d: %s"
              % (policy_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting policy '%s' succeeded" % policy_name)

    policy = response.json()
    return policy


def _get_policy(policy_name, **kwargs):
    """
    Perform a GET call to get details of a particular policy

    :param policy_name: Alphanumeric name of the policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing data about a particular policy
    """
    target_url = kwargs["url"] + "system/policies/%s" % policy_name

    payload = {"selector": "writable", "depth": 2}

    response = kwargs["s"].get(target_url, params=payload, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting policy '%s' failed with status code %d: %s"
              % (policy_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting policy '%s' succeeded" % policy_name)

    policy = response.json()
    return policy


def update_policy(policy_name, **kwargs):
    """
    Perform a PUT call to version-up a policy

    :param policy_name: Alphanumeric name of the policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    policy_data = get_policy(policy_name, **kwargs)

    policy_data.pop('origin', None)
    policy_data.pop('name', None)
    policy_data.pop('type', None)

    policy_data['cfg_version'] = random.randrange(9007199254740991)

    target_url = kwargs["url"] + "system/policies/%s" % policy_name
    put_data = json.dumps(policy_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating policy '%s' failed with status code %d: %s" % (
            policy_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating policy '%s' succeeded" % policy_name)
        return True


def delete_queue_profile(profile_name, **kwargs):
    """
    Perform a DELETE call to delete a QoS queue profile

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_queue_profile_v1(profile_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_queue_profile(profile_name, **kwargs)


def _delete_queue_profile_v1(profile_name, **kwargs):
    """
    Perform a DELETE call to delete a QoS queue profile

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    queue_profiles_list = get_all_queue_profiles(**kwargs)

    if "/rest/v1/system/q_profiles/%s" % profile_name in queue_profiles_list:

        target_url = kwargs["url"] + "system/q_profiles/%s" % profile_name

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting QoS queue profile '%s' failed with status code %d: %s"
                  % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting QoS queue profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to remove QoS queue profile '%s' since it doesn't exist" % profile_name)
        return True


def _delete_queue_profile(profile_name, **kwargs):
    """
    Perform a DELETE call to delete a QoS queue profile

    :param profile_name: Alphanumeric name of the queue profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    queue_profiles_dict = _get_all_queue_profiles(**kwargs)

    if profile_name in queue_profiles_dict:

        target_url = kwargs["url"] + "system/q_profiles/%s" % profile_name

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting QoS queue profile '%s' failed with status code %d: %s"
                  % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting QoS queue profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to remove QoS queue profile '%s' since it doesn't exist" % profile_name)
        return True


def delete_queue_profile_entry(profile_name, queue_num, **kwargs):
    """
    Perform a DELETE call to delete a QoS queue profile entry

    :param profile_name: Alphanumeric name of the queue profile
    :param queue_num: Integer number of the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_queue_profile_entry_v1(profile_name, queue_num, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_queue_profile_entry(profile_name, queue_num, **kwargs)


def _delete_queue_profile_entry_v1(profile_name, queue_num, **kwargs):
    """
    Perform a DELETE call to delete a QoS queue profile entry

    :param profile_name: Alphanumeric name of the queue profile
    :param queue_num: Integer number of the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    queue_profiles_entries_dict = get_all_queue_profile_entries(profile_name, **kwargs)

    if "/rest/v1/system/q_profiles/%s/q_profile_entries/%d" % (profile_name, queue_num) in \
            queue_profiles_entries_dict.values():

        target_url = kwargs["url"] + "system/q_profiles/%s/q_profile_entries/%d" % (profile_name, queue_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in QoS queue profile '%s' failed with status code %d: %s"
                  % (queue_num, profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in QoS queue profile '%s' succeeded" % (queue_num, profile_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in QoS queue profile '%s' since it doesn't exist"
              % (queue_num, profile_name))
        return True


def _delete_queue_profile_entry(profile_name, queue_num, **kwargs):
    """
    Perform a DELETE call to delete a QoS queue profile entry

    :param profile_name: Alphanumeric name of the queue profile
    :param queue_num: Integer number of the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    queue_profiles_entries_dict = _get_all_queue_profile_entries(profile_name, **kwargs)

    if "%d" % queue_num in queue_profiles_entries_dict:

        target_url = kwargs["url"] + "system/q_profiles/%s/q_profile_entries/%d" % (profile_name, queue_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in QoS queue profile '%s' failed with status code %d: %s"
                  % (queue_num, profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in QoS queue profile '%s' succeeded" % (queue_num, profile_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in QoS queue profile '%s' since it doesn't exist"
              % (queue_num, profile_name))
        return True


def delete_schedule_profile(profile_name, **kwargs):
    """
    Perform a DELETE call to delete a QoS schedule profile

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_schedule_profile_v1(profile_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_schedule_profile(profile_name, **kwargs)


def _delete_schedule_profile_v1(profile_name, **kwargs):
    """
    Perform a DELETE call to delete a QoS schedule profile

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    schedule_profiles_list = get_all_schedule_profiles(**kwargs)

    if "/rest/v1/system/qos/%s" % profile_name in schedule_profiles_list:

        target_url = kwargs["url"] + "system/qos/%s" % profile_name

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting QoS schedule profile '%s' failed with status code %d: %s"
                  % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting QoS schedule profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to remove QoS schedule profile '%s' since it doesn't exist" % profile_name)
        return True


def _delete_schedule_profile(profile_name, **kwargs):
    """
    Perform a DELETE call to delete a QoS schedule profile

    :param profile_name: Alphanumeric name of the schedule profile
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    schedule_profiles_dict = _get_all_schedule_profiles(**kwargs)

    if profile_name in schedule_profiles_dict:

        target_url = kwargs["url"] + "system/qos/%s" % profile_name

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting QoS schedule profile '%s' failed with status code %d: %s"
                  % (profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting QoS schedule profile '%s' succeeded" % profile_name)
            return True
    else:
        logging.info("SUCCESS: No need to remove QoS schedule profile '%s' since it doesn't exist" % profile_name)
        return True


def delete_schedule_profile_entry(profile_name, queue_num, **kwargs):
    """
    Perform a DELETE call to delete a QoS schedule profile entry

    :param profile_name: Alphanumeric name of the schedule profile
    :param queue_num: Integer number of the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _delete_schedule_profile_entry_v1(profile_name, queue_num, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_schedule_profile_entry(profile_name, queue_num, **kwargs)


def _delete_schedule_profile_entry_v1(profile_name, queue_num, **kwargs):
    """
    Perform a DELETE call to delete a QoS schedule profile entry

    :param profile_name: Alphanumeric name of the schedule profile
    :param queue_num: Integer number of the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    schedule_profile_entries_dict = get_all_schedule_profile_entries(profile_name, **kwargs)

    if "/rest/v1/system/qos/%s/queues/%d" % (profile_name, queue_num) in schedule_profile_entries_dict.values():

        target_url = kwargs["url"] + "system/qos/%s/queues/%d" % (profile_name, queue_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in QoS schedule profile '%s' failed with status code %d: %s"
                  % (queue_num, profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in QoS schedule profile '%s' succeeded"
                  % (queue_num, profile_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in QoS schedule profile '%s' since it doesn't exist"
              % (queue_num, profile_name))
        return True


def _delete_schedule_profile_entry(profile_name, queue_num, **kwargs):
    """
    Perform a DELETE call to delete a QoS schedule profile entry

    :param profile_name: Alphanumeric name of the schedule profile
    :param queue_num: Integer number of the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    schedule_profile_entries_dict = _get_all_schedule_profile_entries(profile_name, **kwargs)

    if "%d" % queue_num in schedule_profile_entries_dict:

        target_url = kwargs["url"] + "system/qos/%s/queues/%d" % (profile_name, queue_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in QoS schedule profile '%s' failed with status code %d: %s"
                  % (queue_num, profile_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in QoS schedule profile '%s' succeeded"
                  % (queue_num, profile_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in QoS schedule profile '%s' since it doesn't exist"
              % (queue_num, profile_name))
        return True


def unapply_profiles_globally(**kwargs):
    """
    Perform GET and PUT calls to remove global application of QoS queue profile and schedule profile on all interfaces.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _unapply_profiles_globally_v1(**kwargs)
    else:  # Updated else for when version is v10.04
        return _unapply_profiles_globally(**kwargs)


def _unapply_profiles_globally_v1(**kwargs):
    """
    Perform GET and PUT calls to remove global application of QoS queue profile and schedule profile on all interfaces.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data.pop('q_profile_default', None)
    system_data.pop('qos_default', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing global application of queue profile and schedule profile failed with status code %d: %s"
              % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing global application of queue profile and schedule profile succeeded")
        return True

        
def _unapply_profiles_globally(**kwargs):
    """
    Perform GET and PUT calls to remove global application of QoS queue profile and schedule profile on all interfaces.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data.pop('q_profile_default', None)
    system_data.pop('qos_default', None)
    system_data.pop('syslog_remotes', None)
    system_data.pop('vrfs', None)
    system_data.pop('mirrors', None)
    system_data.pop('all_user_copp_policies', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing global application of queue profile and schedule profile failed with status code %d: %s"
              % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing global application of queue profile and schedule profile succeeded")
        return True

        
def clear_trust_globally(**kwargs):
    """
    Perform GET and PUT calls to remove global setting of QoS trust mode on all interfaces.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _clear_trust_globally_v1(**kwargs)
    else:  # Updated else for when version is v10.04
        return _clear_trust_globally(**kwargs)


def _clear_trust_globally_v1(**kwargs):
    """
    Perform GET and PUT calls to remove global setting of QoS trust mode on all interfaces.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"selector": "configuration"}, **kwargs)

    system_data.pop('qos_config', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing global setting QoS trust mode failed with status code %d: %s"
              % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing global setting QoS trust mode failed succeeded")
        return True

        
def _clear_trust_globally(**kwargs):
    """
    Perform GET and PUT calls to remove global setting of QoS trust mode on all interfaces.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    system_data = system.get_system_info(params={"depth": 1, "selector": "writable"}, **kwargs)

    system_data.pop('qos_config', None)
    system_data.pop('syslog_remotes', None)
    system_data.pop('vrfs', None)
    system_data.pop('mirrors', None)
    system_data.pop('all_user_copp_policies', None)

    target_url = kwargs["url"] + "system"
    put_data = json.dumps(system_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Removing global setting QoS trust mode failed with status code %d: %s"
              % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Removing global setting QoS trust mode failed succeeded")
        return True

# Same for v1 and v3?
def reset_dscp_entry(code_point, **kwargs):
    """
    Perform a PUT call to reset the DSCP code point entry to its default setting.

    :param code_point: Integer identifying the DSCP map code point entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    code_point_entry_data = {}

    target_url = kwargs["url"] + "system/qos_dscp_map_entries/%d" % code_point
    put_data = json.dumps(code_point_entry_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Resetting QoS DSCP map entry for code point '%d' to default failed with status code %d: %s"
              % (code_point, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Resetting QoS DSCP map entry for code point '%d' to default succeeded"
              % code_point)
        return True


def delete_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a DELETE call to delete a traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_traffic_class_v1(class_name, class_type, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_traffic_class(class_name, class_type, **kwargs)


def _delete_traffic_class_v1(class_name, class_type, **kwargs):
    """
    Perform a DELETE call to delete a traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_classes_list = get_all_classes(**kwargs)

    if "/rest/v1/system/classes/%s/%s" % (class_name, class_type) in traffic_classes_list:

        target_url = kwargs["url"] + "system/classes/%s/%s" % (class_name, class_type)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting %s traffic class '%s' failed with status code %d: %s"
                  % (class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting %s traffic class '%s' succceeded"
                  % (class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete %s traffic class '%s' since it doesn't exist"
              % (class_type, class_name))
        return True


def _delete_traffic_class(class_name, class_type, **kwargs):
    """
    Perform a DELETE call to delete a traffic class

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_classes_dict = _get_all_classes(**kwargs)

    if "%s,%s" % (class_name, class_type) in traffic_classes_dict:

        target_url = kwargs["url"] + "system/classes/%s,%s" % (class_name, class_type)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting %s traffic class '%s' failed with status code %d: %s"
                  % (class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting %s traffic class '%s' succceeded"
                  % (class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete %s traffic class '%s' since it doesn't exist"
              % (class_type, class_name))
        return True


def delete_traffic_class_entry(class_name, class_type, sequence_num, **kwargs):
    """
    Perform a DELETE call to delete a traffic class entry

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"=
    :param sequence_num: Integer ID for the entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _delete_traffic_class_entry_v1(class_name, class_type, sequence_num, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_traffic_class_entry(class_name, class_type, sequence_num, **kwargs)


def _delete_traffic_class_entry_v1(class_name, class_type, sequence_num, **kwargs):
    """
    Perform a DELETE call to delete a traffic class entry

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"=
    :param sequence_num: Integer ID for the entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_class_entries_dict = get_all_traffic_class_entries(class_name, class_type, **kwargs)

    if "/rest/v1/system/classes/%s/%s/cfg_entries/%d" % (class_name, class_type, sequence_num) \
            in traffic_class_entries_dict.values():

        target_url = kwargs["url"] + "system/classes/%s/%s/cfg_entries/%d" % (class_name, class_type, sequence_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in %s traffic class '%s' failed with status code %d: %s"
                  % (sequence_num, class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in %s traffic class '%s' succeeded"
                  % (sequence_num, class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in %s traffic class '%s' since it doesn't exist"
              % (sequence_num, class_type, class_name))
        return True


def _delete_traffic_class_entry(class_name, class_type, sequence_num, **kwargs):
    """
    Perform a DELETE call to delete a traffic class entry

    :param class_name: Alphanumeric name of the traffic class
    :param class_type: Class type should be one of "ipv4," "ipv6," or "mac"
    :param sequence_num: Integer ID for the entry.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    traffic_class_entries_dict = _get_all_traffic_class_entries(class_name, class_type, **kwargs)

    if "%d" % sequence_num in traffic_class_entries_dict:

        target_url = kwargs["url"] + "system/classes/%s,%s/cfg_entries/%d" % (class_name, class_type, sequence_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in %s traffic class '%s' failed with status code %d: %s"
                  % (sequence_num, class_type, class_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in %s traffic class '%s' succeeded"
                  % (sequence_num, class_type, class_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in %s traffic class '%s' since it doesn't exist"
              % (sequence_num, class_type, class_name))
        return True


def delete_policy(policy_name, **kwargs):
    """
    Perform a DELETE call to delete a classifier policy

    :param policy_name: Alphanumeric name of policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_policy_v1(policy_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_policy(policy_name, **kwargs)


def _delete_policy_v1(policy_name, **kwargs):
    """
    Perform a DELETE call to delete a classifier policy

    :param policy_name: Alphanumeric name of policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policies_list = get_all_policies(**kwargs)

    if "/rest/v1/system/policies/%s" % policy_name in policies_list:

        target_url = kwargs["url"] + "system/policies/%s" % policy_name

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting classifier policy '%s' failed with status code %d: %s"
                  % (policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting classifier policy '%s' succeeded" % policy_name)
            return True
    else:
        logging.info("SUCCESS: No need to delete classifier policy '%s' since it doesn't exist" % policy_name)
        return True


def _delete_policy(policy_name, **kwargs):
    """
    Perform a DELETE call to delete a classifier policy

    :param policy_name: Alphanumeric name of policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policies_dict = _get_all_policies(**kwargs)

    if policy_name in policies_dict:

        target_url = kwargs["url"] + "system/policies/%s" % policy_name

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting classifier policy '%s' failed with status code %d: %s"
                  % (policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting classifier policy '%s' succeeded" % policy_name)
            return True
    else:
        logging.info("SUCCESS: No need to delete classifier policy '%s' since it doesn't exist" % policy_name)
        return True


def delete_policy_entry(policy_name, sequence_num, **kwargs):
    """
    Perform a DELETE call to delete a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_policy_entry_v1(policy_name, sequence_num, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_policy_entry(policy_name, sequence_num, **kwargs)


def _delete_policy_entry_v1(policy_name, sequence_num, **kwargs):
    """
    Perform a DELETE call to delete a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policy_entries_dict = get_all_policy_entries(policy_name, **kwargs)

    if "/rest/v1/system/policies/%s/cfg_entries/%d" % (policy_name, sequence_num) in policy_entries_dict.values():

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%d" % (policy_name, sequence_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in policy '%s' since it doesn't exist"
              % (sequence_num, policy_name))
        return True


def _delete_policy_entry(policy_name, sequence_num, **kwargs):
    """
    Perform a DELETE call to delete a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policy_entries_dict = _get_all_policy_entries(policy_name, **kwargs)

    if "%d" % sequence_num in policy_entries_dict:

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%d" % (policy_name, sequence_num)

        response = kwargs["s"].delete(target_url, verify=False)

        if not common_ops._response_ok(response, "DELETE"):
            logging.warning("FAIL: Deleting entry %d in policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Deleting entry %d in policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to delete entry %d in policy '%s' since it doesn't exist"
              % (sequence_num, policy_name))
        return True


def delete_policy_entry_action(policy_name, sequence_num, **kwargs):
    """
    Perform a PUT call to set no action on a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _delete_policy_entry_action_v1(policy_name, sequence_num, **kwargs)
    else:  # Updated else for when version is v10.04
        return _delete_policy_entry_action(policy_name, sequence_num, **kwargs)


def _delete_policy_entry_action_v1(policy_name, sequence_num, **kwargs):
    """
    Perform a PUT call to set no action on a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policy_entries_dict = get_all_policy_entries(policy_name, **kwargs)

    if "/rest/v1/system/policies/%s/cfg_entries/%d" % (policy_name, sequence_num) in policy_entries_dict.values():

        policy_entry_action_data = {}

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%d/policy_action_set" % (policy_name, sequence_num)
        put_data = json.dumps(policy_entry_action_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Setting no action on entry %d in policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Setting no action on entry %d in policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to set no action on entry %d in policy '%s' since it doesn't exist"
              % (sequence_num, policy_name))
        return True


def _delete_policy_entry_action(policy_name, sequence_num, **kwargs):
    """
    Perform a PUT call to set no action on a policy entry

    :param policy_name: Alphanumeric name of the policy
    :param sequence_num: Integer ID for the entry
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    policy_entries_dict = _get_all_policy_entries(policy_name, **kwargs)

    if "%d" % sequence_num in policy_entries_dict:

        policy_entry_action_data = {}

        target_url = kwargs["url"] + "system/policies/%s/cfg_entries/%d/policy_action_set" % (policy_name, sequence_num)
        put_data = json.dumps(policy_entry_action_data, sort_keys=True, indent=4)

        response = kwargs["s"].put(target_url, data=put_data, verify=False)

        if not common_ops._response_ok(response, "PUT"):
            logging.warning("FAIL: Setting no action on entry %d in policy '%s' failed with status code %d: %s"
                  % (sequence_num, policy_name, response.status_code, response.text))
            return False
        else:
            logging.info("SUCCESS: Setting no action on entry %d in policy '%s' succeeded" % (sequence_num, policy_name))
            return True
    else:
        logging.info("SUCCESS: No need to set no action on entry %d in policy '%s' since it doesn't exist"
              % (sequence_num, policy_name))
        return True


def clear_trust_interface(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear QoS trust mode on an interface.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _clear_trust_interface_v1(port_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _clear_trust_interface(port_name, **kwargs)


def _clear_trust_interface_v1(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear QoS trust mode on an interface.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name_percents, depth=0, selector="configuration", **kwargs)

    port_data.pop('qos_config', None)

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing QoS trust mode on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing QoS trust mode on Port '%s' succeeded" % port_name)
        return True


def _clear_trust_interface(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear QoS trust mode on an interface.

    :param port_name: Alphanumeric name of the Port on which the trust mode is to be set
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    port_name_percents = common_ops._replace_special_characters(port_name)
    int_data = interface.get_interface(port_name_percents, 1, "writable", **kwargs)

    if port_name.startswith('lag'):
        if int_data['interfaces']:
            int_data['interfaces'] = common_ops._dictionary_to_list_values(int_data['interfaces'])

    int_data.pop('qos_config', None)

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing QoS trust mode for Interface '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing QoS trust mode for Interface '%s' succeeded"
              % port_name)
        return True


def update_port_rate_limits(port_name, broadcast_limit=None, broadcast_units=None,
                            multicast_limit=None, multicast_units=None, unknown_unicast_limit=None,
                            unknown_unicast_units=None, **kwargs):
    """
    Perform GET and PUT calls to update a Port's rate limits

    :param port_name: Alphanumeric name of the Port
    :param broadcast_limit: Rate limit for broadcast ingress traffic
    :param broadcast_units: Units for broadcast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param multicast_limit: Rate limit in pps for multicast ingress traffic
    :param multicast_units: Units for multicast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param unknown_unicast_limit: Rate limit in pps for unknown_unicast ingress traffic
    :param unknown_unicast_units: Units for unknown unicast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _update_port_rate_limits_v1(port_name, broadcast_limit, broadcast_units,
                                    multicast_limit, multicast_units, unknown_unicast_limit,
                                    unknown_unicast_units, **kwargs)
    else:  # Updated else for when version is v10.04
        return _update_port_rate_limits(port_name, broadcast_limit, broadcast_units,
                                 multicast_limit, multicast_units, unknown_unicast_limit,
                                 unknown_unicast_units, **kwargs)


def _update_port_rate_limits_v1(port_name, broadcast_limit=None, broadcast_units=None,
                                multicast_limit=None, multicast_units=None, unknown_unicast_limit=None,
                                unknown_unicast_units=None, **kwargs):
    """
    Perform GET and PUT calls to update a Port's rate limits

    :param port_name: Alphanumeric name of the Port
    :param broadcast_limit: Rate limit for broadcast ingress traffic
    :param broadcast_units: Units for broadcast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param multicast_limit: Rate limit in pps for multicast ingress traffic
    :param multicast_units: Units for multicast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param unknown_unicast_limit: Rate limit in pps for unknown_unicast ingress traffic
    :param unknown_unicast_units: Units for unknown unicast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name, depth=0, selector="configuration", **kwargs)
  
    port_data['rate_limits'] = {}

    if broadcast_limit is not None and broadcast_units is not None:
        port_data['rate_limits']['broadcast'] = broadcast_limit
        port_data['rate_limits']['broadcast_units'] = broadcast_units

    if multicast_limit is not None and multicast_units is not None:
        port_data['rate_limits']['multicast'] = multicast_limit
        port_data['rate_limits']['multicast_units'] = multicast_units

    if unknown_unicast_limit is not None and unknown_unicast_units is not None:
        port_data['rate_limits']['unknown-unicast'] = unknown_unicast_limit
        port_data['rate_limits']['unknown-unicast_units'] = unknown_unicast_units

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating rate limits for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating rate limits for Port '%s' succeeded"
              % port_name)
        return True


def _update_port_rate_limits(port_name, broadcast_limit=None, broadcast_units=None,
                            multicast_limit=None, multicast_units=None, unknown_unicast_limit=None,
                            unknown_unicast_units=None, **kwargs):
    """
    Perform GET and PUT calls to update a Port's rate limits

    :param port_name: Alphanumeric name of the Port
    :param broadcast_limit: Rate limit for broadcast ingress traffic
    :param broadcast_units: Units for broadcast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param multicast_limit: Rate limit in pps for multicast ingress traffic
    :param multicast_units: Units for multicast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param unknown_unicast_limit: Rate limit in pps for unknown_unicast ingress traffic
    :param unknown_unicast_units: Units for unknown unicast rate limit; should be either "kbps" (kilobits/second) or
        "pps" (packets/second)
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    int_data = interface.get_interface(port_name, 2, "writable", **kwargs)

    int_data['rate_limits'] = {}

    if broadcast_limit is not None and broadcast_units is not None:
        int_data['rate_limits']['broadcast'] = broadcast_limit
        int_data['rate_limits']['broadcast_units'] = broadcast_units

    if multicast_limit is not None and multicast_units is not None:
        int_data['rate_limits']['multicast'] = multicast_limit
        int_data['rate_limits']['multicast_units'] = multicast_units

    if unknown_unicast_limit is not None and unknown_unicast_units is not None:
        int_data['rate_limits']['unknown-unicast'] = unknown_unicast_limit
        int_data['rate_limits']['unknown-unicast_units'] = unknown_unicast_units

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating rate limits for Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating rate limits for Port '%s' succeeded"
              % port_name)
        return True


def update_port_policy(port_name, policy_name, **kwargs):
    """
    Perform GET and PUT calls to update a Port's policy

    :param port_name: Alphanumeric name of the Port
    :param policy_name: Alphanumeric name of the policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _update_port_policy_v1(port_name, policy_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _update_port_policy(port_name, policy_name, **kwargs)


def _update_port_policy_v1(port_name, policy_name, **kwargs):
    """
    Perform GET and PUT calls to update a Port's policy

    :param port_name: Alphanumeric name of the Port
    :param policy_name: Alphanumeric name of the policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)
    port_data = port.get_port(port_name, depth=0, selector="configuration", **kwargs)

    port_data['policy_in_cfg'] = "/rest/v1/system/policies/%s" % policy_name
    port_data['policy_in_cfg_version'] = random.randrange(9007199254740991)

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating policy on Port '%s' to '%s' failed with status code %d: %s"
              % (port_name, policy_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating policy on Port '%s' to '%s' succeeded"
              % (port_name, policy_name))
        return True


def _update_port_policy(port_name, policy_name, **kwargs):
    """
    Perform GET and PUT calls to update a Port's policy

    :param port_name: Alphanumeric name of the Port
    :param policy_name: Alphanumeric name of the policy
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    int_data = interface.get_interface(port_name, 1, "writable", **kwargs)

    int_data['policy_in_cfg'] = "/rest/v10.04/system/policies/%s" % policy_name
    int_data['policy_in_cfg_version'] = random.randrange(9007199254740991)

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Updating policy on Port '%s' to '%s' failed with status code %d: %s"
              % (port_name, policy_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Updating policy on Port '%s' to '%s' succeeded"
              % (port_name, policy_name))
        return True


def clear_port_policy(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's policy

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    if kwargs["url"].endswith("/v1/"):
        return _clear_port_policy_v1(port_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _clear_port_policy(port_name, **kwargs)


def _clear_port_policy_v1(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's policy

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name, depth=0, selector="configuration", **kwargs)

    port_data.pop('policy_in_cfg', None)
    port_data.pop('policy_in_cfg_version', None)

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing policy on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing policy on Port '%s' succeeded"
              % port_name)
        return True


def _clear_port_policy(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's policy

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    int_data = interface.get_interface(port_name, 2, "writable", **kwargs)

    int_data.pop('policy_in_cfg', None)
    int_data.pop('policy_in_cfg_version', None)

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing policy on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing policy on Port '%s' succeeded"
              % port_name)
        return True


def clear_port_rate_limits(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's rate limits

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    if kwargs["url"].endswith("/v1/"):
        return _clear_port_rate_limits_v1(port_name, **kwargs)
    else:  # Updated else for when version is v10.04
        return _clear_port_rate_limits(port_name, **kwargs)


def _clear_port_rate_limits_v1(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's rate limits

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    port_name_percents = common_ops._replace_special_characters(port_name)

    port_data = port.get_port(port_name, depth=0, selector="configuration", **kwargs)

    port_data.pop('rate_limits', None)

    # must remove these fields from the data since they can't be modified
    port_data.pop('name', None)
    port_data.pop('origin', None)

    target_url = kwargs["url"] + "system/ports/%s" % port_name_percents
    put_data = json.dumps(port_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing rate limits on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing rate limits on Port '%s' succeeded"
              % port_name)
        return True


def _clear_port_rate_limits(port_name, **kwargs):
    """
    Perform GET and PUT calls to clear a Port's rate limits

    :param port_name: Alphanumeric name of the Port
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    port_name_percents = common_ops._replace_special_characters(port_name)

    int_data = interface.get_interface(port_name, 2, "writable", **kwargs)

    int_data.pop('rate_limits', None)

    target_url = kwargs["url"] + "system/interfaces/%s" % port_name_percents
    put_data = json.dumps(int_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=put_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Clearing rate limits on Port '%s' failed with status code %d: %s"
              % (port_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Clearing rate limits on Port '%s' succeeded"
              % port_name)
        return True
