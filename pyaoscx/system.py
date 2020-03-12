# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops

import logging


def get_system_info(params={}, **kwargs):
    """
    Perform a GET call to get system information

    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing system information
    """
    target_url = kwargs["url"] + "system"

    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of system information failed with status code %d: %s"
              % (response.status_code, response.text))
        system_info_dict = {}
    else:
        logging.info("SUCCESS: Getting dictionary of system information succeeded")
        system_info_dict = response.json()

    return system_info_dict

def get_chassis_info(params={}, **kwargs):
    """
    Perform a GET call to get the chassis information, such as product info, reboot statistics, selftest info, and more.

    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing chassis information
    """

    if kwargs["url"].endswith("/v1/"):
        target_url = kwargs["url"] + "/system/subsystems/chassis/1"
    else:
        # Else logic designed for v10.04 and later
        target_url = kwargs["url"] + "/system/subsystems/chassis,1"

    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of chassis information failed with status code %d: %s"
              % (response.status_code, response.text))
        chassis_info_dict = {}
    else:
        logging.info("SUCCESS: Getting dictionary of chassis information succeeded")
        chassis_info_dict = response.json()

    return chassis_info_dict

def get_product_info(params={}, **kwargs):
    """
    Perform a GET call to get the product information, such as MAC, Part Number, Model, and Serial

    :param params: Dictionary of optional parameters for the GET request
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing product information
    """

    if kwargs["url"].endswith("/v1/"):
        target_url = kwargs["url"] + "/system/subsystems/chassis/1?attributes=product_info"
    else:
        # Else logic designed for v10.04 and later
        target_url = kwargs["url"] + "/system/subsystems/chassis,1?attributes=product_info"

    response = kwargs["s"].get(target_url, params=params, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting dictionary of product information failed with status code %d: %s"
              % (response.status_code, response.text))
        product_info_dict = {}
    else:
        logging.info("SUCCESS: Getting dictionary of product information succeeded")
        product_info_dict = response.json()

    return product_info_dict
