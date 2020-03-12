# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops

import json
import logging


def get_all_configs(**kwargs):
    """
    Perform a GET call to get all configs

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of all config URIs
    """

    response = kwargs["s"].get(kwargs["url"] + "fullconfigs", verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting all configs failed with status code %d: %s"
                        % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting all configs succeeded")

    return response.json()


def get_config(config_name, **kwargs):
    """
    Perform a GET call to get contents of a config.

    :param config_name: name of config (e.g. running-config)
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: Dictionary containing config contents
    """

    response = kwargs["s"].get(kwargs["url"] + "fullconfigs/%s" % config_name, verify=False)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting config '%s' failed with status code %d: %s"
                        % (config_name, response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting config '%s' succeeded" % config_name)

    return response.json()


def upload_running_config(config_data, **kwargs):
    """
    Perform a PUT call to upload a new running-config

    :param config_data: Dictionary containing config contents
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    target_url = kwargs["url"] + "fullconfigs/running-config"
    post_data = json.dumps(config_data, sort_keys=True, indent=4)

    response = kwargs["s"].put(target_url, data=post_data, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Loading config data to 'running-config' failed with status code %d: %s"
              % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Loading config data to 'running-config' succeeded")
        return True


def copy_config(src_config_name, dst_config_name, **kwargs):
    """
    Perform a PUT call to copy contents from one config into another config

    :param src_config_name: Name of config to copy data from
    :param dst_config_name: Name of config to copy data into
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """

    query = {"from": "/rest/v10.04/fullconfigs/%s" % src_config_name}

    target_url = kwargs["url"] + "fullconfigs/%s" % dst_config_name

    response = kwargs["s"].put(target_url, params=query, verify=False)

    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Copying config data from '%s' to '%s' failed with status code %d: %s"
              % (src_config_name, dst_config_name, response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Copying config data from '%s' to '%s' succeeded"
              % (src_config_name, dst_config_name))
        return True
