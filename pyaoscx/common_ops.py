# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from os.path import dirname, abspath, join

import yaml


def _list_remove_duplicates(list_with_dup):
    """
    Return a copy of a list without duplicated items.

    :param list_with_dup: Input list that may contain duplicates
    :return: List that does not contain duplicates
    """
    set_no_dup = set(list_with_dup)
    list_no_dup = list(set_no_dup)
    return list_no_dup


def _replace_percents(str_percents):
    """
    Replaces percent-encoded pieces in a string with their special-character counterparts
        '%3A' -> ':'
        '%2F' -> '/'
        '%2C' -> ','
    (e.g. "1/1/9" -> "1%2F1%2F9")

    :param str_percents: string in which to substitute characters
    :return: new string with percent phrases replaced by their special-character counterparts
    """
    str_special_chars = str_percents.replace("%3A", ":").replace("%2F", "/").replace(
        "%2C", ",")
    return str_special_chars


def _replace_special_characters(str_special_chars):
    """
    Replaces special characters in a string with their percent-encoded counterparts
        ':' -> '%3A'
        '/' -> '%2F'
        ',' -> '%2C'
    (e.g. "1/1/9" -> "1%2F1%2F9")

    :param str_special_chars: string in which to substitute characters
    :return: new string with characters replaced by their percent-encoded counterparts
    """
    str_percents = str_special_chars.replace(":", "%3A").replace("/", "%2F").replace(
        ",", "%2C")
    return str_percents


def _response_ok(response, call_type):
    """
    Checks whether API HTTP response contains the associated OK code.

    :param response: Response object
    :param call_type: String containing the HTTP request type
    :return: True if response was OK, False otherwise
    """
    ok_codes = {
        "GET": [200],
        "PUT": [200, 204],
        "POST": [201],
        "DELETE": [204]
    }

    return response.status_code in ok_codes[call_type]


def _dictionary_to_list_values(dictionary):
    """
    Replaces a dictionary with a list of just the values
    Example input:
        "interfaces": {
            "1/1/21": "/rest/v10.04/system/interfaces/1%2F1%2F21",
            "1/1/22": "/rest/v10.04/system/interfaces/1%2F1%2F22"
        }
    Example output:
        "interfaces": [
            "/rest/v10.04/system/interfaces/1%2F1%2F21",
            "/rest/v10.04/system/interfaces/1%2F1%2F22"
        ]

    :param dictionary: A Non-empty dictionary that will have its values added to a list
    :return: A new list with the values from the dictionary
    """
    new_list = []
    for x in dictionary:
        new_list.append(dictionary[x])
    return new_list


def read_yaml(filename):
    """" Reads a YAML file and returns the data in a Python object

    :param filename: Name of YAML file (e.g. 'vlan_data.yml')
    :return: Python object
    """

    parentdirpath = dirname(dirname(abspath(__file__)))
    sampledatadir = join(parentdirpath, "sampledata")

    with open(abspath(join(sampledatadir, filename)), 'r') as yml_file:
        data = yaml.safe_load(yml_file)
    return data