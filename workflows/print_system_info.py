#!/usr/bin/env python3

# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
This workflow performs the following steps:
1. Print the system information

Preconditions:
None
"""

from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests
import os
import sys
import logging
import getpass

logging.basicConfig(level=logging.INFO)
dirpath = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.append(dirpath)
sys.path.append(os.path.join(dirpath, "pyaoscx"))
sys.path.append(os.path.join(dirpath, "cx_utils"))

from pyaoscx import session
from pyaoscx import system

import pprint

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def main():
    switchip = input("Switch IP Address: ")

    username = input("Switch login username: ")

    password = getpass.getpass("Switch login password: ")

    bypassproxy = False  # Set to 'True' to bypass proxy and communicate directly with device.

    if bypassproxy:
        os.environ['no_proxy'] = switchip
        os.environ['NO_PROXY'] = switchip

    version = 'v1'  # Set to 'v10.04' if running code v10.04 or later, otherwise set to 'v1'

    base_url = "https://{0}/rest/{1}/".format(switchip, version)
    try:
        session_dict = dict(s=session.login(base_url, username, password), url=base_url)

        system_info_dict = system.get_system_info(params={"selector": "configuration"}, **session_dict)

        pprint.pprint(system_info_dict)

    except Exception as error:
        print('Ran into exception: {}. Logging out..'.format(error))
    session.logout(**session_dict)


if __name__ == '__main__':
    main()
