#!/usr/bin/env python3

# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
This workflow performs the following steps:
1. Delete DHCP helpers from SVI
      Ex:
        interface vlan999
            no ip helper-address 1.1.1.1
            no ip helper-address 2.2.2.2

2. Delete SVI
      Ex:
        no interface vlan 999

3. Delete VLAN
      Ex:
        no vlan 999

4. Initialize L2 interface
      Ex:
        interface 1/1/20
            no shutdown
            no routing
            vlan access 1

Preconditions:
Must have run the configure_l2_l3_vlans workflow or have the equivalent settings.
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
from pyaoscx import dhcp
from pyaoscx import interface
from pyaoscx import vlan

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

        # Delete all DHCP relays for interface
        dhcp.delete_dhcp_relays('vlan999', "default", **session_dict)

        # Delete VLAN and SVI
        vlan.delete_vlan_and_svi(999, 'vlan999', **session_dict)

        # Initialize L2 interface
        interface.initialize_interface('1/1/20', **session_dict)

    except Exception as error:
        print('Ran into exception: {}. Logging out..'.format(error))
    session.logout(**session_dict)


if __name__ == '__main__':
    main()
