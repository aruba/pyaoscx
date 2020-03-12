#!/usr/bin/env python3

# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
This workflow performs the following steps:
1. Create VLAN
      Ex:
        vlan 999
            description For LAB 999

2. Create SVI
      Ex:
        interface vlan999
            description ### SVI for LAB999 ###
            ip address 10.10.10.99/24

3. Add DHCP helpers for SVI
      Ex:
        interface vlan999
            description ### SVI for LAB999 ###
            ip address 10.10.10.99/24
            ip helper-address 1.1.1.1
            ip helper-address 2.2.2.2

3. Create L2 interface
    a. Create the interface
    b. Enable the interface
    c. Set VLAN mode to 'access'
    d. Set VLAN as untagged VLAN
      Ex:
        interface 1/1/20
            no shutdown
            no routing
            vlan access 999



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
from pyaoscx import vlan
from pyaoscx import interface
from pyaoscx import dhcp

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

        vlan.create_vlan_and_svi(999, 'VLAN999', 'vlan999', 'vlan999',
                                 'For LAB 999', '10.10.10.99/24', vlan_port_desc='### SVI for LAB999 ###',
                                 **session_dict)

        # Add DHCP helper IPv4 addresses for SVI
        dhcp.add_dhcp_relays('vlan999', "default", ['1.1.1.1', '2.2.2.2'], **session_dict)

        # Add a new entry to the Port table if it doesn't yet exist
        interface.add_l2_interface('1/1/20', **session_dict)

        # Update the Interface table entry with "user-config": {"admin": "up"}
        interface.enable_disable_interface('1/1/20', **session_dict)

        # Set the L2 port VLAN mode as 'access'
        vlan.port_set_vlan_mode('1/1/20', "access", **session_dict)

        # Set the access VLAN on the port
        vlan.port_set_untagged_vlan('1/1/20', 999, **session_dict)

    except Exception as error:
        print('Ran into exception: {}. Logging out..'.format(error))
    session.logout(**session_dict)


if __name__ == '__main__':
    main()
