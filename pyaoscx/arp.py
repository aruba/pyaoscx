# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops

import logging


def get_arp_entries(vrf_name, **kwargs):
    """
    Perform a GET call on Neighbors table to get ARP entries

    :param vrf_name: Alphanumeric name of VRF
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: List of dictionaries each containing one ARP entry
    """

    queries = {"depth": 1}

    target_url = kwargs["url"] + "system/vrfs/%s/neighbors" % vrf_name
    response = kwargs["s"].get(target_url, verify=False, params=queries, timeout=2)

    if not common_ops._response_ok(response, "GET"):
        logging.warning("FAIL: Getting Neighbors table entries failed with status code %d: %s"
                        % (response.status_code, response.text))
    else:
        logging.info("SUCCESS: Getting Neighbors table entries succeeded")

    neighbor_info_list = response.json()

    arp_entries_list = []

    for neighbor_info in neighbor_info_list:
        arp_entry = {
            "IPv4 Address": neighbor_info['ip_address'],
            "MAC Address": neighbor_info['mac'],
            # For port and physical port: split string by '/', take last block, and replace any '%' characters
            "Port": common_ops._replace_percents((neighbor_info['port'].split('/'))[-1]),
            "State": neighbor_info['state']
        }

        if 'phy_port' in neighbor_info:
            arp_entry['Physical Port'] = common_ops._replace_percents((neighbor_info['phy_port'].split('/'))[-1])

        arp_entries_list.append(arp_entry)

    return arp_entries_list
