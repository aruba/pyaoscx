# (C) Copyright 2020-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import logging

from pyaoscx.utils import util as utils


def get_firmware_version(**kwargs):
    """
    Perform GET calls to retrieve the current firmware version.
    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function.
    :return: Firmware version string if found, otherwise None.
    """
    target_url = kwargs["url"] + "firmware"

    response = kwargs["s"].get(
        target_url, verify=False, proxies=kwargs["s"].proxies
    )

    if not utils._response_ok(response, "GET"):
        logging.warning(
            "FAIL: Getting firmware version %d: %s",
            response.status_code,
            response.text,
        )
        firmware_version = None
    else:
        logging.info("SUCCESS: Getting firmware version succeeded")
        firmware_version = response.json()["current_version"]

    return firmware_version
