# (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx import common_ops

import getpass
import requests
import json
import logging


def login(base_url, username=None, password=None):
    """

    Perform a POST call to login and gain access to other API calls.
    If either username or password is not specified, user will be prompted to enter the missing credential(s).

    :param base_url: URL in main() function
    :param username: username
    :param password: password
    :return: requests.session object with loaded cookie jar
    """
    if username is None and password is None:
        username = input('Enter username: ')
        password = getpass.getpass()

    login_data = {"username": username, "password": password}

    s = requests.Session()
    try:
        response = s.post(base_url + "login", data=login_data, verify=False, timeout=5)
    except requests.exceptions.ConnectTimeout:
        logging.warning('ERROR: Error connecting to host: connection attempt timed out.')
        exit(-1)
    # Response OK check needs to be passed "PUT" since this POST call returns 200 instead of conventional 201
    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Login failed with status code %d: %s" % (response.status_code, response.text))
        exit(-1)
    else:
        logging.info("SUCCESS: Login succeeded")
        return s


def create_first_password(base_url, password=None):
    """
    Perform POST and PUT calls to open a restricted session with user admin and create the first password needed to gain access to other API calls.

    :param base_url: URL in main() function
    :param password: password
    :return: requests.session object with loaded cookie jar
    """
    if password is None:
        password = getpass.getpass(prompt='Please provide a password: ')
    s = requests.Session()
    try:
        # POST Request opens a limited session for user "admin" - Response code is 268
        response = s.post(base_url + "login", params={"username": "admin"}, verify=False, timeout=5)
        if not common_ops._response_ok(response, "POST"):
            logging.warning("FAIL: Login failed with status code %d: %s" % (response.status_code, response.text))
            exit(-1)
        else:
            # PUT Request updates the password for user "admin" - Response code is 200 - Session is kept open
            payload = {
                    "password": str(password)
                    }
            response = s.put(base_url + "system/users/admin", data=json.dumps(payload), verify=False, timeout=5)
            if not common_ops._response_ok(response, "PUT"):
                logging.warning("FAIL: Password update failed with status code %d: %s" % (response.status_code, response.text))
                exit(-1)
            else:
                logging.info("SUCCESS: Password has been set for user admin")
                return s
    except requests.exceptions.ConnectTimeout:
        logging.warning('ERROR: Error connecting to host: connection attempt timed out.')
        exit(-1)


def logout(**kwargs):
    """
    Perform a POST call to logout and end session.

    :param kwargs:
        keyword s: requests.session object with loaded cookie jar
        keyword url: URL in main() function
    :return: True if successful, False otherwise
    """
    response = kwargs["s"].post(kwargs["url"] + "logout", verify=False)
    # Response OK check needs to be passed "PUT" since this POST call returns 200 instead of conventional 201
    if not common_ops._response_ok(response, "PUT"):
        logging.warning("FAIL: Logout failed with status code %d: %s" % (response.status_code, response.text))
        return False
    else:
        logging.info("SUCCESS: Logout succeeded")
        return True