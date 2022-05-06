# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import getpass
import json
import logging
import re

import requests

from pyaoscx.exceptions.login_error import LoginError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.api import API

# Global Variables
ZEROIZED = 268
UNAUTHORIZED = 401


class Session:
    """
    Represents a connection to an AOS-CX device. It keeps all information
        needed to login/logout to it, including parameters like proxy, IP
        address (both IPv4 and IPv6 are supported), and API version. The IP
        address should be similar to:
        '1.1.1.1'
        or
        '2001:db8::11/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    """

    def __init__(self, ip_address, api, proxy=None):

        self.api = API.create(api)
        self.ip = ip_address
        self.connected = False
        self.proxy = (
            {"no_proxy": self.ip} if proxy is None else {"https": proxy}
        )
        self.scheme = "https"
        self.version_path = "rest/v{0}/".format(self.api)

        # TODO: remove base_url once all modules use the internal
        # request methods
        self.base_url = "https://{0}/rest/v{1}/".format(self.ip, self.api)
        self.resource_prefix = "/rest/v{0}/".format(self.api)
        self.s = requests.Session()
        self.s.verify = False
        self.__username = self.__password = ""

    def cookies(self):
        """
        Return the cookie stored in the requests' session.
        """
        return self.s.cookies._cookies

    @classmethod
    def from_session(cls, req_session, base_url, credentials=None):
        """
        Create a session from an existing request Session. It allows to create
            an internal session from an already-authenticated and serialized
            session.
        :param req_session: Existing Request Session object.
        :param base_url: Url needed to create Session Object.
        :param credentials: Dictionary with user and password credentials.
            Example: {
                username: <username>,
                password: <password>
            }
        :return session: Request Session Object.
        """
        ip_address = version = ""

        # From base url retrieve the ip address and the version
        url_pattern = re.compile(
            r"https://(?P<ip_address>.+)/rest/v(?P<version>.+)/"
        )
        match = url_pattern.match(base_url)
        if match:
            ip_address = match.group("ip_address")
            version = match.group("version")

        else:
            raise Exception("Error creating Session")

        # Create Session
        session = Session(ip_address, version)

        # Determine proxy
        # If the proxy is not {} then it would replace the proxy
        # previously created inside the __init__ method
        if req_session.proxies != {}:
            session.proxy = req_session.proxies

        # Set request.Session()
        session.s.cookies = req_session.cookies
        session.connected = True

        # Set credentials
        if credentials is not None:
            session.__username = credentials["username"]
            session.__password = credentials["password"]

        return session

    def open(self, username=None, password=None):
        """
        Perform a POST call to login and gain access to other API calls. If
            either username or password is not specified, user will be prompted
            to enter the missing credential(s).
        :param username: username
        :param password: password
        """
        if self.__username is None:
            if username is None:
                username = input("Enter username: ")
            else:
                self.__username = username
        else:
            if username is None:
                username = input("Enter username: ")

        if self.__password is None:
            if password is None:
                password = getpass.getpass()
            else:
                self.__password = password
        else:
            if password is None:
                password = getpass.getpass()

        login_data = {"username": username, "password": password}
        self.__username = username
        self.__password = password
        try:
            login_uri = "{0}{1}".format(self.base_url, "login")
            response = self.s.post(
                login_uri,
                data=login_data,
                verify=False,
                timeout=5,
                proxies=self.proxy,
            )
        except requests.exceptions.ConnectTimeout:
            raise Exception(
                "Error connecting to host: connection attempt timed out."
            )

        if response.status_code != 200:
            raise Exception(
                "FAIL: Login failed with status code {0}: {1}".format(
                    response.status_code, response.text
                )
            )

        cookies = self.s.cookies
        if ':' in self.ip:
            ipv6_match = self.ip + '.local'
            self.connected = (
                hasattr(cookies, "_cookies") and ipv6_match in cookies._cookies
            )
        else:
            self.connected = (
                hasattr(cookies, "_cookies") and self.ip in cookies._cookies
            )

        if not self.connected:
            raise LoginError("Cookies were not set correctly. Login failed")

        logging.info("SUCCESS: Login succeeded")

    def close(self):
        """
        Perform a POST call to logout and end the session. Given all the
            required information to perform the operation is already stored
            within the session, no parameters are required.
        """
        if self.connected:
            logout_uri = "{0}{1}".format(self.base_url, "logout")

            try:
                response = self.s.post(
                    logout_uri, verify=False, proxies=self.proxy
                )
            except BaseException:
                raise Exception(
                    "Unable to process the request: ({0}) {1}".format(
                        response.status_code, response.text
                    )
                )

            if response.status_code != 200:
                raise Exception(
                    "FAIL: Logout failed with status code {0}: {1}".format(
                        response.status_code, response.text
                    )
                )

            logging.info("SUCCESS: Logout succeeded")

    # Session Login and Logout
    # Used for Connection within Ansible

    @classmethod
    def login(
        cls,
        base_url,
        username=None,
        password=None,
        use_proxy=True,
        handle_zeroized_device=False,
    ):
        """
        Perform a POST call to login and gain access to other API calls. If
            either username or password is not specified, user will be prompted
            to enter the missing credential(s).
        :param base_url: URL in main() function
        :param username: username
        :param password: password
        :param use_proxy: Whether the system proxy should be used, defaults to
            True.
        :param handle_zeroized_device: Whether a zeroized device should be
            initialized, if so sets the admin password to the provided one,
            defaults to False.
        :return: requests.session object with loaded cookie jar
        """
        if username is None and password is None:
            username = input("Enter username: ")
            password = getpass.getpass()

        login_data = {"username": username, "password": password}

        s = requests.Session()

        if use_proxy is False:
            s.proxies["https"] = None
            s.proxies["http"] = None
        try:
            print(base_url + "login")
            response = s.post(
                base_url + "login",
                data=login_data,
                verify=False,
                timeout=5,
                proxies=s.proxies,
            )
        except requests.exceptions.ConnectTimeout:
            logging.warning(
                "ERROR: Error connecting to host: "
                "connection attempt timed out."
            )
            raise LoginError(
                "ERROR: Error connecting to host: "
                "connection attempt timed out."
            )
        except requests.exceptions.ProxyError as err:
            logging.warning("ERROR: %s", str(err))
            raise LoginError("ERROR: {0}".format(err))
        # Response OK check needs to be passed 'PUT' since this
        # POST call returns 200 instead of conventional 201
        if not utils._response_ok(response, "PUT"):
            if response.status_code == UNAUTHORIZED and handle_zeroized_device:
                # Try to login with default credentials:
                ztp_login_data = {"username": username}
                response = s.post(
                    base_url + "login",
                    data=ztp_login_data,
                    verify=False,
                    timeout=5,
                    proxies=s.proxies,
                )
                if response.status_code == ZEROIZED:
                    data = {"password": password}
                    response = s.put(
                        base_url + "system/users/admin",
                        data=json.dumps(data),
                        verify=False,
                        timeout=5,
                        proxies=s.proxies,
                    )
                    if utils._response_ok(response, "PUT"):
                        logging.info("SUCCESS: Login succeeded")
                        return s
            logging.warning(
                "FAIL: Login failed with status code %d: %s",
                response.status_code,
                response.text,
            )
            raise LoginError(
                "FAIL: Login failed with status code {0}: {1}".format(
                    response.status_code, response.text
                ),
                response.status_code,
            )
        else:
            logging.info("SUCCESS: Login succeeded")
            return s

    @classmethod
    def logout(cls, **kwargs):
        """
        Perform a POST call to logout and end session.
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: True if successful.
        """
        response = kwargs["s"].post(
            kwargs["url"] + "logout", verify=False, proxies=kwargs["s"].proxies
        )
        # Response OK check needs to be passed 'PUT' since this POST
        # call returns 200 instead of conventional 201
        if not utils._response_ok(response, "PUT"):
            logging.warning(
                "FAIL: Logout failed with status code %d: %s",
                response.status_code,
                response.text,
            )
            return False
        else:
            logging.info("SUCCESS: Logout succeeded")
            return True

    def username(self):
        """
        Get username.
        :return username.
        """
        return self.__username

    def password(self):
        """
        Get password.
        :return password.
        """
        return self.__password

    def _build_uri(self, resource_path):
        """
        Build a URI representing a resource.
        :param resource_path: Resource path before adding version prefix.
        :return: String of the uri
        """
        complete_path = self.version_path + resource_path
        uri = requests.utils.urlunparse(
            (self.scheme, self.ip, complete_path, "", "", "")
        )
        return uri

    def request(self, operation, path, params=None, data=None, verify=False):
        """
        Perform a Request to the switch.
        :param operation: type of operation: PUT, GET, POST, DELETE.
        :param path: Path to the resource.
        :param params: Extra request parameters.
        :param data: Data to send in the resquest.
        :param verify: If session should verify.
        :return: response object from the request.
        """
        operations = {
            "PUT": self.s.put,
            "GET": self.s.get,
            "POST": self.s.post,
            "DELETE": self.s.delete,
        }

        if operation not in operations:
            raise VerificationError(
                "The operation {0} is not supported."
                " Use any of {1}".format(operation, list(operations.keys))
            )

        return operations[operation](
            self._build_uri(path),
            verify=verify,
            params=params,
            data=data,
            proxies=self.proxy,
        )
