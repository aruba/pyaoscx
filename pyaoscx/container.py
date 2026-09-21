# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re
import time
from math import isfinite

from requests.exceptions import Timeout

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


STATUS_REQUEST_TIMEOUT = 30


class Container(PyaoscxModule):
    """
    Provide configuration management for Containers on AOS-CX devices.

    Containers allow running lightweight application images on AOS-CX
    switches. Each container is associated with an isolated network for
    connectivity, and an image that is downloaded from an HTTP server via
    a specified VRF.

    Note: Container endpoints require API version v10.17+ on 8325 (GL.10.19)
        or v10.18+ on 6300 (FL.10.18). Ensure the Session is created with
        the appropriate API version.
    """

    base_uri = "system/containers"
    resource_uri_name = "containers"
    indices = ["name"]

    def __init__(
        self,
        session,
        name,
        image_location=None,
        isolated_network=None,
        vrf="default",
        allow_unsigned_image=False,
        enable=False,
        uri=None,
        **kwargs,
    ):
        """
        Create a Container object.

        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param name: Alphanumeric name of the container.
        :param image_location: URL of the container image to download,
            e.g. "http://10.93.201.106:8000/log_agent.img".
        :param isolated_network: A ContainerIsolatedNetwork object or a
            string name of the isolated network to attach the container to.
        :param vrf: Name of the VRF used to download the image.
            Defaults to "default".
        :param allow_unsigned_image: Boolean, whether to allow unsigned
            container images. Defaults to False.
        :param enable: Boolean, whether the container should be enabled
            after creation. Defaults to False.
        :param uri: Optional URI string.
        :param kwargs: Additional keyword arguments for writable attributes.
        """
        self.session = session
        self._uri = uri
        self.name = name
        self.image_location = image_location
        self.isolated_network = isolated_network
        self.vrf = vrf
        self.allow_unsigned_image = allow_unsigned_image
        self.enable = enable
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        self.__modified = False
        utils.set_creation_attrs(self, **kwargs)

        self.path = "{0}/{1}".format(Container.base_uri, self.name)

    @staticmethod
    def _reference_name(reference):
        """Return a resource name from a REST reference or object."""
        if isinstance(reference, dict):
            return next(iter(reference), None)
        if isinstance(reference, str):
            return reference.rstrip("/").rsplit("/", 1)[-1]
        return getattr(reference, "name", None)

    def _build_isolated_network_uri(self):
        """
        Build the container_isolated_network URI reference from the
            isolated_network attribute.

        :return: URI string for the isolated network, or None.
        """
        if self.isolated_network is None:
            return None

        if hasattr(self.isolated_network, "name"):
            net_name = self.isolated_network.name
        else:
            net_name = str(self.isolated_network)

        return "{0}system/container_isolated_networks/{1}".format(
            self.session.resource_prefix, net_name
        )

    def _build_vrf_uri(self):
        """
        Build the image_download_vrf URI reference from the vrf attribute.

        :return: URI string for the VRF, or None.
        """
        if self.vrf is None:
            return None

        if hasattr(self.vrf, "name"):
            vrf_name = self.vrf.name
        else:
            vrf_name = str(self.vrf)

        return "{0}system/vrfs/{1}".format(
            self.session.resource_prefix, vrf_name
        )

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Container table entry and
            fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        utils.create_attrs(self, data)

        if "image_download_vrf" in data:
            self.vrf = self._reference_name(data["image_download_vrf"])
            if self.vrf is not None:
                data["image_download_vrf"] = self._build_vrf_uri()
        if "container_isolated_network" in data:
            self.isolated_network = self._reference_name(
                data["container_isolated_network"]
            )
            if self.isolated_network is not None:
                data["container_isolated_network"] = (
                    self._build_isolated_network_uri()
                )

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(
                self, data, "config_attrs", ["name"]
            )

        self._original_attributes = data
        if "name" in self._original_attributes:
            self._original_attributes.pop("name")

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all Containers and create a dictionary
            containing each respective object.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing container names as keys and Container
            objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", Container.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        containers_dict = {}
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            name, ctr = Container.from_uri(session, uri)
            containers_dict[name] = ctr

        return containers_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create a Container, or update an existing
            one. Checks whether the Container exists in the switch. Calls
            self.update() if Container is being updated. Calls self.create()
            if the Container doesn't exist in the switch.

        :return modified: Boolean, True if object was created or modified.
        """
        modified = False
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing Container table
            entry.

        :return modified: True if Object was modified and a PUT request was
            made.
        """
        ctr_data = utils.get_attrs(self, self.config_attrs)

        net_uri = self._build_isolated_network_uri()
        if net_uri is not None:
            ctr_data["container_isolated_network"] = net_uri

        vrf_uri = self._build_vrf_uri()
        if vrf_uri is not None:
            ctr_data["image_download_vrf"] = vrf_uri

        return self._put_data(ctr_data)

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new Container using the object's
            attributes as POST body.

        :return modified: Boolean, True if Container was created.
        """
        ctr_data = utils.get_attrs(self, self.config_attrs)
        ctr_data["name"] = self.name

        if self.image_location is not None:
            ctr_data["image_location"] = self.image_location

        if self.allow_unsigned_image is not None:
            ctr_data["allow_unsigned_image"] = self.allow_unsigned_image

        if self.enable is not None:
            ctr_data["enable"] = self.enable

        net_uri = self._build_isolated_network_uri()
        if net_uri is not None:
            ctr_data["container_isolated_network"] = net_uri

        vrf_uri = self._build_vrf_uri()
        if vrf_uri is not None:
            ctr_data["image_download_vrf"] = vrf_uri

        return self._post_data(ctr_data)

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete Container table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a Container object given response_data.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {
            "log_agent": "/rest/v10.18/system/containers/log_agent"
            }
        :return: Container Object.
        """
        name_arr = session.api.get_keys(
            response_data, Container.resource_uri_name
        )
        name = name_arr[0]
        return Container(session, name)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Container object given a URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: tuple (name, Container object).
        """
        index_pattern = re.compile(r"(.*)containers/(?P<index>.+)")
        name = index_pattern.match(uri).group("index")
        ctr_obj = Container(session, name, uri=uri)
        return name, ctr_obj

    def __str__(self):
        return "Container, name: '{0}'".format(self.name)

    @PyaoscxModule.connected
    def get_status(self, timeout=STATUS_REQUEST_TIMEOUT):
        """
        Perform a GET call to read the container's runtime state.

        :param timeout: Requests connect/read timeout in seconds.
        :return: Tuple of (status, status_reason). Status is "operational"
            once the image has been downloaded and the container is running.
        """
        data = self._get_data(1, "status", timeout=timeout)
        return data.get("status"), data.get("status_reason", "")

    @PyaoscxModule.connected
    def wait_until_operational(self, timeout=300, interval=5, callback=None):
        """
        Poll the container until it reports "operational", fails, or the
            timeout expires. Creating a container only starts the image
            download, so the switch reports success long before the container
            is usable.

        :param timeout: Nonnegative polling budget in seconds. Each HTTP
            request has a connect/read timeout capped by the remaining
            budget; responses arriving after the deadline cannot succeed.
        :param interval: Positive number of seconds between polls.
        :param callback: Optional callable invoked as
            callback(status, status_reason) when either value changes.
        :return: Tuple of (operational, status, status_reason).
        """
        if not isfinite(timeout) or timeout < 0:
            raise ParameterError("timeout must be finite and nonnegative")
        if not isfinite(interval) or interval <= 0:
            raise ParameterError("interval must be finite and positive")
        deadline = time.monotonic() + timeout
        status = reason = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, status, reason
            try:
                new_status, new_reason = self.get_status(
                    timeout=min(STATUS_REQUEST_TIMEOUT, remaining)
                )
            except ResponseError as error:
                if isinstance(error.__cause__, Timeout):
                    return False, status, str(error)
                raise
            changed = (new_status, new_reason) != (status, reason)
            status, reason = new_status, new_reason
            if changed:
                logging.info(
                    "Container %s status: %s %s", self.name, status, reason
                )
                if callback is not None:
                    callback(status, reason)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, status, reason
            if status == "operational":
                return True, status, reason
            if status and any(
                hint in status for hint in ("failed", "error", "down")
            ):
                return False, status, reason
            time.sleep(min(interval, remaining))

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific object URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                Container.base_uri,
                self.name,
            )
        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.

        :return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified
