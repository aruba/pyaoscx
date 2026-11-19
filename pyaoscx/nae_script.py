# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import base64
import binascii
import hashlib
import json
import logging
import time

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


def get_json(session, uri, params=None):
    """
    Perform a GET request and return the decoded JSON body.

    :param session: pyaoscx.Session object used to represent a logical
        connection to the device.
    :param uri: URI of the resource, relative to the REST version prefix.
    :param params: Optional dictionary of query parameters.
    :return: Decoded JSON body.
    """
    try:
        response = session.request("GET", uri, params=params)
    except Exception as exc:
        raise ResponseError("GET", exc)

    if not utils._response_ok(response, "GET"):
        raise GenericOperationError(response.text, response.status_code)

    return json.loads(response.text)


def name_from_uri(value):
    """
    Return the last element of a URI, the switch returns references to other
        resources (NAE parameters, VRFs) as URIs.

    :param value: URI or plain name.
    :return: Name of the referenced resource.
    """
    return str(value).rstrip("/").split("/")[-1]


class NaeScript(PyaoscxModule):
    """
    Provide configuration management for Network Analytics Engine (NAE)
        scripts on AOS-CX devices.

    The script content is sent and returned by the switch in Base64; use
        set_script_code() or load_script_from_file() to set it from the Python
        source, set_script_base64() to set it from its Base64 encoding, and
        get_script_code() to read it back.
    """

    collection_uri = "system/nae_scripts"
    object_uri = collection_uri + "/{name}"
    resource_uri_name = "name"
    indices = ["name"]

    final_states = ("VALIDATED", "ERROR")

    status_attributes = [
        "aoscx_platform_list",
        "aoscx_version_max",
        "aoscx_version_min",
        "author",
        "description",
        "expert_only",
        "name",
        "origin",
        "required_nae_api_version",
        "status",
        "tags",
        "target_platform",
        "target_software_version",
        "version",
    ]

    def __init__(self, session, name, **kwargs):
        self.session = session
        self.__name = name

        # List used to determine attributes related to the NAE Script
        # configuration
        self.config_attrs = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET request
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)

        # Used to know if the object was changed since the last request
        self.__modified = False

        self.path = self.object_uri.format(name=name)
        self.base_uri = self.collection_uri

    @property
    def name(self):
        return self.__name

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a NAE Script and fill the
            object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # Agents are managed with the NaeAgent class
        data.pop("nae_agents", None)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs")

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all NAE Scripts and create a dictionary
            containing each of them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing NAE Script names as keys and a NAE
            Script object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        data = get_json(session, cls.collection_uri)

        script_dict = {}
        for uri in session.api.get_uri_from_data(data):
            name, script = cls.from_uri(session, uri)
            script_dict[name] = script

        return script_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing NAE Script.
            Checks whether the NAE Script exists in the switch and calls
            self.update() or self.create() accordingly.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing NAE Script. The
            agents of the script are kept and run the new script.

        :return: True if the object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data.pop("name", None)
        if data.get("script") and data != self._original_attributes:
            self._revalidate_if_needed(data)
        self.__modified = self._put_data(data)
        logging.info("SUCCESS: Updating %s", self)
        return self.__modified

    def _revalidate_if_needed(self, data):
        """
        The switch does not validate again a content whose checksum is the
            one of the last validated content: after a failed validation,
            uploading the last valid content again leaves the script in the
            ERROR state. In this case a variant of the content, with an extra
            line break, is uploaded and validated first.

        :param data: Body of the PUT request about to be sent.
        """
        code = base64.b64decode(data["script"])
        status = self.get_status()
        if (
            status["state"] != "ERROR"
            or status["script_checksum"] != hashlib.sha512(code).hexdigest()
        ):
            return
        logging.info("Uploading a variant of %s to validate it again", self)
        variant = dict(data, script=self.encode_script(code + b"\n"))
        self._send_data(self.path, variant, "PUT", "Update")
        self.script = variant["script"]
        try:
            self.wait_for_validation()
        finally:
            self.script = data["script"]

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to upload a new NAE Script to the switch.

        :return: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data["name"] = self.name
        self.__modified = self._post_data(data)
        logging.info("SUCCESS: Adding %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a NAE Script from the switch. The
            agents of the script are removed with it. Scripts generated by a
            NAE-Lite agent are removed with the NaeLiteAgent class.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @staticmethod
    def encode_script(code):
        """
        Encode the Python source of a NAE Script in Base64, as expected by
            the switch.

        :param code: Script source, as str or bytes.
        :return: Base64 string.
        """
        if not isinstance(code, bytes):
            code = code.encode("utf-8")
        return base64.b64encode(code).decode("ascii")

    def set_script_code(self, code):
        """
        Set the script content from its Python source.

        :param code: Script source, as str or bytes.
        """
        self.script = self.encode_script(code)
        if "script" not in self.config_attrs:
            self.config_attrs.append("script")

    @staticmethod
    def decode_script_base64(value):
        """
        Decode a NAE Script content given in Base64. Whitespace and line
            breaks, as added by tools wrapping Base64 lines, are ignored.

        :param value: Base64 content, as str or bytes.
        :return: Script source, as bytes.
        """
        if isinstance(value, bytes):
            value = value.decode("ascii", "replace")
        cleaned = "".join(value.split())
        try:
            code = base64.b64decode(cleaned, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ParameterError(
                "Invalid Base64 NAE Script content: {0}".format(exc)
            )
        if not code:
            raise ParameterError("Empty Base64 NAE Script content")
        return code

    def set_script_base64(self, value):
        """
        Set the script content from its Base64 encoding, after checking it.
            The content is sent in the canonical Base64 form, so that it can
            be compared with the content returned by the switch.

        :param value: Base64 content, as str or bytes.
        """
        self.set_script_code(self.decode_script_base64(value))

    def load_script_from_file(self, path):
        """
        Set the script content from a local Python file.

        :param path: Path of the NAE Script file.
        """
        with open(path, "rb") as script_file:
            self.set_script_code(script_file.read())

    def get_script_code(self):
        """
        Return the Python source of the script, decoded from the Base64
            content read from the switch.

        :return: Script source as str, None if the content is unknown.
        """
        script = getattr(self, "script", None)
        if not script:
            return None
        return base64.b64decode(script).decode("utf-8")

    @PyaoscxModule.connected
    def get_status(self):
        """
        Retrieve the information and validation status of the NAE Script.

        :return: Dictionary with the script information (origin, version,
            author, description...) and its status: state (CREATED,
            VALIDATING, VALIDATED or ERROR), error_description and error_at.
        """
        data = get_json(
            self.session,
            self.path,
            params={"attributes": ",".join(self.status_attributes)},
        )
        return self._format_status(data)

    @PyaoscxModule.connected
    def wait_for_validation(self, timeout=30, interval=1):
        """
        Wait until the switch has validated the script uploaded or updated:
            agents cannot be created before.

        :param timeout: Maximum time to wait, in seconds.
        :param interval: Time between two checks, in seconds.
        :return: Dictionary as returned by get_status(). Its state is
            VALIDATED or ERROR, or another state when the timeout expired.
        """
        # The switch exposes the SHA-512 of the validated script: a VALIDATED
        # or ERROR state read before the validation of the new content
        # started belongs to the previous content.
        expected_checksum = None
        if getattr(self, "script", None):
            expected_checksum = hashlib.sha512(
                base64.b64decode(self.script)
            ).hexdigest()
        validating = False
        deadline = time.time() + timeout
        while True:
            status = self.get_status()
            state = status["state"]
            if state == "VALIDATED" and expected_checksum in (
                None,
                status["script_checksum"],
            ):
                return status
            if state == "ERROR" and (expected_checksum is None or validating):
                return status
            if state not in self.final_states:
                validating = True
            if time.time() >= deadline:
                return status
            time.sleep(interval)

    @classmethod
    def _format_status(cls, data):
        status = data.get("status") or {}
        info = {
            key: data.get(key)
            for key in cls.status_attributes
            if key != "status"
        }
        info["state"] = status.get("state")
        info["error_description"] = status.get("error_description") or None
        info["error_at"] = status.get("error_at") or None
        info["script_checksum"] = status.get("script_checksum")
        return info

    @PyaoscxModule.connected
    def get_parameters(self):
        """
        Retrieve the parameters defined by the NAE Script.

        :return: Dictionary with the parameter names as keys and their
            definition (type, default_value, required, encrypt, descriptions)
            as values.
        """
        uri = "{0}/nae_parameters".format(self.path)
        return get_json(self.session, uri, params={"depth": 2})

    @classmethod
    def get_facts(cls, session):
        """
        Retrieve the information and status of all NAE Scripts, without their
            content.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing the script name as key and its
            information and status as value.
        """
        logging.info("Retrieving NAE Scripts facts")

        data = get_json(
            session,
            cls.collection_uri,
            params={
                "depth": 2,
                "attributes": ",".join(cls.status_attributes),
            },
        )
        return {
            name: cls._format_status(script) for name, script in data.items()
        }

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a NAE Script object given an URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return: tuple with the name and the NAE Script.
        """
        name = name_from_uri(uri)
        return name, cls(session, name)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a NAE Script object given a response_data.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {name: URI}.
        :return: NAE Script object.
        """
        uri = next(iter(response_data.values()))
        _, script = cls.from_uri(session, uri)
        return script

    def __str__(self):
        return "NAE Script {0}".format(self.name)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
