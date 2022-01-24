# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import functools
import json
import logging
import warnings

from abc import ABC, abstractmethod
from copy import deepcopy

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils


class PyaoscxModule(ABC):
    """
    Provide an Interface class for pyaoscx Modules.
    """

    base_uri = ""
    indices = []

    def connected(fnct):
        """
        Function used as a decorator to ensure the module has a established
            connection.
        :param fnct: function which behavior is modified.
        :return ensure_connected: Function.
        """

        @functools.wraps(fnct)
        def ensure_connected(self, *args, **kwargs):
            if not self.session.connected:
                self.session.open()
            return fnct(self, *args, **kwargs)

        return ensure_connected

    def materialized(fnct):
        """
        Function used as a decorator to verify if the object is materialized.
        :para fnct: function which behavior is modified.
        :return is_materialized: Function.
        """

        @functools.wraps(fnct)
        def is_materialized(self, *args, **kwargs):
            if not self.materialized:
                raise VerificationError(
                    "Object {0}".format(self), " not materialized"
                )
            return fnct(self, *args, **kwargs)

        return is_materialized

    def deprecated(func):
        """
        Function used as a decorator to show deprecation notice of a method.
        :param func: function whose behavior is modified/wrapped.
        :return func: function whose behavior is modified/wrapped.
        """

        @functools.wraps(func)
        def is_deprecated(*args, **kwargs):
            warnings.warn(
                "{0} will be removed in a future version".format(
                    func.__name__
                ),
                category=DeprecationWarning,
                stacklevel=2,
            )
            return func(*args, **kwargs)

        return is_deprecated

    @abstractmethod
    @connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a table entry and fill the
            object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        pass

    @abstractmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all system <pyaoscx_module_type> and
            create a dictionary of each object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing object IDs as keys their respective
            objects as values.
        """
        pass

    @abstractmethod
    @connected
    def apply(self):
        """
        Main method used to either create or update an existing
            <pyaoscx_module_type>. Checks whether the <pyaoscx_module_type>
            exists in the switch. Calls self.update() if object being updated.
            Calls self.create() if a new <pyaoscx_module_type> is being
            created.
        :return modified: Boolean, True if object was created or modified.
        """
        pass

    @abstractmethod
    @connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing
            <pyaoscx_module_type> table entry.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        pass

    @abstractmethod
    @connected
    def create(self):
        """
        Perform a POST call to create a new <pyaoscx_module_type>. Only returns
            if an exception is not raise.
        :return modified: Boolean, True if entry was created.
        """
        pass

    @abstractmethod
    @connected
    def delete(self):
        """
        Perform DELETE call to delete <pyaoscx_module_type> table entry.
        """
        pass

    @abstractmethod
    def from_uri(cls, session, uri):
        """
        Create a <pyaoscx_module_type> object given its URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return index, <pyaoscx_module_type>: tuple containing both the
            <pyaoscx_module_type> object its ID.
        """
        pass

    def _get_and_copy_data(
        self, depth=None, selector=None, unwanted_attrs=None
    ):
        """
        Get data from switch with _get_data, and populate the object with the
            data obtained. Note that this is meant to be a common block in the
            get() method of modules derived from PyaoscxModule, and the
            specifics of each module with the _original_attributes dictionary
            should be done in each module's get() body.
        """
        unwanted_attrs = unwanted_attrs or []
        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        self._original_attributes = deepcopy(data)

        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete unwanted attributes
            utils.set_config_attrs(self, data, "config_attrs", unwanted_attrs)

    def _get_data(self, depth, selector):
        """
        Perform a GET call to retrieve data from a switch.
        :param depth: Integer deciding how many levels into the API JSON
            that references will be retrieved from the switch
        :param selector: Alphanumeric option to select specific information
            to return.
        :return: Retrieved data from the switch.
        """
        depth = depth or self.session.api.default_depth

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be one of {0}".format(depths))

        if selector not in self.session.api.valid_selectors:
            selectors = " ".join(self.session.api.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {0}".format(selectors)
            )

        payload = {"depth": depth, "selector": selector}

        try:
            response = self.session.request("GET", self.path, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        return json.loads(response.text)

    def _put_data(self, data):
        """
        Perform a PUT request to the switch.
        :param data: data to send.
        :return: True if the object was modified.
        """
        if data == self._original_attributes:
            return False

        self._send_data(self.path, data, "PUT", "Update")
        # Set new original attributes
        self._original_attributes = data
        # Object was modified
        return True

    def _post_data(self, data):
        """
        Perform a POST request to the switch.
        :param data: data to send.
        """
        self._send_data(self.base_uri, data, "POST", "Adding")
        # Get the data from the created object
        self.get()
        return True

    def _send_data(self, path, data, http_verb, display_verb):
        """
        Perform either PUT or POST operation to the switch.
        :param path: path of the resource for the request. This could
            the base URI if this was called in a create method, or
            the VLAN URI if this was called in an update method.
        :param data: data to send.
        :param hrrp_verb: HTTP operation to perfrom.
        :display_module_name: Module to display in logs.
        :display_verb: verb to display in logs.
        """
        send_data = json.dumps(data, sort_keys=True, indent=4)

        try:
            response = self.session.request(http_verb, path, data=send_data)

        except Exception as e:
            raise ResponseError(http_verb, e)

        if not utils._response_ok(response, http_verb):
            raise GenericOperationError(response.text, response.status_code)

        logging.info(
            "SUCCESS: %s %s table entry succeeded",
            display_verb,
            type(self).__name__,
        )

    @staticmethod
    def _is_replace_required(current, replacement, immutable_parameter_names):
        """
        Compares two PYAOSCX modules to determine if a replace (delete+create)
            is required. To do so, all the immutable parameters are checked; in
            case any of them differs a replace is required. Note that if the
            replacement object has a None parameter then a replace is not
            required because they just get ignored, null parameters are
            meant to be taken as 'keep the current value' by PYAOSCX.
        :param current: Module representing the current switch configuration.
        :param replacement: Another Module (same type) object to compare to
        :param immutable_parameter_names: the names of parameters that cannot
            change once the module has been created.
        :return: True if a replacement is required.
        """
        for param_name in immutable_parameter_names:
            if hasattr(current, param_name) and hasattr(
                replacement, param_name
            ):
                # In this case, a common parameter has a different value in the
                # potential replacement config, so a replacement is required
                old = getattr(current, param_name)
                new = getattr(replacement, param_name)
                if new is not None and old != new:
                    return True
            elif hasattr(replacement, param_name):
                # In this case the replacement has an attribute that the
                # current lacks, so a replacement is required
                if getattr(replacement, param_name) is not None:
                    return True

    def _extract_missing_parameters_from(self, other):
        """
        Extract the missing configuration parameters from another PYAOSCX
            Module, to incorporate them as their own. This is useful when
            replacing (delete+create) Modules. If the Module has to be
            replaced, the parameters that are not specified (locally) should
            remain unchanged (switch), so it is necessary to extract them from
            the switch before performing the replacement.
        :param other: the other module to extract the parameters.
        """
        # Until we are able to read the Schema we need to keep a list of the
        # the names of mutable an immutable parameters. Once we are capable of
        # using the schema, the information can be taken from there.
        all_param_names = (
            self.immutable_parameter_names + self.mutable_parameter_names
        )
        for param_name in all_param_names:
            if hasattr(other, param_name):
                param = getattr(other, param_name)
                if not hasattr(self, param_name):
                    if param is not None:
                        setattr(self, param_name, deepcopy(param))
                else:
                    if getattr(self, param_name) is None:
                        setattr(self, param_name, deepcopy(param))

    @deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)
