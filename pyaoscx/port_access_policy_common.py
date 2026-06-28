# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Common base classes for the Port Access policy families (Group Based Policy,
Application Based Policy and Port Access Policy).

The three families share the exact same three level shape::

    container (system/port_access_<family>s, indexed by name)
      -> cfg_entries/{sequence_number} (traffic class reference + comment)
           -> <family>_action_set (drop, ... family specific fields)

Each family provides thin subclasses that only set ``base_uri`` /
``resource_uri_name`` (container) and ``action_key`` (action set).
"""

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class PortAccessPolicyContainer(PyaoscxModule):
    """
    Base class for a Port Access policy family container, indexed by name.
    Subclasses must set ``base_uri`` and ``resource_uri_name``.
    """

    base_uri = None
    resource_uri_name = None

    indices = ["name"]

    def __init__(self, session, name, uri=None, **kwargs):
        self.session = session
        self.name = name
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self._modified = False
        self.path = "{0}/{1}".format(self.base_uri, self.name)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a policy container and fill the
            object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {0}".format(depths))

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

        data = json.loads(response.text)

        if "name" in data:
            data.pop("name")

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", ["name"])

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all containers of this family and create
            a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing the names as keys and the objects as
            values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.base_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        containers = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            index, container = cls.from_uri(session, uri)
            containers[index] = container

        return containers

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing policy
            container.

        :return: Boolean, True if object was created or modified.
        """
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self._modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing policy container.

        :return: True if Object was modified and a PUT request was made.
        """
        container_data = utils.get_attrs(self, self.config_attrs)

        if container_data == self._original_attributes:
            return False

        post_data = json.dumps(container_data)

        try:
            response = self.session.request("PUT", self.path, data=post_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = container_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new policy container. Only returns if
            no exception is raised.

        :return: Boolean, True if container was created.
        """
        container_data = utils.get_attrs(self, self.config_attrs)
        container_data["name"] = self.name

        post_data = json.dumps(container_data)

        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
            )
        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        self.get()
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete a policy container.
        """
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a policy container object given a response_data.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param response_data: The response must be a dictionary of the form:
            {name: "/rest/v10.xx/system/port_access_<family>s/name"}
        :return: policy container object.
        """
        container_arr = session.api.get_keys(
            response_data, cls.resource_uri_name
        )
        name = container_arr[0]
        return cls(session, name)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a policy container object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param uri: a String with a URI.
        :return: tuple containing both the index and the object.
        """
        index_pattern = re.compile(
            r"(.*){0}/(?P<index>.+)".format(cls.resource_uri_name)
        )
        name = index_pattern.match(uri).group("index")

        container = cls(session, name)
        return name, container

    def __str__(self):
        return "{0} name:{1}".format(type(self).__name__, self.name)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific policy container URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_prefix,
                self.base_uri,
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
        return self._modified


class PortAccessPolicyEntry(PyaoscxModule):
    """
    Base class for a Port Access policy entry, child of a container and indexed
    by sequence_number. Holds the referenced traffic class and a comment.
    """

    resource_name = "sequence_number"
    indices = ["sequence_number"]

    def __init__(
        self, session, sequence_number, parent_container, uri=None, **kwargs
    ):
        self.__parent_container = parent_container
        self.__sequence_number = sequence_number
        self.session = session
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self._modified = False
        self.base_uri = "{0}/cfg_entries".format(parent_container.path)
        self.path = "{0}/{1}".format(self.base_uri, sequence_number)

    @property
    def sequence_number(self):
        return self.__sequence_number

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a policy entry and fill the
            object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {0}".format(depths))

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

        data = json.loads(response.text)

        if "sequence_number" in data:
            data.pop("sequence_number")

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(
                self, data, "config_attrs", ["sequence_number"]
            )

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_container):
        """
        Perform a GET call to retrieve all entries of a container and create a
            dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object.
        :param parent_container: container object to which the entries belong.
        :return: Dictionary keyed by sequence number with the entry objects as
            values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/cfg_entries".format(parent_container.path)

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        entries = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            sequence_number, entry = cls.from_uri(
                session, parent_container, uri
            )
            entries[sequence_number] = entry

        return entries

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing policy entry.

        :return: Boolean, True if object was created or modified.
        """
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self._modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing policy entry.

        :return: True if Object was modified and a PUT request was made.
        """
        entry_data = utils.get_attrs(self, self.config_attrs)

        if entry_data == self._original_attributes:
            return False

        post_data = json.dumps(entry_data)

        try:
            response = self.session.request("PUT", self.path, data=post_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = entry_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new policy entry. Only returns if no
            exception is raised.

        :return: Boolean, True if entry was created.
        """
        entry_data = utils.get_attrs(self, self.config_attrs)
        entry_data["sequence_number"] = self.sequence_number

        post_data = json.dumps(entry_data)

        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
            )
        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        self.get()
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete a policy entry.
        """
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, parent_container, uri):
        """
        Create a policy entry object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param parent_container: container object to which the entry belongs.
        :param uri: a String with a URI.
        :return: tuple containing both the sequence number and the object.
        """
        sequence_number = uri.split("/")[-1]
        entry = cls(session, sequence_number, parent_container)
        return sequence_number, entry

    def __str__(self):
        return "{0} sequence_number:{1}".format(
            type(self).__name__, self.sequence_number
        )

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific policy entry URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix,
                self.path,
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
        return self._modified


class PortAccessActionSet(PyaoscxModule):
    """
    Base class for a Port Access policy entry action set. It is a singleton
    child of an entry reachable at ``<entry>/<action_key>``. Subclasses must
    set ``action_key``.
    """

    action_key = None

    def __init__(self, session, parent_entry, uri=None, **kwargs):
        self.__parent_entry = parent_entry
        self.session = session
        self._uri = uri
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)
        self._modified = False
        self.path = "{0}/{1}".format(parent_entry.path, self.action_key)
        self.base_uri = self.path

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for an action set and fill the
            object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {0}".format(depths))

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

        data = json.loads(response.text)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs", [])

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, parent_entry):
        """
        Retrieve the singleton action set of an entry, if it exists.

        :param cls: Object's class.
        :param session: pyaoscx.Session object.
        :param parent_entry: entry object to which the action set belongs.
        :return: Dictionary keyed by the action key with the action set object
            as value, or an empty dictionary when it does not exist.
        """
        action = cls(session, parent_entry)
        try:
            action.get()
        except GenericOperationError:
            return {}
        return {cls.action_key: action}

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing action set.

        :return: Boolean, True if object was created or modified.
        """
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        self._modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing action set.

        :return: True if Object was modified and a PUT request was made.
        """
        action_data = utils.get_attrs(self, self.config_attrs)

        if action_data == self._original_attributes:
            return False

        post_data = json.dumps(action_data)

        try:
            response = self.session.request("PUT", self.path, data=post_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Updating %s", self)
        self._original_attributes = action_data
        return True

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new action set. Only returns if no
            exception is raised.

        :return: Boolean, True if action set was created.
        """
        action_data = utils.get_attrs(self, self.config_attrs)

        post_data = json.dumps(action_data)

        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
            )
        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete an action set.
        """
        try:
            response = self.session.request("DELETE", self.path)
        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    def __str__(self):
        return "{0}".format(type(self).__name__)

    @classmethod
    def from_uri(cls, session, parent_entry, uri):
        """
        Create an action set object given a URI.

        :param cls: Class calling the method.
        :param session: pyaoscx.Session object.
        :param parent_entry: entry object to which the action set belongs.
        :param uri: a String with a URI.
        :return: tuple containing the action key and the action set object.
        """
        action = cls(session, parent_entry)
        return cls.action_key, action

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific action set URI.

        :return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}".format(
                self.session.resource_prefix,
                self.path,
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
        return self._modified
