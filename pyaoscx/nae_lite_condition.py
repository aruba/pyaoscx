# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import logging

from pyaoscx.utils import util as utils

from pyaoscx.nae_lite_agent import NaeLiteAgent
from pyaoscx.nae_script import get_json

from pyaoscx.pyaoscx_module import PyaoscxModule


class NaeLiteCondition(PyaoscxModule):
    """
    Provide configuration management for the conditions of NAE-Lite agents
        on AOS-CX devices (CLI "set-condition" and "clear-condition", REST
        table NAE_Script_Condition).

    A condition is identified by its rule name (the CLI uses "Default") and
        its type: active_condition (CLI "set-condition") or clear_condition.
        The expression uses the CLI syntax, for example "gt 90 for 2 minutes"
        on a monitor or "count 5" on a watch, and applies to the monitor or
        watch named in resource_name ({"0": <name>}).
    """

    collection_uri = "system/nae_script_generates/{name}/conditions"
    object_uri = collection_uri + "/{rule_name},{condition_type}"
    resource_uri_name = "conditions"
    indices = ["rule_name", "condition_type"]

    DEFAULT_RULE = "Default"
    ACTIVE_CONDITION = "active_condition"
    CLEAR_CONDITION = "clear_condition"

    def __init__(
        self,
        session,
        rule_name,
        condition_type,
        parent_nae_lite_agent,
        **kwargs
    ):
        self.session = session
        self.__rule_name = rule_name
        self.__condition_type = condition_type
        if not isinstance(parent_nae_lite_agent, NaeLiteAgent):
            parent_nae_lite_agent = NaeLiteAgent(
                session, parent_nae_lite_agent
            )
        self.__parent_nae_lite_agent = parent_nae_lite_agent

        # List used to determine attributes related to the condition
        # configuration
        self.config_attrs = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET request
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)

        # Used to know if the object was changed since the last request
        self.__modified = False

        self.path = self.object_uri.format(
            name=parent_nae_lite_agent.name,
            rule_name=rule_name,
            condition_type=condition_type,
        )
        self.base_uri = self.collection_uri.format(
            name=parent_nae_lite_agent.name
        )

    @property
    def rule_name(self):
        return self.__rule_name

    @property
    def condition_type(self):
        return self.__condition_type

    @property
    def nae_lite_agent(self):
        return self.__parent_nae_lite_agent

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a NAE-Lite condition and fill
            the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        # The indices are read-only properties
        data.pop("rule_name", None)
        data.pop("condition_type", None)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs")

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, nae_lite_agent_name):
        """
        Perform a GET call to retrieve all the conditions of a NAE-Lite Agent
            and create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param nae_lite_agent_name: Name of the NAE-Lite Agent.
        :return: Dictionary containing "<rule_name>,<condition_type>" as keys
            and a NAE-Lite condition object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        data = get_json(
            session, cls.collection_uri.format(name=nae_lite_agent_name)
        )

        condition_dict = {}
        for uri in session.api.get_uri_from_data(data):
            index, condition = cls.from_uri(session, uri)
            condition_dict[index] = condition

        return condition_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing NAE-Lite
            condition. Checks whether the condition exists in the switch and
            calls self.update() or self.create() accordingly.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing NAE-Lite
            condition. An activated NAE-Lite Agent must be activated again to
            apply the change, see NaeLiteAgent.activate().

        :return: True if the object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data.pop("rule_name", None)
        data.pop("condition_type", None)
        self.__modified = self._put_data(data)
        logging.info("SUCCESS: Updating %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new NAE-Lite condition in the switch.

        :return: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data = {key: value for key, value in data.items() if value is not None}
        data["rule_name"] = self.rule_name
        data["condition_type"] = self.condition_type
        self.__modified = self._post_data(data)
        logging.info("SUCCESS: Adding %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a NAE-Lite condition from the switch.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a NAE-Lite condition object given an URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return: tuple with the "<rule_name>,<condition_type>" index and the
            NAE-Lite condition.
        """
        # URI format is:
        # /system/nae_script_generates/{name}/conditions/{rule},{type}
        parts = uri.rstrip("/").split("/")
        index = parts[-1]
        rule_name, condition_type = index.rsplit(",", 1)
        agent = NaeLiteAgent(session, parts[-3])
        return index, cls(session, rule_name, condition_type, agent)

    def __str__(self):
        return "NAE-Lite condition {0},{1} of NAE-Lite Agent {2}".format(
            self.rule_name, self.condition_type, self.nae_lite_agent.name
        )

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
