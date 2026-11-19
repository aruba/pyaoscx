# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import logging
import time

from pyaoscx.utils import util as utils

from pyaoscx.nae_agent import NaeAgent
from pyaoscx.nae_script import NaeScript, get_json, name_from_uri

from pyaoscx.pyaoscx_module import PyaoscxModule


class NaeLiteAgent(PyaoscxModule):
    """
    Provide configuration management for NAE-Lite agents on AOS-CX devices
        (CLI "nae-agent lite", REST table NAE_Script_Generate).

    A NAE-Lite agent is defined by monitors (for example the "system cpu"
        resource) or watches (event log IDs), and by conditions, managed with
        the NaeLiteCondition class. Once activated, the switch generates a NAE
        Script and a NAE Agent with the name of the NAE-Lite agent.
    """

    collection_uri = "system/nae_script_generates"
    object_uri = collection_uri + "/{name}"
    resource_uri_name = "name"
    indices = ["name"]

    final_states = ("AGENT_CREATED", "ERROR")

    def __init__(self, session, name, **kwargs):
        self.session = session
        self.__name = name

        # List used to determine attributes related to the NAE-Lite Agent
        # configuration
        self.config_attrs = []
        self.materialized = False

        # Attribute dictionary used to manage the original data
        # obtained from the GET request
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)

        # Used to know if the object was changed since the last request
        self.__modified = False

        # Execution and error times before an activation, used to tell the
        # status of the new generation from the status of the previous one
        self.__before_activation = {}

        self.path = self.object_uri.format(name=name)
        self.base_uri = self.collection_uri

    @property
    def name(self):
        return self.__name

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a NAE-Lite Agent and fill the
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

        # Conditions are managed with the NaeLiteCondition class
        data.pop("conditions", None)

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            utils.set_config_attrs(self, data, "config_attrs")

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all NAE-Lite Agents and create a
            dictionary containing each of them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing NAE-Lite Agent names as keys and a
            NAE-Lite Agent object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        data = get_json(session, cls.collection_uri)

        agent_dict = {}
        for uri in session.api.get_uri_from_data(data):
            name, agent = cls.from_uri(session, uri)
            agent_dict[name] = agent

        return agent_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing NAE-Lite
            Agent. Checks whether the NAE-Lite Agent exists in the switch and
            calls self.update() or self.create() accordingly.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing NAE-Lite Agent.
            The switch does not regenerate an activated agent on changes: call
            activate() afterwards to apply them.

        :return: True if the object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data.pop("name", None)
        self.__modified = self._put_data(data)
        logging.info("SUCCESS: Updating %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new NAE-Lite Agent in the switch. The
            agent is activated with activate(), once its conditions are
            created.

        :return: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data = {key: value for key, value in data.items() if value is not None}
        data["name"] = self.name
        self.__modified = self._post_data(data)
        logging.info("SUCCESS: Adding %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a NAE-Lite Agent from the switch,
            with its conditions and the NAE Script and NAE Agent generated
            from it.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.connected
    def activate(self):
        """
        Activate the NAE-Lite Agent (CLI "nae-agent lite <name> activate"):
            the switch generates the NAE Script and the NAE Agent. An agent
            that is already activated is deactivated first, so that the
            switch generates it again with the current configuration.
        """
        self.__before_activation = self._get_activation_times()
        if self._get_ready():
            self._set_ready(False)
        self._set_ready(True)

    @PyaoscxModule.connected
    def deactivate(self):
        """
        Deactivate the NAE-Lite Agent.

        :return: True if the agent was activated.
        """
        if not self._get_ready():
            return False
        self._set_ready(False)
        return True

    def _get_ready(self):
        data = get_json(
            self.session, self.path, params={"attributes": "ready"}
        )
        return bool(data.get("ready"))

    def _set_ready(self, ready):
        self._send_data(self.path, {"ready": ready}, "PATCH", "Update")
        self.ready = ready
        if "ready" in self._original_attributes:
            self._original_attributes["ready"] = ready

    def _get_activation_times(self):
        try:
            status = self.get_status()
        except Exception:
            return {}
        agent = status["agent"] or {}
        return {
            "error_at": status["error_at"],
            "agent_error_at": agent.get("error_at"),
            "executed_at": agent.get("executed_at"),
        }

    @property
    def generated_agent(self):
        """
        NAE Agent generated by the switch for this NAE-Lite Agent.
        """
        return NaeAgent(
            self.session, self.name, NaeScript(self.session, self.name)
        )

    @PyaoscxModule.connected
    def get_generation_status(self):
        """
        Retrieve the generation status of the NAE-Lite Agent.

        :return: Dictionary with ready, state (PENDING, SCRIPT_GENERATED,
            SCRIPT_VALIDATED, AGENT_CREATED or ERROR), error_description and
            error_at.
        """
        data = get_json(
            self.session, self.path, params={"attributes": "ready,status"}
        )
        status = data.get("status") or {}
        return {
            "ready": bool(data.get("ready")),
            "state": status.get("state"),
            "error_description": status.get("error_description") or None,
            "error_at": status.get("error_at") or None,
        }

    @PyaoscxModule.connected
    def get_status(self):
        """
        Retrieve the generation status of the NAE-Lite Agent and the status
            of the generated NAE Agent.

        :return: Dictionary as returned by get_generation_status(), with the
            name and an agent key holding the generated NAE Agent status (see
            NaeAgent.get_status()), None if it does not exist.
        """
        status = self.get_generation_status()
        status["name"] = self.name
        try:
            status["agent"] = self.generated_agent.get_status()
        except Exception:
            status["agent"] = None
        return status

    @PyaoscxModule.connected
    def wait_for_activation(self, timeout=60, interval=2):
        """
        Wait until the switch has generated the NAE-Lite Agent and the
            generated NAE Agent has run, or has failed, after activate().

        :param timeout: Maximum time to wait, in seconds.
        :param interval: Time between two checks, in seconds.
        :return: Dictionary as returned by get_status(). Its state is ERROR
            when the generation or the agent failed, and is not one of
            AGENT_CREATED or ERROR when the timeout expired.
        """
        # Until the switch processes the activation, it still shows the
        # status of the previous generation: errors and executions are only
        # taken into account when they are new.
        before = self.__before_activation
        deadline = time.time() + timeout
        while True:
            status = self.get_status()
            agent = status["agent"] or {}
            if status["state"] == "ERROR" and status["error_at"] != before.get(
                "error_at"
            ):
                return status
            if status["state"] == "AGENT_CREATED":
                if agent.get("error_description") and agent.get(
                    "error_at"
                ) != before.get("agent_error_at"):
                    status["state"] = "ERROR"
                    status["error_description"] = agent["error_description"]
                    return status
                executed_at = agent.get("executed_at")
                if executed_at and executed_at != before.get("executed_at"):
                    return status
            if time.time() >= deadline:
                return status
            time.sleep(interval)

    @classmethod
    def get_facts(cls, session):
        """
        Retrieve the configuration and generation status of all NAE-Lite
            Agents.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: Dictionary containing the agent name as key and its
            configuration and status as value.
        """
        logging.info("Retrieving NAE-Lite Agents facts")

        data = get_json(session, cls.collection_uri, params={"depth": 2})
        for agent in data.values():
            agent.pop("conditions", None)
        return data

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a NAE-Lite Agent object given an URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return: tuple with the name and the NAE-Lite Agent.
        """
        name = name_from_uri(uri)
        return name, cls(session, name)

    @classmethod
    def from_response(cls, session, response_data):
        """
        Create a NAE-Lite Agent object given a response_data.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param response_data: The response must be a dictionary of the form:
            {name: URI}.
        :return: NAE-Lite Agent object.
        """
        uri = next(iter(response_data.values()))
        _, agent = cls.from_uri(session, uri)
        return agent

    def __str__(self):
        return "NAE-Lite Agent {0}".format(self.name)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
