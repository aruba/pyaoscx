# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import logging

from pyaoscx.utils import util as utils

from pyaoscx.nae_script import NaeScript, get_json, name_from_uri

from pyaoscx.pyaoscx_module import PyaoscxModule


class NaeAgent(PyaoscxModule):
    """
    Provide configuration management for Network Analytics Engine (NAE)
        agents on AOS-CX devices, and the collection of their status and
        alerts.

    The values of the script parameters are set with the parameters_values
        dictionary, keyed by parameter name. Encrypted parameters are set with
        the encrypted_parameters_values dictionary: the switch only returns
        their encrypted form, so they are only sent when set explicitly, and
        their names are listed in encrypted_parameters_names after get().
    """

    collection_uri = "system/nae_scripts/{script}/nae_agents"
    object_uri = collection_uri + "/{name}"
    resource_uri_name = "name"
    indices = ["name"]

    status_attributes = [
        "alert_info",
        "disabled",
        "nae_alerts_count",
        "nae_rules_count",
        "nae_time_series_count",
        "origin",
        "statistics",
        "status",
        "vrf",
    ]

    def __init__(self, session, name, parent_nae_script, **kwargs):
        self.session = session
        self.__name = name
        if not isinstance(parent_nae_script, NaeScript):
            parent_nae_script = NaeScript(session, parent_nae_script)
        self.__parent_nae_script = parent_nae_script

        # List used to determine attributes related to the NAE Agent
        # configuration
        self.config_attrs = []
        self.materialized = False
        self.encrypted_parameters_names = []

        # Attribute dictionary used to manage the original data
        # obtained from the GET request
        self._original_attributes = {}
        utils.set_creation_attrs(self, **kwargs)

        # Used to know if the object was changed since the last request
        self.__modified = False

        self.path = self.object_uri.format(
            script=parent_nae_script.name, name=name
        )
        self.base_uri = self.collection_uri.format(
            script=parent_nae_script.name
        )

    @property
    def name(self):
        return self.__name

    @property
    def nae_script(self):
        return self.__parent_nae_script

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a NAE Agent and fill the
            object with the incoming attributes. The parameters are keyed by
            name and the VRF is given by its name.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        selector = selector or self.session.api.default_selector

        data = self._get_data(depth, selector)

        if isinstance(data.get("parameters_values"), dict):
            data["parameters_values"] = self._params_by_name(
                data["parameters_values"]
            )
        encrypted = data.pop("encrypted_parameters_values", None) or {}
        self.encrypted_parameters_names = sorted(
            self._params_by_name(encrypted)
        )
        if "vrf" in data:
            data["vrf"] = self._vrf_name(data["vrf"])

        utils.create_attrs(self, data)

        if selector in self.session.api.configurable_selectors:
            # The VRF can only be set when the agent is created
            utils.set_config_attrs(self, data, "config_attrs", ["vrf"])
            data.pop("vrf", None)

        self._original_attributes = data

        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session, script_name):
        """
        Perform a GET call to retrieve all NAE Agents of a NAE Script and
            create a dictionary containing them.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param script_name: Name of the NAE Script running the agents.
        :return: Dictionary containing NAE Agent names as keys and a NAE
            Agent object as value.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        data = get_json(session, cls.collection_uri.format(script=script_name))

        agent_dict = {}
        for uri in session.api.get_uri_from_data(data):
            name, agent = cls.from_uri(session, uri)
            agent_dict[name] = agent

        return agent_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing NAE Agent.
            Checks whether the NAE Agent exists in the switch and calls
            self.update() or self.create() accordingly.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing NAE Agent. The
            switch replaces all the parameter values with parameters_values:
            parameters missing from it get back their default value. The
            encrypted parameters are only changed when
            encrypted_parameters_values is set.

        :return: True if the object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        for key in ("name", "vrf", "encrypted_parameters_values"):
            data.pop(key, None)
        if data.get("parameters_values") is not None:
            data["parameters_values"] = self._stringify(
                data["parameters_values"]
            )
        encrypted = getattr(self, "encrypted_parameters_values", None)
        if encrypted:
            data["encrypted_parameters_values"] = self._stringify(encrypted)
        self.__modified = self._put_data(data)
        logging.info("SUCCESS: Updating %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new NAE Agent in the switch.

        :return: True if the object was modified.
        """
        data = utils.get_attrs(self, self.config_attrs)
        data = {key: value for key, value in data.items() if value is not None}
        data["name"] = self.name
        for key in ("parameters_values", "encrypted_parameters_values"):
            if key in data:
                data[key] = self._stringify(data[key])
        if "vrf" in data:
            data["vrf"] = self._vrf_name(data["vrf"])
        self.__modified = self._post_data(data)
        logging.info("SUCCESS: Adding %s", self)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to remove a NAE Agent from the switch.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        logging.info("SUCCESS: Deleting %s", self)
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.connected
    def enable(self):
        """
        Enable the NAE Agent, with a PATCH request that only changes the
            disabled attribute.

        :return: True if the agent was disabled and is now enabled.
        """
        return self._set_disabled(False)

    @PyaoscxModule.connected
    def disable(self):
        """
        Disable the NAE Agent, with a PATCH request that only changes the
            disabled attribute.

        :return: True if the agent was enabled and is now disabled.
        """
        return self._set_disabled(True)

    def _set_disabled(self, disabled):
        current = get_json(
            self.session, self.path, params={"attributes": "disabled"}
        ).get("disabled")
        if bool(current) == disabled:
            return False
        self._send_data(self.path, {"disabled": disabled}, "PATCH", "Update")
        self.disabled = disabled
        if "disabled" in self._original_attributes:
            self._original_attributes["disabled"] = disabled
        return True

    @PyaoscxModule.connected
    def get_status(self):
        """
        Retrieve the status and alert information of the NAE Agent.

        :return: Dictionary with the agent state, alert_level (CRITICAL,
            MAJOR, MINOR or NORMAL), alert_description, alerts_count,
            error_description and counters.
        """
        data = get_json(
            self.session,
            self.path,
            params={"attributes": ",".join(self.status_attributes)},
        )
        return self._format_status(self.name, self.nae_script.name, data)

    @PyaoscxModule.connected
    def get_conditions(self, include_events=True):
        """
        Retrieve the rules and conditions of the NAE Agent with the number of
            times each condition was met and, optionally, the condition events
            not yet processed by the agent.

        :param include_events: Whether to retrieve the condition events.
        :return: List of dictionaries, one per condition.
        """
        rules_uri = "{0}/nae_rules".format(self.path)
        rules = get_json(self.session, rules_uri, params={"depth": 2})
        conditions = []
        for rule_name in sorted(rules):
            rule = rules[rule_name]
            conditions_uri = "{0}/{1}/nae_conditions".format(
                rules_uri, rule_name
            )
            rule_conditions = get_json(
                self.session, conditions_uri, params={"depth": 2}
            )
            for condition_type in sorted(rule_conditions):
                condition = rule_conditions[condition_type]
                entry = {
                    "rule": rule_name,
                    "rule_description": rule.get("description"),
                    "active_condition_triggered": rule.get(
                        "active_condition_triggered"
                    ),
                    "condition_type": condition_type,
                    "type": condition.get("type"),
                    "expression": condition.get("expression"),
                    "count": condition.get("count") or 0,
                }
                if include_events:
                    entry["events"] = self._get_condition_events(
                        "{0}/{1}/nae_condition_events".format(
                            conditions_uri, condition_type
                        )
                    )
                conditions.append(entry)
        return conditions

    def _get_condition_events(self, uri):
        events = get_json(self.session, uri, params={"depth": 2})
        return [
            {
                "name": name,
                "status": event.get("status"),
                "event": event.get("event") or {},
                "processed_actions_count": event.get(
                    "processed_actions_count"
                ),
                "uri_resources": event.get("uri_resources") or [],
            }
            for name, event in sorted(events.items())
        ]

    @classmethod
    def get_facts(cls, session, script_name=None):
        """
        Retrieve the status and alert information of all the NAE Agents, or
            of the agents of a NAE Script, with a single request.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param script_name: Optional name of a NAE Script.
        :return: Dictionary containing the agent name as key and its status,
            as returned by get_status(), as value.
        """
        logging.info("Retrieving NAE Agents facts")

        data = get_json(
            session,
            cls.collection_uri.format(script=script_name or "*"),
            params={
                "depth": 2,
                "attributes": ",".join(cls.status_attributes),
            },
        )
        if script_name:
            data = {script_name: data}

        facts = {}
        for script, agents in data.items():
            for name, agent in (agents or {}).items():
                facts[name] = cls._format_status(name, script, agent)
        return facts

    @classmethod
    def get_aggregated_alert_level(cls, session):
        """
        Retrieve the highest alert level of all the NAE Agents.

        :param cls: Class reference.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :return: CRITICAL, MAJOR or MINOR, or NORMAL when no agent has an
            alert.
        """
        data = get_json(
            session,
            "system",
            params={"attributes": "nae_aggregated_alert_level"},
        )
        return data.get("nae_aggregated_alert_level") or "NORMAL"

    @classmethod
    def _format_status(cls, name, script_name, data):
        alert = data.get("alert_info") or {}
        status = data.get("status") or {}
        return {
            "name": name,
            "script": script_name,
            "origin": data.get("origin"),
            "disabled": data.get("disabled"),
            "vrf": cls._vrf_name(data.get("vrf")),
            "state": status.get("state"),
            "alert_level": (
                alert.get("alert_level")
                or status.get("alert_level")
                or "NORMAL"
            ),
            "alert_description": alert.get("alert_description"),
            "alert_level_updated_at": (
                alert.get("alert_level_updated_at")
                or status.get("alert_level_updated_at")
            ),
            "alerts_count": data.get("nae_alerts_count") or 0,
            "rules_count": data.get("nae_rules_count") or 0,
            "time_series_count": data.get("nae_time_series_count") or 0,
            "error_description": status.get("error_description") or None,
            "error_at": status.get("error_at") or None,
            "executed_at": status.get("executed_at"),
            "last_activity_at": status.get("last_activity_at"),
            "statistics": data.get("statistics") or {},
        }

    @staticmethod
    def _params_by_name(values):
        return {name_from_uri(key): value for key, value in values.items()}

    @staticmethod
    def _stringify(values):
        # The switch stores every parameter value as a string
        return {
            key: value if isinstance(value, str) else str(value)
            for key, value in values.items()
        }

    @staticmethod
    def _vrf_name(vrf):
        if vrf is None:
            return None
        if hasattr(vrf, "name"):
            return vrf.name
        if isinstance(vrf, dict):
            return next(iter(vrf), None)
        return name_from_uri(vrf)

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a NAE Agent object given an URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a string with the URI.
        :return: tuple with the name and the NAE Agent.
        """
        # URI format is: /system/nae_scripts/{script}/nae_agents/{name}
        parts = uri.rstrip("/").split("/")
        name = parts[-1]
        script = NaeScript(session, parts[-3])
        return name, cls(session, name, script)

    def __str__(self):
        return "NAE Agent {0} of NAE Script {1}".format(
            self.name, self.nae_script.name
        )

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        return self.modified
