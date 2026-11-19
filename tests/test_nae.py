# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for the NAE modules: NaeScript, NaeAgent, NaeLiteAgent
and NaeLiteCondition.

These tests do not require a live switch. A fake session records the
requests and answers with the data formats returned by an AOS-CX switch
(REST v10.09, FL.10.19).
"""

import base64
import hashlib
import json

from types import SimpleNamespace

import pytest

from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.nae_agent import NaeAgent
from pyaoscx.nae_lite_agent import NaeLiteAgent
from pyaoscx.nae_lite_condition import NaeLiteCondition
from pyaoscx.nae_script import NaeScript

PREFIX = "/rest/v10.09/"


class FakeSession(object):
    """Session answering GET requests from a dictionary of paths."""

    def __init__(self, routes=None):
        self.connected = True
        self.routes = routes or {}
        self.calls = []
        self.api = SimpleNamespace(
            default_selector="writable",
            default_depth=1,
            default_facts_depth=2,
            valid_selectors=["configuration", "status", "writable"],
            configurable_selectors=["writable"],
            valid_depth=lambda depth: True,
            get_uri_from_data=lambda data: list(data.values()),
        )

    def request(self, operation, path, params=None, data=None, **kwargs):
        self.calls.append(
            (operation, path, params, json.loads(data) if data else None)
        )
        if operation == "GET":
            body = self.routes[path]
            if callable(body):
                body = body()
            return SimpleNamespace(status_code=200, text=json.dumps(body))
        codes = {"POST": 201, "PUT": 200, "PATCH": 204, "DELETE": 204}
        return SimpleNamespace(status_code=codes[operation], text="")

    def writes(self):
        return [call for call in self.calls if call[0] != "GET"]


SCRIPT_PATH = "system/nae_scripts/qa_script"
AGENT_PATH = SCRIPT_PATH + "/nae_agents/qa_agent"
LITE_PATH = "system/nae_script_generates/qa_lite"


# --------------------------------------------------------------------------
# NaeScript
# --------------------------------------------------------------------------
def test_script_create_body_encodes_the_source():
    session = FakeSession(
        {SCRIPT_PATH: {"script": "eA==", "expert_only": False}}
    )
    script = NaeScript(session, "qa_script")
    script.set_script_code("Manifest = {}\n")

    assert script.create() is True

    _, path, _, body = session.writes()[0]
    assert path == "system/nae_scripts"
    assert body == {
        "name": "qa_script",
        "script": base64.b64encode(b"Manifest = {}\n").decode(),
    }


def test_script_set_script_base64_normalizes_and_validates():
    script = NaeScript(FakeSession(), "qa_script")
    encoded = base64.b64encode(b"Manifest = {}\n").decode()
    # Line breaks added by tools wrapping Base64 lines are ignored
    script.set_script_base64(encoded[:8] + "\n" + encoded[8:] + "\n")

    assert script.script == encoded
    assert "script" in script.config_attrs
    for invalid in ("not base64!", "", "QUJD="):
        with pytest.raises(ParameterError):
            script.set_script_base64(invalid)


def test_script_get_script_code_and_idempotent_update():
    encoded = base64.b64encode(b"print(1)\n").decode()
    session = FakeSession(
        {
            SCRIPT_PATH: {
                "expert_only": False,
                "nae_agents": PREFIX + SCRIPT_PATH + "/nae_agents",
                "script": encoded,
            }
        }
    )
    script = NaeScript(session, "qa_script")
    script.get()

    assert script.get_script_code() == "print(1)\n"
    assert sorted(script.config_attrs) == ["expert_only", "script"]
    # Same content: no request
    script.set_script_code(b"print(1)\n")
    assert script.update() is False
    # New content: PUT without the name
    script.set_script_code("print(2)\n")
    assert script.update() is True
    method, path, _, body = session.writes()[-1]
    assert (method, path) == ("PUT", SCRIPT_PATH)
    assert body == {
        "expert_only": False,
        "script": base64.b64encode(b"print(2)\n").decode(),
    }


def test_script_wait_ignores_the_status_of_the_previous_content():
    new_code = b"print(2)\n"
    old = {"state": "VALIDATED", "script_checksum": "0" * 128}
    states = iter(
        [
            old,
            {"state": "VALIDATING", "script_checksum": "0" * 128},
            {
                "state": "VALIDATED",
                "script_checksum": hashlib.sha512(new_code).hexdigest(),
            },
        ]
    )
    session = FakeSession(
        {SCRIPT_PATH: lambda: {"status": dict(next(states))}}
    )
    script = NaeScript(session, "qa_script")
    script.set_script_code(new_code)

    status = script.wait_for_validation(timeout=5, interval=0)

    assert status["state"] == "VALIDATED"
    assert status["script_checksum"] == hashlib.sha512(new_code).hexdigest()


def test_script_update_revalidates_the_last_valid_content():
    valid = b"print(1)\n"
    checksum = hashlib.sha512(valid).hexdigest()
    variant_checksum = hashlib.sha512(valid + b"\n").hexdigest()
    # Stuck in ERROR after an invalid upload, with the checksum of the last
    # valid content (read by get() and update()), then the variant validated
    stuck = {"state": "ERROR", "script_checksum": checksum}
    statuses = iter(
        [
            stuck,
            stuck,
            {"state": "VALIDATING", "script_checksum": checksum},
            {"state": "VALIDATED", "script_checksum": variant_checksum},
        ]
    )
    session = FakeSession(
        {
            SCRIPT_PATH: lambda: {
                "expert_only": False,
                "script": base64.b64encode(b"invalid").decode(),
                "status": next(statuses),
            }
        }
    )
    script = NaeScript(session, "qa_script")
    script.get()
    script.set_script_code(valid)

    assert script.update() is True

    puts = [call[3]["script"] for call in session.writes()]
    assert puts == [
        base64.b64encode(valid + b"\n").decode(),
        base64.b64encode(valid).decode(),
    ]


def test_script_facts_drop_the_content():
    session = FakeSession(
        {
            "system/nae_scripts": {
                "qa_script": {
                    "name": "qa_script",
                    "origin": "user",
                    "version": "1.0",
                    "status": {"state": "VALIDATED", "error_at": 0},
                }
            }
        }
    )
    facts = NaeScript.get_facts(session)
    assert facts["qa_script"]["state"] == "VALIDATED"
    assert facts["qa_script"]["error_at"] is None
    assert "script" not in facts["qa_script"]
    params = session.calls[0][2]
    assert "script" not in params["attributes"].split(",")


# --------------------------------------------------------------------------
# NaeAgent
# --------------------------------------------------------------------------
AGENT_WRITABLE = {
    "disabled": False,
    "encrypted_parameters_values": {
        PREFIX + SCRIPT_PATH + "/nae_parameters/secret": "AQBapb4T=="
    },
    "parameters_values": {
        PREFIX + SCRIPT_PATH + "/nae_parameters/threshold": "5",
        PREFIX + SCRIPT_PATH + "/nae_parameters/label": "lab",
    },
    "vrf": {"default": PREFIX + "system/vrfs/default"},
}


def test_agent_get_normalizes_names_and_hides_encrypted_values():
    session = FakeSession({AGENT_PATH: AGENT_WRITABLE})
    agent = NaeAgent(session, "qa_agent", "qa_script")
    agent.get()

    assert agent.path == AGENT_PATH
    assert agent.parameters_values == {"threshold": "5", "label": "lab"}
    assert agent.vrf == "default"
    assert agent.encrypted_parameters_names == ["secret"]
    assert not hasattr(agent, "encrypted_parameters_values")
    assert sorted(agent.config_attrs) == ["disabled", "parameters_values"]


def test_agent_update_sends_all_parameters_without_vrf():
    session = FakeSession({AGENT_PATH: AGENT_WRITABLE})
    agent = NaeAgent(session, "qa_agent", "qa_script")
    agent.get()

    assert agent.update() is False

    agent.parameters_values["threshold"] = 10
    assert agent.update() is True
    method, path, _, body = session.writes()[-1]
    assert (method, path) == ("PUT", AGENT_PATH)
    # The switch replaces the whole map: all values are sent, as strings
    assert body == {
        "disabled": False,
        "parameters_values": {"threshold": "10", "label": "lab"},
    }


def test_agent_update_sends_encrypted_values_only_when_set():
    session = FakeSession({AGENT_PATH: AGENT_WRITABLE})
    agent = NaeAgent(session, "qa_agent", "qa_script")
    agent.get()
    agent.encrypted_parameters_values = {"secret": "s3cr3t"}

    assert agent.update() is True
    body = session.writes()[-1][3]
    assert body["encrypted_parameters_values"] == {"secret": "s3cr3t"}
    assert agent.update() is False


def test_agent_create_body():
    session = FakeSession({AGENT_PATH: AGENT_WRITABLE})
    agent = NaeAgent(
        session,
        "qa_agent",
        NaeScript(session, "qa_script"),
        parameters_values={"threshold": 0},
        vrf=SimpleNamespace(name="mgmt"),
        disabled=None,
    )
    agent.create()
    method, path, _, body = session.writes()[0]
    assert (method, path) == ("POST", SCRIPT_PATH + "/nae_agents")
    assert body == {
        "name": "qa_agent",
        "parameters_values": {"threshold": "0"},
        "vrf": "mgmt",
    }


def test_agent_disable_patches_only_when_needed():
    session = FakeSession({AGENT_PATH: {"disabled": False}})
    agent = NaeAgent(session, "qa_agent", "qa_script")

    assert agent.disable() is True
    assert session.writes()[-1][::3] == ("PATCH", {"disabled": True})
    assert agent.enable() is False


def test_agent_status_and_facts():
    status = {
        "alert_info": {
            "alert_description": "critical - QA",
            "alert_level": "CRITICAL",
            "alert_level_updated_at": 1795105680,
        },
        "nae_alerts_count": 1,
        "status": {"error_at": 0, "error_description": "", "executed_at": 9},
        "vrf": {"default": PREFIX + "system/vrfs/default"},
    }
    idle = {"alert_info": {}, "nae_alerts_count": None, "status": {}}
    session = FakeSession(
        {
            "system/nae_scripts/*/nae_agents": {
                "qa_script": {"qa_agent": status},
                "system_resource_monitor": {
                    "system_resource_monitor.default": idle
                },
            }
        }
    )
    facts = NaeAgent.get_facts(session)

    assert facts["qa_agent"]["script"] == "qa_script"
    assert facts["qa_agent"]["alert_level"] == "CRITICAL"
    assert facts["qa_agent"]["alerts_count"] == 1
    assert facts["qa_agent"]["vrf"] == "default"
    assert facts["qa_agent"]["error_description"] is None
    default = facts["system_resource_monitor.default"]
    assert default["alert_level"] == "NORMAL"
    assert default["alerts_count"] == 0


def test_agent_conditions_with_events():
    rules = AGENT_PATH + "/nae_rules"
    conditions = rules + "/qa_agent.rule_0/nae_conditions"
    session = FakeSession(
        {
            rules: {
                "qa_agent.rule_0": {
                    "description": "CPU above threshold",
                    "active_condition_triggered": True,
                }
            },
            conditions: {
                "ACTIVE_CONDITION": {
                    "type": "monitor_resource",
                    "expression": "{} >= {}",
                    "count": 3,
                },
                "CLEAR_CONDITION": {
                    "type": "monitor_resource",
                    "expression": "{} < {}",
                    "count": None,
                },
            },
            conditions
            + "/ACTIVE_CONDITION/nae_condition_events": {
                "event_1": {"status": "PENDING", "event": {"1": "95"}}
            },
            conditions + "/CLEAR_CONDITION/nae_condition_events": {},
        }
    )
    agent = NaeAgent(session, "qa_agent", "qa_script")
    result = agent.get_conditions()

    assert [c["condition_type"] for c in result] == [
        "ACTIVE_CONDITION",
        "CLEAR_CONDITION",
    ]
    assert result[0]["count"] == 3
    assert result[0]["active_condition_triggered"] is True
    assert result[0]["events"][0]["status"] == "PENDING"
    assert result[1]["count"] == 0
    assert result[1]["events"] == []


def test_agent_from_uri():
    name, agent = NaeAgent.from_uri(
        FakeSession(),
        PREFIX + "system/nae_scripts/srm/nae_agents/srm.default",
    )
    assert name == "srm.default"
    assert agent.nae_script.name == "srm"


# --------------------------------------------------------------------------
# NaeLiteAgent / NaeLiteCondition
# --------------------------------------------------------------------------
def make_lite_session(ready):
    state = {"ready": ready}
    session = FakeSession(
        {
            LITE_PATH: lambda: {"ready": state["ready"]},
            "system/nae_scripts/qa_lite/nae_agents/qa_lite": {
                "status": {"executed_at": 1}
            },
        }
    )
    return session


def test_lite_activate_regenerates_an_activated_agent():
    session = make_lite_session(ready=True)
    NaeLiteAgent(session, "qa_lite").activate()
    patches = [c[3] for c in session.writes() if c[0] == "PATCH"]
    assert patches == [{"ready": False}, {"ready": True}]


def test_lite_activate_a_new_agent():
    session = make_lite_session(ready=False)
    NaeLiteAgent(session, "qa_lite").activate()
    patches = [c[3] for c in session.writes() if c[0] == "PATCH"]
    assert patches == [{"ready": True}]


def test_lite_update_keeps_ready():
    session = FakeSession(
        {
            LITE_PATH: {
                "description": None,
                "disabled": False,
                "monitors": {"m_cpu": {"resource": "system cpu"}},
                "ready": True,
                "tags": [],
                "watches": {},
            }
        }
    )
    agent = NaeLiteAgent(session, "qa_lite")
    agent.get()
    agent.description = "changed"
    assert agent.update() is True
    # A PUT without "ready" deactivates the agent
    assert session.writes()[-1][3]["ready"] is True


def test_lite_wait_reports_agent_errors():
    session = FakeSession(
        {
            LITE_PATH: {"ready": True, "status": {"state": "AGENT_CREATED"}},
            "system/nae_scripts/qa_lite/nae_agents/qa_lite": {
                "status": {
                    "error_at": 5,
                    "error_description": "The NAE Agent has Python errors.",
                    "executed_at": 5,
                }
            },
        }
    )
    status = NaeLiteAgent(session, "qa_lite").wait_for_activation(timeout=0)
    assert status["state"] == "ERROR"
    assert "Python errors" in status["error_description"]


def test_lite_wait_waits_for_a_new_execution():
    executions = iter([1, 1, 2])
    agent_path = "system/nae_scripts/qa_lite/nae_agents/qa_lite"
    session = FakeSession(
        {
            LITE_PATH: {"ready": True, "status": {"state": "AGENT_CREATED"}},
            agent_path: lambda: {"status": {"executed_at": next(executions)}},
        }
    )
    agent = NaeLiteAgent(session, "qa_lite")
    agent.activate()
    status = agent.wait_for_activation(timeout=5, interval=0)
    assert status["agent"]["executed_at"] == 2


def test_lite_wait_ignores_the_error_of_the_previous_generation():
    agent_path = "system/nae_scripts/qa_lite/nae_agents/qa_lite"
    failed = {
        "status": {
            "error_at": 5,
            "error_description": "The NAE Agent has Python errors.",
            "executed_at": 5,
        }
    }
    fixed = {"status": {"executed_at": 9}}
    # activate() reads the failed agent, the first check still sees it
    agents = iter([failed, failed, fixed])
    session = FakeSession(
        {
            LITE_PATH: {
                "ready": True,
                "status": {"state": "AGENT_CREATED"},
            },
            agent_path: lambda: next(agents),
        }
    )
    agent = NaeLiteAgent(session, "qa_lite")
    agent.activate()
    status = agent.wait_for_activation(timeout=5, interval=0)

    assert status["state"] == "AGENT_CREATED"
    assert status["agent"]["executed_at"] == 9


def test_lite_condition_create_and_from_uri():
    session = FakeSession(
        {LITE_PATH + "/conditions/Default,active_condition": {}}
    )
    condition = NaeLiteCondition(
        session,
        "Default",
        "active_condition",
        "qa_lite",
        expression="gt 90",
        expression_type="monitor_resource",
        resource_name={"0": "m_cpu"},
        action_snmp=None,
    )
    assert condition.path == LITE_PATH + "/conditions/Default,active_condition"
    condition.create()
    _, path, _, body = session.writes()[0]
    assert path == LITE_PATH + "/conditions"
    assert body == {
        "rule_name": "Default",
        "condition_type": "active_condition",
        "expression": "gt 90",
        "expression_type": "monitor_resource",
        "resource_name": {"0": "m_cpu"},
    }

    index, parsed = NaeLiteCondition.from_uri(
        session, PREFIX + LITE_PATH + "/conditions/Default,clear_condition"
    )
    assert index == "Default,clear_condition"
    assert parsed.condition_type == "clear_condition"
    assert parsed.nae_lite_agent.name == "qa_lite"
