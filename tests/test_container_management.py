"""Offline regression tests for container management and deployment."""

import copy
import contextlib
import io
import json
import runpy
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from requests.exceptions import ConnectionError, ReadTimeout

from pyaoscx.container import Container, STATUS_REQUEST_TIMEOUT
from pyaoscx.container_isolated_network import ContainerIsolatedNetwork
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.pyaoscx_factory import PyaoscxFactory
from pyaoscx.session import Session


PREFIX = "/rest/v10.19/"
CONTAINER = {
    "name": "review-container",
    "image_location": "https://example.com/image.tar",
    "image_download_vrf": {"mgmt": PREFIX + "system/vrfs/mgmt"},
    "container_isolated_network": {
        "net10": PREFIX + "system/container_isolated_networks/net10"
    },
    "enable": True,
    "allow_unsigned_image": False,
    "environment_variables": {"RUN_MODE": "responder"},
}
NETWORK = {
    "name": "net10",
    "default_gateway": "192.0.2.1",
    "virtual_interfaces": {
        PREFIX + "system/vlans/10": {
            "ipv4_address": "192.0.2.20/24",
            "ipv6_address": "2001:db8::20/64",
        }
    },
}


def response(data, status=200):
    """Build a mock REST response without a live switch."""
    return Mock(status_code=status, text=json.dumps(data))


def connected_session(data):
    """Return a real Session with its network boundary mocked."""
    session = Session("192.0.2.10", "10.19", login_api="10.09")
    session.connected = True
    session.request = Mock(return_value=response(data))
    return session


def factory_for(session):
    """Isolate tests from the factory's legacy process-wide singleton."""
    factory = object.__new__(PyaoscxFactory)
    factory.session = session
    return factory


class ContainerTests(unittest.TestCase):
    """Check container reference preservation across read-modify-write."""

    def test_unbound_references_are_preserved(self):
        """Empty and null references must not trigger a reconfiguration."""
        for empty_reference in ({}, None):
            with self.subTest(reference=empty_reference):
                data = copy.deepcopy(CONTAINER)
                data["container_isolated_network"] = empty_reference
                data["image_download_vrf"] = empty_reference
                session = connected_session(data)
                container = Container(session, "review-container")
                container.get()
                self.assertFalse(container.apply())
                session.request.assert_called_once()
                container.enable = False
                session.request.return_value = response({}, 204)
                self.assertTrue(container.apply())
                payload = json.loads(session.request.call_args.kwargs["data"])
                self.assertEqual(
                    payload["image_download_vrf"], empty_reference
                )
                self.assertEqual(
                    payload["container_isolated_network"], empty_reference
                )

    def test_read_then_apply_does_not_write(self):
        """An unchanged object must not send a PUT."""
        for reference_form in ("mapping", "uri"):
            with self.subTest(reference_form=reference_form):
                data = copy.deepcopy(CONTAINER)
                if reference_form == "uri":
                    for field in (
                        "image_download_vrf", "container_isolated_network"
                    ):
                        data[field] = next(iter(data[field].values()))
                session = connected_session(data)
                container = Container(session, "review-container")
                container.get()
                self.assertEqual(container.vrf, "mgmt")
                self.assertEqual(container.isolated_network, "net10")
                self.assertFalse(container.apply())
                session.request.assert_called_once()

    def test_enable_update_preserves_references(self):
        """Changing enable must preserve VRF, network, and environment."""
        session = connected_session(CONTAINER)
        container = Container(session, "review-container")
        container.get()
        session.request.return_value = response({}, 204)
        container.enable = False
        self.assertTrue(container.apply())
        payload = json.loads(session.request.call_args.kwargs["data"])
        self.assertEqual(
            payload["image_download_vrf"], PREFIX + "system/vrfs/mgmt"
        )
        self.assertEqual(
            payload["container_isolated_network"],
            PREFIX + "system/container_isolated_networks/net10",
        )
        self.assertEqual(
            payload["environment_variables"],
            CONTAINER["environment_variables"],
        )
        self.assertFalse(payload["enable"])
        self.assertFalse(container.apply())
        self.assertEqual(session.request.call_count, 2)


class NetworkTests(unittest.TestCase):
    """Check partial network updates preserve other configuration."""

    def test_read_then_apply_does_not_write(self):
        """Both supported VLAN key forms round-trip without a PUT."""
        for key in (PREFIX + "system/vlans/10", "10"):
            with self.subTest(key=key):
                data = copy.deepcopy(NETWORK)
                attributes = next(iter(data["virtual_interfaces"].values()))
                data["virtual_interfaces"] = {key: attributes}
                session = connected_session(data)
                network = ContainerIsolatedNetwork(session, "net10")
                network.get()
                self.assertEqual(network.vlan, 10)
                self.assertEqual(network.ipv4_address, "192.0.2.20/24")
                self.assertFalse(network.apply())
                session.request.assert_called_once()

    def test_ip_only_and_vlan_only_updates(self):
        """Factory updates change only the specified network field."""
        for settings in (
            {"ipv4_address": "192.0.2.30/24"}, {"vlan_id": 20}
        ):
            with self.subTest(settings=settings):
                session = connected_session(NETWORK)
                session.request.side_effect = [
                    response(NETWORK), response({}, 204)
                ]
                network = factory_for(session).container_isolated_network(
                    "net10", **settings
                )
                payload = json.loads(session.request.call_args.kwargs["data"])
                vlan_id = settings.get("vlan_id", 10)
                interface = payload["virtual_interfaces"][
                    PREFIX + "system/vlans/" + str(vlan_id)
                ]
                self.assertEqual(
                    interface["ipv4_address"],
                    settings.get("ipv4_address", "192.0.2.20/24"),
                )
                self.assertEqual(interface["ipv6_address"], "2001:db8::20/64")
                self.assertEqual(payload["default_gateway"], "192.0.2.1")
                self.assertEqual(len(payload["virtual_interfaces"]), 1)
                self.assertFalse(network.apply())

    def test_ambiguous_ip_only_update_is_rejected(self):
        """Multiple interfaces require an explicit VLAN selection."""
        data = copy.deepcopy(NETWORK)
        data["virtual_interfaces"][PREFIX + "system/vlans/20"] = {
            "ipv4_address": "198.51.100.20/24"
        }
        session = connected_session(data)
        network = ContainerIsolatedNetwork(session, "net10")
        network.get()
        self.assertFalse(network.apply())
        network.ipv4_address = "192.0.2.30/24"
        with self.assertRaises(ParameterError):
            network.apply()
        session.request.assert_called_once()


class FactoryTests(unittest.TestCase):
    """Check explicit settings and error handling during reconciliation."""

    def test_resource_object_keeps_its_session(self):
        """A supplied network is not deep-copied along with its session."""
        session = connected_session(CONTAINER)
        network = ContainerIsolatedNetwork(session, "net10")
        container = factory_for(session).container(
            "review-container", isolated_network_name=network
        )
        self.assertIs(container.isolated_network, network)
        self.assertIs(container.isolated_network.session, session)
        session.request.assert_called_once()

    def test_omitted_container_settings_are_preserved(self):
        """Retrieving an enabled container must not stop or reconfigure it."""
        session = connected_session(CONTAINER)
        container = factory_for(session).container("review-container")
        self.assertTrue(container.enable)
        self.assertEqual(container.vrf, "mgmt")
        self.assertFalse(container.modified)
        session.request.assert_called_once()

    def test_explicit_container_settings_are_applied(self):
        """An explicit boolean, reference, or image survives the GET."""
        for allow_unsigned in (False, True):
            with self.subTest(allow_unsigned=allow_unsigned):
                data = copy.deepcopy(CONTAINER)
                data["allow_unsigned_image"] = not allow_unsigned
                session = connected_session(data)
                session.request.side_effect = [
                    response(data), response({}, 204)
                ]
                factory_for(session).container(
                    "review-container", vrf="default", enable=False,
                    allow_unsigned_image=allow_unsigned,
                    isolated_network_name="net20",
                    image_location="https://example.com/new.tar",
                )
                payload = json.loads(session.request.call_args.kwargs["data"])
                self.assertEqual(
                    payload["allow_unsigned_image"], allow_unsigned
                )
                self.assertFalse(payload["enable"])
                self.assertEqual(
                    payload["image_download_vrf"],
                    PREFIX + "system/vrfs/default",
                )
                self.assertEqual(
                    payload["container_isolated_network"],
                    PREFIX + "system/container_isolated_networks/net20",
                )
                self.assertEqual(
                    payload["image_location"], "https://example.com/new.tar"
                )

    def test_only_get_404_allows_creation(self):
        """Permission and server errors must never trigger a POST."""
        for method in ("container", "container_isolated_network"):
            for status in (401, 403, 409, 500):
                with self.subTest(method=method, status=status):
                    session = connected_session({})
                    session.request.return_value = response({}, status)
                    with self.assertRaises(GenericOperationError) as error:
                        getattr(factory_for(session), method)("resource")
                    self.assertEqual(error.exception.response_code, status)
                    session.request.assert_called_once()

    def test_creation_keeps_defaults_and_explicit_settings(self):
        """A missing resource is created exactly once and read back."""
        for method, data, settings in (
            ("container", CONTAINER, {}),
            ("container", CONTAINER, {
                "enable": True, "allow_unsigned_image": True, "vrf": "mgmt"
            }),
            ("container_isolated_network", NETWORK, {
                "vlan_id": 10, "ipv4_address": "192.0.2.20/24"
            }),
        ):
            with self.subTest(method=method, settings=settings):
                session = connected_session(data)
                session.request.side_effect = [
                    response({}, 404), response({}, 201), response(data)
                ]
                getattr(factory_for(session), method)(data["name"], **settings)
                calls = session.request.call_args_list
                self.assertEqual(
                    [call.args[0] for call in calls], ["GET", "POST", "GET"]
                )
                payload = json.loads(calls[1].kwargs["data"])
                if method == "container":
                    self.assertEqual(
                        payload["enable"], settings.get("enable", False)
                    )
                    self.assertEqual(
                        payload["allow_unsigned_image"],
                        settings.get("allow_unsigned_image", False),
                    )
                    self.assertEqual(
                        payload["image_download_vrf"],
                        PREFIX + "system/vrfs/"
                        + settings.get("vrf", "default"),
                    )
                else:
                    self.assertEqual(
                        payload["virtual_interfaces"], {
                            PREFIX + "system/vlans/10": {
                                "ipv4_address": "192.0.2.20/24"
                            }
                        },
                    )

    def test_update_failure_is_not_retried(self):
        """Neither factory repeats a failed PUT, including a 404."""
        for method, data, settings in (
            ("container", CONTAINER, {"enable": False}),
            ("container_isolated_network", NETWORK, {
                "ipv4_address": "192.0.2.30/24"
            }),
        ):
            for status in (400, 403, 404, 500):
                with self.subTest(method=method, status=status):
                    session = connected_session(data)
                    session.request.side_effect = [
                        response(data), response({}, status)
                    ]
                    with self.assertRaises(GenericOperationError) as error:
                        getattr(factory_for(session), method)(
                            data["name"], **settings
                        )
                    self.assertEqual(error.exception.response_code, status)
                    self.assertEqual(
                        [
                            call.args[0]
                            for call in session.request.call_args_list
                        ],
                        ["GET", "PUT"],
                    )


class Clock:
    """Simulate elapsed time without sleeping during regression tests."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        """Return simulated monotonic time."""
        return self.now

    def sleep(self, duration):
        """Record a polling delay and advance simulated time."""
        self.sleeps.append(duration)
        self.now += duration


class PollingTests(unittest.TestCase):
    """Check deadlines, diagnostics, and HTTP request timeout forwarding."""

    def setUp(self):
        """Create an offline container and patch only its polling clock."""
        self.session = connected_session({})
        self.container = Container(self.session, "review-container")
        self.clock = Clock()
        patcher = patch("pyaoscx.container.time", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_reason_changes_are_reported(self):
        """Reason-only changes reach callbacks and the timeout result."""
        callbacks = []
        with patch.object(self.container, "get_status", side_effect=[
            ("container_acquiring", "fetching"),
            ("container_acquiring", "unpacking"),
        ]) as status:
            result = self.container.wait_until_operational(
                timeout=2, interval=1,
                callback=lambda *values: callbacks.append(values),
            )
        self.assertEqual(result, (False, "container_acquiring", "unpacking"))
        self.assertEqual(callbacks, [
            ("container_acquiring", "fetching"),
            ("container_acquiring", "unpacking"),
        ])
        self.assertEqual(
            [call.kwargs["timeout"] for call in status.call_args_list], [2, 1]
        )

    def test_unchanged_status_does_not_repeat_callback(self):
        """Identical status and reason produce only one notification."""
        callback = Mock()
        with patch.object(self.container, "get_status", return_value=(
            "container_acquiring", "fetching"
        )):
            self.container.wait_until_operational(
                timeout=2, interval=1, callback=callback
            )
        callback.assert_called_once_with("container_acquiring", "fetching")

    def test_terminal_statuses_do_not_sleep(self):
        """Success and terminal failures return without another poll."""
        for state, success in (
            ("operational", True), ("run_failed", False),
            ("network_provision_failed", False), ("error", False),
        ):
            with self.subTest(state=state):
                with patch.object(self.container, "get_status", return_value=(
                    state, "detail"
                )):
                    self.assertEqual(
                        self.container.wait_until_operational(),
                        (success, state, "detail"),
                    )
        self.assertEqual(self.clock.sleeps, [])

    def test_late_success_is_rejected(self):
        """Responses arriving after the deadline cannot report success."""
        def delayed_status(timeout):
            self.assertEqual(timeout, 1)
            self.clock.now += 30
            return "operational", ""

        with patch.object(self.container, "get_status", delayed_status):
            self.assertEqual(
                self.container.wait_until_operational(timeout=1),
                (False, "operational", ""),
            )

    def test_sleep_does_not_exceed_remaining_budget(self):
        """A long interval is capped by the remaining deadline."""
        with patch.object(self.container, "get_status", return_value=(
            "container_acquiring", "fetching"
        )):
            self.container.wait_until_operational(timeout=0.5, interval=5)
        self.assertEqual(self.clock.sleeps, [0.5])

    def test_read_timeout_returns_failure(self):
        """Use the real Session and module path to test timeout propagation."""
        del self.session.request
        self.session.s = Mock()
        self.session.s.get.side_effect = ReadTimeout(
            "status request timed out"
        )
        result = self.container.wait_until_operational(timeout=3)
        self.assertFalse(result[0])
        self.assertIn("status request timed out", result[2])
        self.assertEqual(self.session.s.get.call_args.kwargs["timeout"], 3)
        self.assertEqual(self.clock.sleeps, [])

    def test_non_timeout_transport_error_propagates(self):
        """Other transport failures are not reported as polling expiry."""
        self.session.request.side_effect = ConnectionError("connection lost")
        with self.assertRaises(ResponseError) as error:
            self.container.wait_until_operational(timeout=3)
        self.assertIsInstance(error.exception.__cause__, ConnectionError)

    def test_default_status_request_is_bounded(self):
        """A standalone status call also carries a finite HTTP timeout."""
        self.session.request.return_value = response({"status": "operational"})
        self.assertEqual(self.container.get_status(), ("operational", ""))
        self.assertEqual(
            self.session.request.call_args.kwargs["timeout"],
            STATUS_REQUEST_TIMEOUT,
        )

    def test_long_poll_budget_caps_each_request(self):
        """A large startup budget does not allow a single unbounded request."""
        with patch.object(self.container, "get_status", return_value=(
            "operational", ""
        )) as status:
            self.container.wait_until_operational(timeout=300)
        status.assert_called_once_with(timeout=STATUS_REQUEST_TIMEOUT)

    def test_invalid_polling_arguments(self):
        """Invalid budgets and intervals fail before any REST request."""
        for settings in (
            {"timeout": -1}, {"timeout": float("inf")},
            {"timeout": float("nan")}, {"interval": 0},
            {"interval": -1}, {"interval": float("inf")},
        ):
            with self.subTest(settings=settings):
                with self.assertRaises(ParameterError):
                    self.container.wait_until_operational(**settings)
        self.assertEqual(
            self.container.wait_until_operational(timeout=0),
            (False, None, None),
        )
        self.session.request.assert_not_called()


class SessionTests(unittest.TestCase):
    """Check the optional timeout leaves existing callers unchanged."""

    def test_request_timeout_is_opt_in(self):
        """Legacy calls omit timeout; opted-in calls forward it unchanged."""
        session = Session("192.0.2.10", "10.09")
        session.s = Mock()
        for verb in ("GET", "POST", "PUT", "DELETE"):
            with self.subTest(verb=verb):
                transport = getattr(session.s, verb.lower())
                session.request(verb, "system")
                self.assertNotIn("timeout", transport.call_args.kwargs)
                session.request(verb, "system", timeout=2.5)
                self.assertEqual(transport.call_args.kwargs["timeout"], 2.5)

    def test_normal_resource_get_keeps_legacy_request_signature(self):
        """Adding timeout support does not change ordinary module requests."""
        session = connected_session(CONTAINER)
        Container(session, "review-container").get()
        self.assertNotIn("timeout", session.request.call_args.kwargs)


class WorkflowTests(unittest.TestCase):
    """Run the example's entry point with all hardware operations mocked."""

    def run_workflow(self, failure=None, startup=(True, "operational", "")):
        """Return the example's process exit status after mock deployment."""
        script = (
            Path(__file__).resolve().parents[1]
            / "workflows" / "deploy_container.py"
        )
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            session = stack.enter_context(patch("pyaoscx.session.Session"))
            vlan = stack.enter_context(patch("pyaoscx.vlan.Vlan"))
            stack.enter_context(patch(
                "pyaoscx.container_isolated_network.ContainerIsolatedNetwork"
            ))
            container = stack.enter_context(
                patch("pyaoscx.container.Container")
            )
            vlan.return_value.apply.side_effect = failure
            container.return_value.wait_until_operational.return_value = (
                startup
            )
            container.get_all.return_value = {}
            with self.assertRaises(SystemExit) as exit_status:
                runpy.run_path(str(script), run_name="__main__")
            session.return_value.close.assert_called_once()
            return exit_status.exception.code

    def test_deployment_error_exits_nonzero(self):
        """A failed REST operation is visible to shell automation."""
        self.assertEqual(
            self.run_workflow(failure=GenericOperationError("conflict", 409)),
            1,
        )

    def test_startup_failure_exits_nonzero(self):
        """A container startup failure is visible to shell automation."""
        self.assertEqual(
            self.run_workflow(startup=(False, "run_failed", "failed")), 1
        )

    def test_success_exits_zero(self):
        """A successful deployment still returns zero and logs out."""
        self.assertEqual(self.run_workflow(), 0)


if __name__ == "__main__":
    unittest.main()
