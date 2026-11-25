# (C) Copyright 2019-2023 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from copy import deepcopy

import logging
import json
from urllib.parse import quote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.unsupported_capability_error import (
    UnsupportedCapabilityError,
)
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_factory import PyaoscxFactory, Singleton
from pyaoscx.pyaoscx_module import PyaoscxModule


class Device(PyaoscxFactory, metaclass=Singleton):
    """
    Represents a Device and all of its attributes. Keeping all the important
        information inside one class.
    """

    base_uri = "system"

    def __init__(self, session):
        self.session = session
        self.firmware_version = None
        # Used to set attributes
        self.config_attrs = []
        self.materialized = False
        self.__original_attributes = {}
        # Set firmware version
        self.get_firmware_version()

    @PyaoscxModule.connected
    def get(self, selector=None):
        """
        Perform a GET call to retrieve device attributes. After data from
            response, Device class attributes are generated using
            create_attrs().
        """
        logging.info("Retrieving the switch attributes and capabilities")

        non_configurable_attrs = [
            "admin_password_set",
            "aruba_central",
            "boot_time",
            "capabilities",
            "capacities",
            "mgmt_intf_status",
            "platform_name",
            "software_images",
            "software_info",
            "software_version",
            "qos_defaults",
            "lldp_mgmt_neighbor_info",
        ]

        uri = "system?depth={0}".format(self.session.api.default_depth)
        if selector:
            uri += "&selector={0}".format(selector)
        else:
            uri += "&attributes={0}".format(",".join(non_configurable_attrs))

        try:
            response = self.session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load into json format
        data = json.loads(response.text)

        # Create class attributes using util.create_attrs
        utils.create_attrs(self, data)

        utils.set_config_attrs(
            self, data, "config_attrs", non_configurable_attrs
        )

        # Save original attributes
        self.__original_attributes = deepcopy(
            utils.get_attrs(self, self.config_attrs)
        )
        # Set device as materialized
        self.materialized = True

    @property
    def modified(self):
        """
        Verifies if there has been a modification for this object or not.
        """
        device_data = utils.get_attrs(self, self.config_attrs)
        return device_data != self.__original_attributes

    @PyaoscxModule.connected
    def get_subsystems(self):
        """
        Perform GET call to retrieve subsystem attributes and create a
            dictionary containing them.
        """
        logging.info(
            "Retrieving the switch subsystem attributes and capabilities"
        )

        # Attribute list
        attributes = [
            "product_info",
            "power_supplies",
            "interfaces",
            "fans",
            "resource_utilization",
        ]

        # Format attribute list by joining every element with a comma
        attributes_list = ",".join(attributes)

        # Build URI
        uri = "system/subsystems?attributes={0}&depth={1}".format(
            attributes_list, self.session.api.default_subsystem_facts_depth
        )

        try:
            # Try to perform a GET call and retrieve the data
            response = self.session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load into json format
        data = json.loads(response.text)
        data_subsystems = {"subsystems": data}

        # Create class attributes using util.create_attrs
        utils.create_attrs(self, data_subsystems)

    @PyaoscxModule.connected
    def get_data_planes(self):
        """
        Perform GET call to retrieve data-planes attributes and create a
            dictionary containing them.
        """
        logging.info(
            "Retrieving the switch data-planes attributes and capabilities"
        )

        api = self.session.api
        if hasattr(api, "default_data_planes_facts_depth"):
            depth = api.default_data_planes_facts_depth
        else:
            depth = api.default_subsystem_facts_depth

        # Build URI
        uri = "system/subsystems?attributes=data_planes&depth={0}".format(
            depth
        )

        try:
            # Try to perform a GET call and retrieve the data
            response = self.session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load into json format
        data = json.loads(response.text)
        data_subsystems = {"data_planes": data}

        # Create class attributes using util.create_attrs
        utils.create_attrs(self, data_subsystems)

    @PyaoscxModule.connected
    def get_firmware_version(self):
        """
        Perform a GET call to retrieve device firmware version.

        :return: The firmware version.
        """
        data = self.get_firmware_info()
        self.firmware_version = data["current_version"]
        # Return Version
        return self.firmware_version

    @PyaoscxModule.connected
    def get_firmware_info(self):
        """
        Perform a GET call to retrieve device firmware information.

        :return: The versions of current, primary and
            secondary images.
        """
        try:
            response = self.session.request("GET", "firmware")

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        firmware_info = json.loads(response.text)
        return firmware_info

    @PyaoscxModule.connected
    def get_firmware_status(self):
        """
        Perform a GET call to retrieve device firmware status.

        :return: firmware_status: The date, reason and status of the firmware
            upload.
        """
        uri = "firmware/status"

        try:
            # Try to perform a GET call and retrieve the data
            response = self.session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        firmware_status = json.loads(response.text)
        return firmware_status

    @PyaoscxModule.materialized
    def apply(self):
        """
        Main method to update an existing Device object.

        :return modified: Boolean, True if object was created or modified.
        """
        return self.update()

    @PyaoscxModule.materialized
    def update(self):
        """
        Perform a PUT call to apply changes to a Device object.

        :return modified: Boolean, True if object was created or modified.
        """
        if not self.modified:
            return False

        device_data = utils.get_attrs(self, self.config_attrs)
        put_data = json.dumps(device_data)

        try:
            response = self.session.request("PUT", "system", data=put_data)
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        # Set new original attributes
        self.__original_attributes = deepcopy(device_data)

        return True

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def update_banner(self, banner_info, banner_type="banner"):
        """
        Perform a PUT request to modify a Device's Banner.

        :param banner_info: String to be configured as the banner.
        :param banner_type: Type of banner being configured on the switch
            either banner or banner_exec.
        :return modified: Returns True if Banner was modified.
        """
        modified = False

        logging.info("Setting Banner")
        depth = self.session.api.default_depth

        # Second GET request to obtain just the variables that are writable
        selector = self.session.api.default_selector
        payload = {"depth": depth, "selector": selector}
        try:
            response = self.session.request(
                "GET", Device.base_uri, params=payload
            )

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Configurable data
        config_data = json.loads(response.text)

        # If Banner type does not exist
        if banner_type not in config_data["other_config"]:
            # Create Banner type
            config_data["other_config"][banner_type] = ""

        # Verify data is different
        if config_data["other_config"][banner_type] == banner_info:
            modified = False

        else:
            # Modify Banner
            config_data["other_config"][banner_type] = banner_info

            # UPDATE Banner
            put_uri = Device.base_uri
            # Set data to be used inside PUT
            put_data = json.dumps(config_data)

            try:
                response = self.session.request("PUT", put_uri, data=put_data)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code, "UPDATE SYSTEM BANNER"
                )

            # Object was modified, returns True
            modified = True

        return modified

    def delete_banner(self, banner_type="banner"):
        """
        Perform a DELETE request to delete a device's Banner.

        :param banner_type: Type of banner being removed on the switch
            either banner or banner_exec.
        :return modified: Returns True if Banner was modified.
        """
        logging.info("Removing Banner")
        depth = self.session.api.default_depth

        # Second GET request to obtain just the variables that are writable
        selector = self.session.api.default_selector
        payload = {"depth": depth, "selector": selector}
        try:
            response = self.session.request(
                "GET", Device.base_uri, params=payload
            )

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Configurable data
        config_data = json.loads(response.text)

        # If Banner type does not exist
        if banner_type not in config_data["other_config"]:
            modified = False

        else:
            # Delete Banner
            config_data["other_config"].pop(banner_type)

            put_data = json.dumps(config_data)

            try:
                response = self.session.request(
                    "PUT", Device.base_uri, data=put_data
                )

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code, "DELETE Banner"
                )

            # Object was modified, returns True
            modified = True

        return modified

    INTERNAL_VLAN_RANGE_ATTRS = (
        "internal_vlan_range_base",
        "internal_vlan_range_size",
    )

    @PyaoscxModule.connected
    def get_internal_vlan_range(self):
        """
        Perform a GET request to read the VLAN range reserved for internal
            use (CLI 'system internal-vlan-range start <id> end <id>').
            Platforms such as the 6200 do not reserve any internal VLAN by
            default and refuse to enable routing on a port until a range is
            configured.

        :return: (start, end) tuple, or None when no range is configured.
        :raises UnsupportedCapabilityError: When the platform does not
            support a configurable internal VLAN range.
        """
        uri = "{0}?attributes={1}".format(
            Device.base_uri, ",".join(self.INTERNAL_VLAN_RANGE_ATTRS)
        )
        try:
            response = self.session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if response.status_code == 400 and "not found" in response.text:
            raise UnsupportedCapabilityError(
                "The internal VLAN range is not supported on this platform"
            )
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)
        base = data.get("internal_vlan_range_base")
        size = data.get("internal_vlan_range_size")
        if not base or not size:
            return None
        return base, base + size - 1

    @PyaoscxModule.connected
    def set_internal_vlan_range(self, start, end):
        """
        Perform a PATCH request to set the VLAN range reserved for internal
            use (CLI 'system internal-vlan-range start <id> end <id>'). The
            switch stores it as a base VLAN and a size.

        :param start: First VLAN ID of the range.
        :param end: Last VLAN ID of the range.
        :return modified: Returns True if the range was modified.
        :raises ParameterError: When the range is not within 2-4094 or
            start is greater than end.
        :raises UnsupportedCapabilityError: When the platform does not
            support a configurable internal VLAN range.
        """
        logging.info("Setting the internal VLAN range")

        for value in (start, end):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ParameterError(
                    "Internal VLAN range bounds must be integers"
                )
        if not 2 <= start <= end <= 4094:
            raise ParameterError(
                "Invalid internal VLAN range {0}-{1}: the bounds must be "
                "within 2-4094 and start must not be greater than "
                "end".format(start, end)
            )

        if self.get_internal_vlan_range() == (start, end):
            return False

        self._patch_internal_vlan_range(start, end - start + 1)
        return True

    @PyaoscxModule.connected
    def delete_internal_vlan_range(self):
        """
        Perform a PATCH request to remove the VLAN range reserved for
            internal use (CLI 'no system internal-vlan-range'). As the CLI,
            and unlike the switch REST API, the removal is refused while
            routing is enabled on a port or LAG, as these use the internal
            VLANs.

        :return modified: Returns True if the range was removed.
        :raises ParameterError: When routing is enabled on a port or LAG.
        :raises UnsupportedCapabilityError: When the platform does not
            support a configurable internal VLAN range.
        """
        logging.info("Removing the internal VLAN range")

        if self.get_internal_vlan_range() is None:
            return False

        uri = "{0}/interfaces?depth=2&attributes=name,type,routing".format(
            Device.base_uri
        )
        try:
            response = self.session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        routed = sorted(
            name
            for name, data in json.loads(response.text).items()
            if data.get("routing") and data.get("type") in ("system", "lag")
        )
        if routed:
            raise ParameterError(
                "The internal VLAN range cannot be removed while routing is "
                "enabled on: {0}".format(", ".join(routed))
            )

        self._patch_internal_vlan_range(None, None)
        return True

    def _patch_internal_vlan_range(self, base, size):
        """
        Send the internal VLAN range with a PATCH; None values remove it.
        """
        data = {
            "internal_vlan_range_base": base,
            "internal_vlan_range_size": size,
        }
        try:
            response = self.session.request(
                "PATCH", Device.base_uri, data=json.dumps(data)
            )
        except Exception as e:
            raise ResponseError("PATCH", e)

        if not utils._response_ok(response, "PATCH"):
            raise GenericOperationError(
                response.text, response.status_code, "SET INTERNAL VLAN RANGE"
            )

    @PyaoscxModule.connected
    def get_interface_groups(self):
        """
        Perform a GET request to read the interface groups of the device
            (CLI 'show system interface-group'). An interface group is a set
            of ports of a line card or chassis sharing the same permitted
            transceiver speed.

        :return: Dictionary keyed by subsystem name (for example
            'line_card,1/1'), then by group number (string), with:
            'speed': configured speed or None when the default applies,
            'applied_speed': speed in use,
            'default_speed': factory default speed,
            'speeds': dictionary of the permitted group speeds with the
            supported port speeds. Subsystems without interface groups are
            omitted.
        """
        attributes = [
            "interface_group_speed",
            "interface_group_applied_speed",
            "interface_group_default_speed",
            "interface_group_info",
        ]
        uri = "{0}/subsystems?attributes={1}&depth=2".format(
            Device.base_uri, ",".join(attributes)
        )
        try:
            response = self.session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        groups = {}
        for subsystem, data in json.loads(response.text).items():
            info = data.get("interface_group_info") or {}
            if not info:
                continue
            configured = data.get("interface_group_speed") or {}
            applied = data.get("interface_group_applied_speed") or {}
            default = data.get("interface_group_default_speed") or {}
            groups[subsystem] = {
                group: {
                    "speed": configured.get(group),
                    "applied_speed": applied.get(group),
                    "default_speed": default.get(group),
                    "speeds": speeds,
                }
                for group, speeds in info.items()
            }
        return groups

    @PyaoscxModule.connected
    def set_interface_group_speed(self, group, speed, line_module=None):
        """
        Perform a PUT request to set the permitted transceiver speed of an
            interface group (CLI 'system interface-group <group> speed
            <speed>', or 'system interface-group <group> line-module
            <line_module> speed <speed>' on modular switches). Changing the
            speed of a group resets all its ports.

        :param group: Interface group number.
        :param speed: Speed such as '10g' or '25g', as listed by
            get_interface_groups(), or None to restore the default speed.
        :param line_module: Line module of the group, for example '1/3'.
            Optional when only one subsystem has this group.
        :return modified: Returns True if the group speed was modified.
        :raises ParameterError: When the group or speed does not exist on
            the device or the line module is ambiguous.
        """
        logging.info("Setting the speed of interface group %s", group)

        group = str(group)
        groups = self.get_interface_groups()
        if line_module is not None:
            subsystem = "line_card,{0}".format(line_module)
            if group not in groups.get(subsystem, {}):
                raise ParameterError(
                    "Interface group {0} does not exist on line module "
                    "{1}".format(group, line_module)
                )
        else:
            candidates = [name for name in groups if group in groups[name]]
            if not candidates:
                raise ParameterError(
                    "Interface group {0} does not exist on this "
                    "device".format(group)
                )
            if len(candidates) > 1:
                raise ParameterError(
                    "Interface group {0} exists on several subsystems ({1}), "
                    "set line_module".format(group, ", ".join(candidates))
                )
            subsystem = candidates[0]

        current = groups[subsystem][group]
        if speed is not None and speed not in current["speeds"]:
            raise ParameterError(
                "Invalid speed {0} for interface group {1}, valid values "
                "are: {2}".format(
                    speed, group, ", ".join(sorted(current["speeds"]))
                )
            )
        if current["speed"] == speed:
            return False

        uri = "{0}/subsystems/{1}".format(
            Device.base_uri, quote_plus(subsystem, safe=",")
        )
        try:
            response = self.session.request(
                "GET", uri, params={"selector": "configuration"}
            )
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # A PATCH merges the dictionary and cannot remove a group, so the
        # whole subsystem configuration is sent back with a PUT.
        config_data = json.loads(response.text)
        configured = dict(config_data.get("interface_group_speed") or {})
        if speed is None:
            configured.pop(group, None)
        else:
            configured[group] = speed
        config_data["interface_group_speed"] = configured

        try:
            response = self.session.request(
                "PUT", uri, data=json.dumps(config_data)
            )
        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(
                response.text,
                response.status_code,
                "SET INTERFACE GROUP SPEED",
            )
        return True

    def boot_firmware(self, partition_name="primary"):
        """
        Perform a POST request to Boot the AOS-CX switch with image present
            to the specified partition.

        :param partition_name: Name of the partition for device to boot to.
        :return bool: True if success.
        """
        # Lower case for partition name
        partition_name = partition_name.lower()
        if partition_name not in ["primary", "secondary"]:
            raise VerificationError("Boot Firmware", "Bad partition name")

        success = False
        uri = "boot?image={0}".format(partition_name)

        try:
            self.session.request("POST", uri)

        except Exception as e:
            raise ResponseError("POST", e)

        success = True

        # Return result
        return success

    def upload_firmware_http(
        self, remote_firmware_file_path, vrf, partition_name="primary"
    ):
        """
        Perform a PUT request to upload a firmware image given a http_request.

        :param remote_firmware_file_path: "HTTP server address and path for
            uploading firmware image, must be reachable through provided vrf
            ex: http://192.168.1.2:8000/TL_10_04_0030A.swi".
        :param vrf: VRF to be used to contact HTTP server, required if
            remote_firmware_file_path is provided.
        :param partition_name: Name of the partition for the image to be
            uploaded to.
        :return bool: True if success.
        """
        http_path = remote_firmware_file_path
        unsupported_versions = [
            "10.00",
            "10.01",
            "10.02",
            "10.03",
        ]
        # Verify Version
        for version in unsupported_versions:
            if version in self.firmware_version:
                raise VerificationError(
                    "Upload Firmware through HTTPs",
                    "Minimum supported firmware version is 10.04 for "
                    "remote firmware upload, your version is {0}".format(
                        self.firmware_version
                    ),
                )
        # Verify VRF
        if vrf is None:
            raise VerificationError(
                "VRF",
                "VRF needs to be provided in order"
                + " to upload firmware from HTTP server",
            )
        http_path_encoded = quote_plus(http_path)

        # Build URI
        uri = "firmware?image={0}&from={1}&vrf={2}".format(
            partition_name, http_path_encoded, vrf
        )

        # PUT for a HTTP Request
        try:
            response = self.session.request("PUT", uri)

        except Exception as e:
            raise ResponseError("PUT", e)

        if (
            not utils._response_ok(response, "PUT")
            and response.status_code != 400
        ):
            # In this case, status code 400 is a valid state
            # PUT often returns "400: Firmware upgrade in progress"
            raise GenericOperationError(response.text, response.status_code)

        # True if successful
        return True

    def upload_firmware_local(
        self,
        partition_name="primary",
        firmware_file_path=None,
        try_pycurl=False,
    ):
        """
        Perform a POST request to upload a firmware image from a local file.

        :param partition_name: Name of the partition for the image to be
            uploaded to.
        :param firmware_file_path: File name and path for local file uploading
            firmware image.
        :param try_pycurl: If True the function will try to use pycurl instead
            of requests.
        :return success: True if success.
        """
        uri = "firmware?image={0}".format(partition_name)

        success = utils.file_upload(
            self.session,
            firmware_file_path,
            self.session._build_uri(uri),
            try_pycurl,
        )
        # If no errors detected
        return success

    def upload_firmware(
        self,
        partition_name=None,
        firmware_file_path=None,
        remote_firmware_file_path=None,
        vrf=None,
        try_pycurl=False,
    ):
        """
        Upload a firmware image from a local file OR from a remote location.

        :param partition_name: Name of the partition for the image to be
            uploaded to.
        :param firmware_file_path: File name and path for local file uploading
            firmware image.
            IMPORTANT: For this to be used, the remote_firmware_file_path
            parameter must be None.
        :param remote_firmware_file_path: HTTP server address and path for
            uploading firmware image, must be reachable through provided vrf
            ex: 'http://192.168.1.2:8000/TL_10_04_0030A.swi'.
        :param vrf: VRF to be used to contact HTTP server, required if
            remote_firmware_file_path is provided.
        :param try_pycurl: If True the function will try to use pycurl instead
            of requests.
        :return bool: True if success.
        """
        result = None
        if partition_name is None:
            partition_name = "primary"

        # Use HTTP Server
        if remote_firmware_file_path is not None:
            result = self.upload_firmware_http(
                remote_firmware_file_path, vrf, partition_name
            )

        # Locally
        else:
            result = self.upload_firmware_local(
                partition_name, firmware_file_path, try_pycurl
            )

        # If no errors detected
        return result

    def vsx_capable(self):
        """
        Return whether this device supports the VSX functionality.

        :return: True if device supports VSX.
        """
        return hasattr(self, "capabilities") and "vsx" in self.capabilities

    def is_capable(self, capability):
        """
        Check if the current Device has the given capability.

        :param capability: String name of a Device capability.
        :return: True if Device is capable.
        """
        if not self.materialized:
            self.get()

        return capability in self.capabilities
