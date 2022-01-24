# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from copy import deepcopy

import logging
import json
from urllib.parse import quote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
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
    def get(self):
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
        ]

        configurable_attrs = [
            "domain_name",
            "hostname",
            "other_config",
            "qos_config",
            "qos_default",
            "q_profile_default",
        ]

        # Concatenate both config and non-config attrs without duplicates
        all_attributes = list(set(non_configurable_attrs + configurable_attrs))

        attributes_list = ",".join(all_attributes)
        uri = "system?attributes={0}&depth={1}".format(
            attributes_list, self.session.api.default_depth
        )

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
    def get_firmware_version(self):
        """
        Perform a GET call to retrieve device firmware version.
        :return: firmware_version: The firmware version.
        """
        try:
            response = self.session.request("GET", "firmware")

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        self.firmware_version = data["current_version"]
        # Return Version
        return self.firmware_version

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
        :param banner_type: Type of banner being configured on the switch.
            Either banner or banner_exec.
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
        :param banner_type: Type of banner being removed on the switch.
            Either banner or banner_exec.
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

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        # True if successful
        return True

    def upload_firmware_local(
        self, partition_name="primary", firmware_file_path=None
    ):
        """
        Perform a POST request to upload a firmware image from a local file.
        :param partition_name: Name of the partition for the image to be
            uploaded to.
        :param firmware_file_path: File name and path for local file uploading
            firmware image.
        :return success: True if success.
        """
        uri = "firmware?image={0}".format(partition_name)

        success = utils.file_upload(self.session, firmware_file_path, uri)
        # If no errors detected
        return success

    def upload_firmware(
        self,
        partition_name=None,
        firmware_file_path=None,
        remote_firmware_file_path=None,
        vrf=None,
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
                partition_name, firmware_file_path
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
