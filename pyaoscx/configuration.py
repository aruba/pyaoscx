# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from urllib.parse import quote_plus

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class Configuration:
    """
    Represents a Device's Configuration and all of its attributes.
    Keeping all configuration information.
    """

    base_uri = "system"

    def __init__(self, session):
        self.session = session
        # Used to set attributes
        self.config_attrs = []
        self.materialized = False
        # Attribute used to know if object was changed recently
        self.__modified = False

    @PyaoscxModule.connected
    def get(self):
        """
        Perform a GET call to retrieve system attributes.
        """
        logging.info("Retrieving the switch attributes and capabilities")
        depth = self.session.api.default_depth
        uri = "{0}?depth={1}".format(Configuration.base_uri, depth)

        try:
            response = self.session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Create class attributes using util.create_attrs
        utils.create_attrs(self, data)

        # Second GET request to obtain just the variables that are writable
        selector = self.session.api.default_selector
        payload = {"depth": depth, "selector": selector}
        try:
            response = self.session.request(
                "GET", Configuration.base_uri, params=payload
            )

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Configurable data
        config_data = json.loads(response.text)

        # Set self.config_attrs and delete ID from it
        utils.set_config_attrs(self, config_data, "config_attrs")

        # Set original attributes
        self.__original_attributes = config_data

        # Set device as materialized
        self.materialized = True

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to update System Attributes. Checks whether the System
            is materialized. Calls self.update() if the configuration is being
            updated.
        :return modified: Boolean, True if object was modified.
        """
        modified = False
        if self.materialized:
            modified = self.update()
        else:
            raise VerificationError("Device", "Not materialized")
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to a Device Configuration.
        :return modified: Boolean, True if object was modified.
        """
        system_data = utils.get_attrs(self, self.config_attrs)

        # Compare dictionaries
        if system_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:

            put_data = json.dumps(system_data)

            try:
                response = self.session.request(
                    "PUT", Configuration.base_uri, data=put_data
                )

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text,
                    response.status_code,
                    "UPDATE SYSTEM ATTRIBUTES",
                )

            logging.info("SUCCESS: Updating System Attributes")
            # Set new original attributes
            self.__original_attributes = system_data

            # Object was modified, returns True
            modified = True

        return modified

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def get_full_config(self, config_name="running-config"):
        """
        Perform a GET request to obtain the device's full config.
        :param config_name: String with the local-config name wanted.
            Defaults to 'running-config'.
        :return config_data: Data containing the full configuration.
        """
        uri = "fullconfigs/{0}".format(config_name)
        try:
            response = self.session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Configurable data
        config_data = json.loads(response.text)

        return config_data

    def tftp_switch_config_from_remote_location(
        self, config_file_location, config_name, vrf
    ):
        """
        TFTP switch config from TFTP server.
        :param config_file_location: TFTP server address and path for
            uploading configuration.
        :param config_name: Config file or checkpoint to be uploaded to.
            When using TFTP only running-config or startup-config can be used.
        :param vrf: VRF to be used to contact TFTP server, required if
            remote_output_file_tftp_path is provided.
        :return success: Return True if response is successful or False if
            it was not.
        """
        success = False
        uri = "fullconfigs/{0}?from={1}&vrf={2}".format(
            config_name, config_file_location, vrf
        )

        try:
            response = self.session.request("PUT", uri)

            success = True

        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        return success

    def copy_switch_config_to_remote_location(
        self, config_name, config_type, destination, vrf
    ):
        """
        Copy TFTP switch config to TFTP server using a PUT request.
        :param config_name:  String with the config file or checkpoint to be
            downloaded. When using TFTP only 'running-config' or
            'startup-config' can be used.
        :param config_type: Configuration type to be downloaded, JSON or CLI
            version of the config. 'json' or 'cli'.
        :param destination: TFTP server address and path for copying
            configuration, must be reachable through provided vrf.
        :param vrf: VRF to be used to contact TFTP server.
        :return: True if completed.
        """
        uri = "fullconfigs/{0}?to={1}&type={2}&vrf={3}".format(
            config_name, destination, config_type, vrf
        )
        try:
            response = self.session.request("GET", uri)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # If no errors, return True for completion
        return True

    def backup_configuration(
        self,
        config_name,
        output_file=None,
        vrf=None,
        config_type="json",
        remote_file_tftp_path=None,
    ):
        """
        Obtains the switch's full config in json format and saves it to
            a local file or a remote location over TFTP.
        :param config_name:  String with the config file or checkpoint to be
            downloaded. When using TFTP only 'running-config' or
            'startup-config' can be used.
        :param output_file: String with the File name and path for locally
            downloading configuration, only JSON version of configuration will
            be downloaded.
        :param vrf: VRF to be used to contact TFTP server.
        :param config_type: Configuration type to be downloaded, JSON or CLI
            version of the config. 'json' or 'cli'. Defaults to 'json'.
        :param remote_file_tftp_path: TFTP server address and path for
            copying off configuration, must be reachable through provided vrf.
        :return bool: True if success.
        """
        success = False

        if remote_file_tftp_path is not None:
            tftp_path = remote_file_tftp_path
            if vrf is None:
                raise VerificationError(
                    "Backup Config",
                    "VRF needs to be provided in order to TFTP "
                    "the configuration from the switch",
                )

            tftp_path_encoded = quote_plus(tftp_path)

            if config_name not in ("running-config", "startup-config"):
                raise VerificationError(
                    "Backup Config",
                    "Only running-config or "
                    "startup-config can be backed-up using TFTP",
                )
            success = self.copy_switch_config_to_remote_location(
                config_name, config_type, tftp_path_encoded, vrf
            )
        else:
            config_json = self.get_full_config()
            with open(output_file, "w") as to_file:
                formatted_file = json.dumps(config_json, indent=4)
                to_file.write(formatted_file)

            success = True

        # Return result
        return success

    def create_checkpoint(self, source_config, destination_config):
        """
        Perform a PUT request to create a new checkpoint or copy an existing
              checkpoint to AOS-CX switch config.
        :param source_config: Name of the source configuration from which
            checkpoint needs to be created or copied.
        :param destination_config: Name of the destination configuration or
            name of checkpoint.
        :return bool: True if success.
        """
        success = False

        uri = "fullconfigs/{0}?from={1}fullconfigs/{2}".format(
            self.session.resource_prefix, destination_config, source_config
        )

        try:
            response = self.session.request("PUT", uri)

        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        success = True

        # Return result
        return success

    def setup_mgmt_nameservers_dns(self, primary=None, secondary=None):
        """
        Setup primary and secondary name servers on a mgmt interface.
        :param primary: Primary nameservers on mgmt interface, a IPv4 address.
            Example: "10.10.2.10".
        :param secondary: Secondary nameservers on mgmt interface,
            a IP address. Example: "10.10.2.10".
        :return modified: Return True if coinfig was modified.
        """
        if "mode" in self.mgmt_intf:
            mgmt_if_mode = self.mgmt_intf["mode"]
        else:
            mgmt_if_mode = "dhcp"

        if mgmt_if_mode != "static":
            message_part1 = "The management interface must have static"
            message_part2 = "IP to configure management interface name servers"
            raise Exception(message_part1 + " " + message_part2)

        if primary is not None:
            self.mgmt_intf["dns_server_1"] = primary
        elif secondary is not None:
            self.mgmt_intf["dns_server_2"] = secondary

        return self.apply()

    def delete_mgmt_nameservers_dns(self):
        """
        Delete primary and secondary name servers on a mgmt interface.
        :return modified: Return True if coinfig was modified.
        """
        if "dns_server_1" in self.mgmt_intf:
            self.mgmt_intf.pop("dns_server_1")

        if "dns_server_2" in self.mgmt_intf:
            self.mgmt_intf.pop("dns_server_2")

        return self.apply()

    def upload_switch_config(
        self,
        config_name=None,
        config_file=None,
        config_json=None,
        vrf=None,
        remote_file_tftp_path=None,
    ):
        """
        Uploads configuration from a configuration file.
        :param config_name:  String with the Config file or checkpoint to be
            uploaded to. When using TFTP only 'running-config' or
            'startup-config' can be used. Defaults to None.
        :param config_file: File name for locally downloading configuration,
            only JSON version of configuration will be downloaded. Defaults to
            None.
        :param config_json: String with the JSON file name and path for locally
            uploading configuration, only JSON version of configuration can be
            uploaded. Defaults to None.
        :param vrf: String for VRF to be used to contact TFTP server, required
            if remote_output_file_tftp_path is provided. Defaults to None.
        :param remote_file_tftp_path: String for TFTP server address and path
            for copying off configuration, must be reachable through provided
            vrf. Defaults to None.
        :return success: Return boolean True if response is successful.
        """
        success = False

        if remote_file_tftp_path is not None:
            if vrf is None:
                raise VerificationError(
                    "Upload Config",
                    "VRF needs to be provided in order to TFTP "
                    "the configuration onto the switch",
                )

            tftp_path_encoded = quote_plus(remote_file_tftp_path)

            if config_name not in ("running-config", "startup-config"):
                raise VerificationError(
                    "Upload Config",
                    "Only running-config or startup-config "
                    "can be uploaded using TFTP",
                )

            success = self.tftp_switch_config_from_remote_location(
                tftp_path_encoded, config_name, vrf
            )

        else:

            success = self.upload_switch_config_from_local(
                config_json, config_file, config_name
            )

        return success

    def upload_switch_config_from_local(
        self, config_json=None, config_file=None, config_name=None
    ):
        """
        Uploads configuration from a configuration file.
        :param config_name:  String with the Config file or checkpoint
            to be uploaded to. When using TFTP only 'running-config' or
            'startup-config' can be used. Defaults to None.
        :param config_file: String with the File name and path for
            locally downloading configuration, only JSON version of
            configuration will be downloaded. Defaults to None.
        :param config_json: String with the JSON file name and path for
            locally uploading configuration, only JSON version of
            configuration can be uploaded. Defaults to None.
        :return success: Return boolean True if response is successful.
        """
        success = False

        if config_json:
            with open(config_json) as json_file:
                config_json = json.load(json_file)

        if config_file:
            with open(config_file) as json_file:
                config_json = json.load(json_file)

        config_json = json.dumps(config_json)

        # Create URI from the session base url and the configuration name
        uri = "fullconfigs/{0}".format(config_name)
        try:
            # Put (REST) configuration file
            response = self.session.request("PUT", uri, data=config_json)

            success = True

        except Exception as e:
            raise ResponseError("PUT", e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(response.text, response.status_code)

        return success
