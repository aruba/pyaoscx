# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.pyaoscx_factory import PyaoscxFactory
from pyaoscx.pyaoscx_module import PyaoscxModule
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError
from pyaoscx.session import Session
import pyaoscx.utils.util as utils


import logging
import json


class Device(PyaoscxFactory):
    '''
    Represents a Device and all of its attributes. Keeping all the important information
    inside one class.
    '''

    base_uri = "system"

    def __init__(self, session):
        self.session = session
        self.firmware_version = None
        # Used to set attributes
        self.config_attrs = []
        self.materialized = False
        # Set firmware version
        self.get_firmware_version()

    @PyaoscxModule.connected
    def get(self):
        '''
        Perform a GET call to retrieve device attributes
        After data from response, Device class attributes
        are generated using create_attrs()

        '''
        logging.info("Retrieving the switch attributes and capabilities")
        attributes = [
            'software_version',
            'software_images',
            'software_info',
            'platform_name',
            'hostname',
            'boot_time',
            'mgmt_intf_status',
            'aruba_central',
            'capabilities',
            'capacities',
            'admin_password_set',
            'other_config',
            'domain_name'
        ]

        attributes_list = ','.join(attributes)
        uri = "{}system?attributes={}&depth={}".format(
            self.session.base_url, attributes_list,
            self.session.api.default_depth)

        try:
            response = self.session.s.get(
                uri, verify=False, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load into json format
        data = json.loads(response.text)

        # Create class attributes using util.create_attrs
        utils.create_attrs(self, data)

        # Set device as materialized
        self.materialized = True

    @PyaoscxModule.connected
    def get_subsystems(self):
        '''
         Perform GET call to retrieve subsystem attributes and create a dictionary containing them
        '''
        # Log
        logging.info("Retrieving the switch subsystem attributes and capabilities")

        # Attribute list
        attributes = [
            'product_info',
            'power_supplies',
            'interfaces',
            'fans',
            'resource_utilization'
        ]

        # Format attribute list by joining every element with a comma
        attributes_list = ','.join(attributes)

        # Build URI
        uri = "{}system/subsystems?attributes={}&depth={}".format(
            self.session.base_url, attributes_list,
            self.session.api.default_subsystem_facts_depth)

        try:
            # Try to perform a GET call and retrieve the data
            response = self.session.s.get(
                uri, verify=False, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Load into json format
        data = json.loads(response.text)
        data_subsystems = {'subsystems' : data}

        # Create class attributes using util.create_attrs
        utils.create_attrs(self, data_subsystems)

    @PyaoscxModule.connected
    def get_firmware_version(self):
        '''
        Perform a GET call to retrieve device firmware version
        :return: firmware_version: The firmware version
        '''

        uri = "{}firmware".format(self.session.base_url)

        try:
            response = self.session.s.get(
                uri, verify=False, proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        self.firmware_version = data["current_version"]
        # Return Version
        return self.firmware_version

    ####################################################################
    # IMPERATIVES FUNCTIONS
    ####################################################################

    def update_banner(self, banner_info, banner_type='banner'):
        '''
        Perform a PUT request to modify a Device's Banner
        :param banner_info: String to be configured as the banner.
        :param banner_type: Type of banner being configured on the switch.
            Either banner or banner_exec
        :return modified: Returns True if Banner was modified.
            False otherwise
        '''
        modified = False

        logging.info("Setting Banner")
        depth = self.session.api.default_depth

        # Second GET request to obtain just the variables that are writable
        selector = self.session.api.default_selector
        payload = {
            "depth": depth,
            "selector": selector
        }
        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=Device.base_uri,
            depth=self.session.api.default_depth
        )
        try:
            response = self.session.s.get(
                uri, verify=False,
                proxies=self.session.proxy,
                params=payload)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Configurable data
        config_data = json.loads(response.text)

        # If Banner type does not exist
        if banner_type not in config_data['other_config']:
            # Create Banner type
            config_data['other_config'][banner_type] = ""

        # Verify data is different
        if config_data['other_config'][banner_type] == banner_info:
            modified = False

        else:
            # Modify Banner
            config_data['other_config'][banner_type] = banner_info

            # UPDATE Banner
            put_uri = "{base_url}{class_uri}".format(
                base_url=self.session.base_url,
                class_uri=Device.base_uri
            )
            # Set data to be used inside PUT
            put_data = json.dumps(config_data, sort_keys=True, indent=4)

            try:
                response = self.session.s.put(
                    put_uri, verify=False, data=put_data, proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError('PUT', e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code, "UPDATE SYSTEM BANNER")

            # Object was modified, returns True
            modified = True

        return modified

    def delete_banner(self, banner_type='banner'):
        '''
        Perform a DELETE request to delete a device's Banner
        :param banner_type: Type of banner being removed on the switch.
            Either banner or banner_exec
        :return modified: Returns True if Banner was modified.
            False otherwise
        '''
        logging.info("Removing Banner")
        depth = self.session.api.default_depth

        # Second GET request to obtain just the variables that are writable
        selector = self.session.api.default_selector
        payload = {
            "depth": depth,
            "selector": selector
        }
        uri = "{base_url}{class_uri}".format(
            base_url=self.session.base_url,
            class_uri=Device.base_uri,
            depth=self.session.api.default_depth
        )
        try:
            response = self.session.s.get(
                uri, verify=False,
                proxies=self.session.proxy,
                params=payload)

        except Exception as e:
            raise ResponseError('GET', e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        # Configurable data
        config_data = json.loads(response.text)

        # If Banner type does not exist
        if banner_type not in config_data['other_config']:
            modified = False

        else:
            # Delete Banner
            config_data['other_config'].pop(banner_type)

            # UPDATE Banner
            uri = "{base_url}{class_uri}".format(
                base_url=self.session.base_url,
                class_uri=Device.base_uri
            )

            put_data = json.dumps(config_data, sort_keys=True, indent=4)

            try:
                response = self.session.s.put(
                    uri, verify=False, data=put_data, proxies=self.session.proxy)

            except Exception as e:
                raise ResponseError('PUT', e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code, "DELETE Banner")

            # Object was modified, returns True
            modified = True

        return modified

    def boot_firmware(self, partition_name='primary'):
        '''
        Perform a POST request to Boot the AOS-CX switch with image present
            to the specified partition
        :param partition_name: String name of the partition for device to boot to.

        :return bool: True if success

        '''
        # Lower case for partition name
        partition_name = partition_name.lower()
        if partition_name not in ['primary', 'secondary']:
            raise VerificationError('Boot Firmware', 'Bad partition name')

        success = False
        uri = '{base_url}boot?image={part}'.format(
            base_url=self.session.base_url,
            part=partition_name)

        try:
            self.session.s.post(
                uri, verify=False,
                proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('POST', e)

        success = True

        # Return result
        return success

    def upload_firmware_http(self, remote_firmware_file_path,
                             vrf,
                             partition_name='primary'):
        '''
        Perform a PUT request to upload a firmware image given
        a http_request

        :param remote_firmware_file_path: "HTTP server address and path for
            uploading firmware image, must be reachable through provided vrf
            ex: http://192.168.1.2:8000/TL_10_04_0030A.swi"
        :param vrf: VRF to be used to contact HTTP server, required if
            remote_firmware_file_path is provided
        :param partition_name: Name of the partition for the
            image to be uploaded to.
        :return bool: True if success
        '''
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
                    'Upload Firmware through HTTPs',
                    "Minimum supported firmware version is 10.04 for" +
                    " remote firmware upload, your version is {firmware}"
                    .format(firmware=self.firmware_version))
        # Verify VRF
        if vrf is None:
            raise VerificationError(
                'VRF',
                "VRF needs to be provided in order" +
                " to upload firmware from HTTP server")
        http_path_encoded = utils._replace_special_characters(http_path)

        # Build URI
        uri = '{base_url}firmware?image={part}&from={path}&vrf={vrf}'\
            .format(
                base_url=self.session.base_url,
                part=partition_name,
                path=http_path_encoded,
                vrf=vrf)

        # PUT for a HTTP Request
        try:
            response = self.session.s.put(
                uri, verify=False,
                proxies=self.session.proxy)

        except Exception as e:
            raise ResponseError('PUT', e)

        if not utils._response_ok(response, "PUT"):
            raise GenericOperationError(
                response.text, response.status_code)

        # True if successful
        return True

    def upload_firmware_local(self, partition_name='primary',
                              firmware_file_path=None):
        '''
        Perform a POST request to upload a firmware image from a local file

        :param partition_name: Name of the partition for the
            image to be uploaded to.
        :param firmware_file_path: File name and path for local file uploading
            firmware image
        :return success: True if success
        '''

        uri = '{base_url}firmware?image={part}'.format(
            base_url=self.session.base_url,
            part=partition_name)

        # Upload file
        success = utils.file_upload(self.session, firmware_file_path, uri)
        # If no errors detected
        return success

    def upload_firmware(self, partition_name=None,
                        firmware_file_path=None,
                        remote_firmware_file_path=None,
                        vrf=None):
        '''
        Upload a firmware image from a local file OR from a remote location

        :param partition_name: Name of the partition for the
            image to be uploaded to.
        :param firmware_file_path: File name and path for local file uploading
            firmware image.
            IMPORTANT: For this to be used, the remote_firmware_file_path
            parameter must be left as NONE
        :param remote_firmware_file_path: HTTP server address and path for
            uploading firmware image, must be reachable through provided vrf
            ex: http://192.168.1.2:8000/TL_10_04_0030A.swi
        :param vrf: VRF to be used to contact HTTP server, required if
            remote_firmware_file_path is provided
        :return bool: True if success
        '''
        result = None
        if partition_name is None:
            partition_name = 'primary'

        # Use HTTP Server
        if remote_firmware_file_path is not None:
            result = self.upload_firmware_http(
                remote_firmware_file_path,
                vrf,
                partition_name)

        # Locally
        else:
            result = self.upload_firmware_local(
                partition_name,
                firmware_file_path)

        # If no errors detected
        return result
