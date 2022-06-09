# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import logging

from pyaoscx.exceptions.verification_error import VerificationError
from pyaoscx.pyaoscx_module import PyaoscxModule
from pyaoscx.utils import util as utils


class PoEInterface(PyaoscxModule):
    """
    Provide configuration management for PoE Interface on AOS-CX devices.
    """

    collection_uri = "system/interfaces"
    object_uri = collection_uri + "/{interface}/poe_interface"
    resource_uri_name = "poe_interface"
    indices = ["name"]

    def __init__(self, session, parent_interface, **kwargs):
        """
        Create an instance of PoEInterface Class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_interface: parent Inferface object where PoE is stored.
        """
        self.session = session
        # List used to determine attributes related to the PoEInterface
        # configuration
        self.config_attrs = []
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        self.materialized = False
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.base_uri = self.collection_uri
        if isinstance(parent_interface, str):
            parent_interface = self.session.api.get_module(
                self.session, "Interface", parent_interface
            )
        self.name = parent_interface.name
        self.path = self.object_uri.format(
            interface=parent_interface.percents_name
        )
        self._interface = parent_interface
        # Attribute used to know if object was changed recently
        self.__modified = False

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a PoE Interface table entry and
            fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @PyaoscxModule.connected
    def apply(self):
        """
        Apply an update of values of this PoE Interface.
        Calls self.update() to apply changes to an existing PoE Interface.
        """
        modified = False
        if self.materialized:
            modified = self.update()

        # Set internal attribute
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing PoE Interface.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        poe_interface_data = utils.get_attrs(self, self.config_attrs)
        poe_interface_data["config"] = self.config.copy()
        self.__modified = self._put_data(poe_interface_data)
        logging.info("SUCCESS: Updating %s", self)
        self.__original_attributes = poe_interface_data
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        pass

    @PyaoscxModule.connected
    def delete(self):
        pass

    @PyaoscxModule.connected
    def get_all(self):
        pass

    @classmethod
    def from_uri(cls):
        pass

    def __str__(self):
        return "PoE Interface {0}".format(self.name)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific PoE Interface URI.
        return: Object's URI.
        """
        uri = "{0}{1}".format(self.session.resource_prefix, self.path)

        return uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        pass

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    @property
    @PyaoscxModule.materialized
    def allocate_by_method(self):
        """
        Getter method for the allocate_by_method attribute.
        :return: String value for method.
        """
        return self.config["allocate_by_method"]

    @allocate_by_method.setter
    @PyaoscxModule.materialized
    def allocate_by_method(self, new_method):
        """
        Setter method for the allocate_by_method attribute.
        """
        valid_methods = ["class", "usage"]
        if new_method not in valid_methods:
            raise VerificationError(
                "Invalid method {0}, method must be one of {1}".format(
                    new_method, ",".join(valid_methods)
                )
            )
        self.config["allocate_by_method"] = new_method

    @property
    @PyaoscxModule.materialized
    def assigned_class(self):
        """
        Getter method for the cfg_assigned_class attribute.
        :return: String value for assigned class.
        """
        return self.config["cfg_assigned_class"]

    @assigned_class.setter
    def assigned_class(self, new_class):
        """
        Setter method for the cfg_assigned_class attribute.
        """
        valid_classes = ["class3", "class4", "class6", "class8"]
        if new_class not in valid_classes:
            raise VerificationError(
                "Invalid class {0}, assigned class must be one of {1}".format(
                    new_class, ",".join(valid_classes)
                )
            )
        self.config["cfg_assigned_class"] = new_class

    @property
    @PyaoscxModule.materialized
    def priority(self):
        """
        Getter method for the priority attribute.
        :return: String value for priority.
        """
        return self.config["priority"]

    @priority.setter
    @PyaoscxModule.materialized
    def priority(self, new_priority):
        """
        Setter method for the priority attribute.
        """
        valid_priorities = ["low", "high", "critical"]
        if new_priority not in valid_priorities:
            raise VerificationError(
                "Invalid priority {0} priority must be one of {1}".format(
                    new_priority, ",".join(valid_priorities)
                )
            )
        self.config["priority"] = new_priority

    @property
    @PyaoscxModule.materialized
    def power_enabled(self):
        """
        Getter method for admin_disabled attribute.
        :return: Bool value for priority.
        """
        return not self.config["admin_disable"]

    @power_enabled.setter
    @PyaoscxModule.materialized
    def power_enabled(self, state):
        """
        Setter method for admin_disabled attribute
        """
        self.config["admin_disable"] = not state

    @property
    @PyaoscxModule.materialized
    def pd_class_override(self):
        """
        Getter method for pd_class_override attribute.
        :return: Bool value for pd_class_override.
        """
        return self.config["pd_class_override"]

    @pd_class_override.setter
    @PyaoscxModule.materialized
    def pd_class_override(self, new_flag):
        """
        Setter method for pd_class_override attribute
        """
        self.config["pd_class_override"] = new_flag

    @property
    @PyaoscxModule.materialized
    def pre_standard_detect(self):
        """
        Getter method for pre_standard_detect attribute.
        :return: Bool value for pre_standard_detect.
        """
        return self.config["pre_standard_detect"]

    @pre_standard_detect.setter
    @PyaoscxModule.materialized
    def pre_standard_detect(self, new_flag):
        """
        Setter method for pre_standard_detect attribute
        """
        self.config["pre_standard_detect"] = new_flag
