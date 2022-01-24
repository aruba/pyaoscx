# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import logging

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class Vsx(PyaoscxModule):
    """
    Provide configuration management for VSX protocol on AOS-CX devices.
    """

    base_uri = "system/vsx"
    path = "system/vsx"

    def __init__(self, session, **kwargs):
        self.session = session
        # List used to determine attributes related to the VSX configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        # Attribute used to know if object was changed recently
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    def __get_vrf(self, name):
        vrf = self.session.api.get_module(self.session, "Vrf", name)
        return vrf.get_info_format()

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a VSX table entry and fill the
            class with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        # this is common for all PyaoscxModule derived classes
        self._get_and_copy_data(depth, selector)
        # this is specific for this class
        isl_port = self._original_attributes.get("isl_port")
        keepalive_vrf = self._original_attributes.get("keepalive_vrf")
        update_vrf = self._original_attributes.get("software_update_vrf")
        # If the VSX has a isl_port inside the switch and a new one is not
        # being added
        if isl_port:
            isl_port = self.session.api.get_module(
                self.session, "Interface", next(iter(isl_port))
            )
            setattr(self, "isl_port", isl_port.get_info_format())
        # If the VSX has a keepalive_vrf inside the switch and a new one is
        # not being added
        if keepalive_vrf:
            setattr(
                self,
                "keepalive_vrf",
                self.__get_vrf(next(iter(keepalive_vrf))),
            )
        if update_vrf:
            setattr(
                self,
                "software_update_vrf",
                self.__get_vrf(next(iter(update_vrf))),
            )
        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Not applicable for VSX.
        """

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create a Vsx object given a VSX URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return Vsx object.
        """
        return cls(session, uri=uri)

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing VSX
            configuration. Checks whether the VSX configuration exists in the
            switch. Calls self.update() if VSX configuration being updated.
            Calls self.create() if a new VSX configuration is being created.
        :return modified: True if object was created or modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    def _set_isl_port_for_requests(self):
        """
        Set the correct data for the isl_port attribute to use in POST and PUT
            requests.
        """
        if isinstance(self.isl_port, str):
            # if it's a string, it's an interface name, so here it gets changed
            # to an Interface instance
            self.isl_port = self.session.api.get_module(
                self.session, "Interface", self.isl_port
            )
        if not isinstance(self.isl_port, dict):
            # if it's gotten to this point, it should be a either a dictionary,
            # in which case nothing else is needed, or an Interface instance,
            # in which case, the get_info_format() is called to get the
            # dictionary
            self.isl_port = self.isl_port.get_info_format()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing VSX inside switch.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        put_data = utils.get_attrs(self, self.config_attrs)
        if hasattr(self, "keepalive_vrf") and self.keepalive_vrf:
            put_data["keepalive_vrf"] = self.keepalive_vrf
        if hasattr(self, "software_update_vrf") and self.software_update_vrf:
            put_data["software_update_vrf"] = self.software_update_vrf
        if hasattr(self, "isl_port") and self.isl_port:
            self._set_isl_port_for_requests()
            put_data["isl_port"] = self.isl_port
        self.__modified = self._put_data(put_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new VSX. Only returns if no exception
            is raised.
        return: True if entry was created.
        """
        post_data = utils.get_attrs(self, self.config_attrs)
        if hasattr(self, "keepalive_vrf") and self.keepalive_vrf:
            if isinstance(self.keepalive_vrf, str):
                self.keepalive_vrf = self.__get_vrf(self.keepalive_vrf)
            post_data["keepalive_vrf"] = self.keepalive_vrf
        if hasattr(self, "software_update_vrf") and self.software_update_vrf:
            if isinstance(self.software_update_vrf, str):
                self.software_update_vrf = self.__get_vrf(
                    self.software_update_vrf
                )
            post_data["software_update_vrf"] = self.software_update_vrf
        if hasattr(self, "isl_port") and self.isl_port:
            self._set_isl_port_for_requests()
            post_data["isl_port"] = self.isl_port
        if (
            hasattr(self, "keepalive_peer_ip")
            and hasattr(self, "keepalive_src_ip")
            and self.keepalive_src_ip is not None
            and self.keepalive_src_ip is not None
        ):
            ip_src_subnet = self.keepalive_src_ip.find("/")
            ip_peer_subnet = self.keepalive_peer_ip.find("/")
            keepalive_src_ip = self.keepalive_src_ip
            keepalive_peer_ip = self.keepalive_peer_ip
            if ip_src_subnet >= 0:
                keepalive_src_ip = keepalive_src_ip[0:ip_src_subnet]
            if ip_peer_subnet >= 0:
                keepalive_peer_ip = keepalive_peer_ip[0:ip_peer_subnet]
            post_data["keepalive_peer_ip"] = keepalive_peer_ip
            post_data["keepalive_src_ip"] = keepalive_src_ip
        self.__modified = self._post_data(post_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete VSX configuration.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific VSX URI.
        return: Object's URI.
        """
        return self.path

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Not applicable for VSX.
        """

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.
        :return: True if the object was recently modified.
        """
        return self.modified
