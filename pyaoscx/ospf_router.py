# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.verification_error import VerificationError

from pyaoscx.utils import util as utils
from pyaoscx.utils.list_attributes import ListDescriptor

from pyaoscx.pyaoscx_module import PyaoscxModule


class OspfRouter(PyaoscxModule):
    """
    Provide configuration management for OSPF Routers on AOS-CX devices.
    """

    version = ""
    collection_uri = "system/vrfs/{name}/ospf{version}_routers"
    object_uri = collection_uri + "/{instance_tag}"

    indices = ["instance_tag"]
    resource_uri_name = "ospf_routers"

    # Use to manage references
    areas = ListDescriptor("areas")

    def __init__(self, session, instance_tag, parent_vrf, **kwargs):
        self.session = session
        # Assign ID
        self.__instance_tag = instance_tag
        # Assign parent Vrf object
        self._parent_vrf = parent_vrf
        # List used to determine attributes related to the OSPF configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary to manage original data obtained from the GET
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.passive_interfaces = None
        if kwargs.get("passive_interfaces"):
            self.passive_interfaces = [
                self.session.api.get_module(self.session, "Interface", i)
                for i in kwargs["passive_interfaces"]
            ]
        # Use to manage Areas
        self.areas = []
        # Attribute used to know if object was changed recently
        self.__modified = False
        uri_indices = {
            "name": self._parent_vrf.name,
            "version": self.version,
            "instance_tag": self.__instance_tag,
        }
        self.base_uri = self.collection_uri.format(**uri_indices)
        self.path = self.object_uri.format(**uri_indices)
        self._parent_vrf.update_ospf_routers(self)

    @property
    def instance_tag(self):
        """
        Return this OSPF Router's instance_tag.
        """
        return self.__instance_tag

    @property
    def modified(self):
        """
        Return boolean with whether this object has been modified.
        """
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a OSPF Router table entry and
            fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        # this is common for all PyaoscxModule derived classes
        self._get_and_copy_data(depth, selector, self.indices)
        # Delete unwanted data
        if "areas" in self._original_attributes:
            del self._original_attributes["areas"]
        # Set original attributes
        if "instance_tag" in self._original_attributes:
            del self._original_attributes["instance_tag"]
        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        # Set a list of passive_interfaces as an attribute
        if self.passive_interfaces:
            interfaces_list = []
            # Get all URI elements in the form of a list
            uri_list = self.session.api.get_uri_from_data(
                self.passive_interfaces
            )
            # gotta use deferred import to avoid cyclical import error
            from pyaoscx.interface import Interface

            for uri in uri_list:
                # Create an Interface object
                _, iface = Interface.from_uri(self.session, uri)
                # Add interface to list
                interfaces_list.append(iface)
            # Set list as Interfaces
            self.passive_interfaces = interfaces_list
        if self.areas == []:
            # Set Areas if any
            # Adds Area to parent OspfRouter
            from pyaoscx.ospf_area import OspfArea

            OspfArea.get_all(self.session, self)
        return True

    @classmethod
    def get_all(cls, session, parent_vrf):
        """
        Perform a GET call to retrieve all system OSPF Router settings for a
            given VRF, and create a dictionary containing them.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: Vrf object where OspfRouter object is stored.
        :return: Dictionary containing
            (OSPF Router ID, OspfRouter object) (key,value) pairs.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)
        uri_indices = {"name": parent_vrf.name, "version": cls.version}
        uri = cls.collection_uri.format(**uri_indices)
        try:
            response = session.request("GET", uri)
        except Exception as exc:
            raise ResponseError("GET", exc) from exc
        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)
        data = json.loads(response.text)
        ospf_dict = {}
        uri_list = session.api.get_uri_from_data(data)
        for uri in uri_list:
            # Create a OspfRouter object and adds it to parent Vrf object list
            instance_tag, ospf = cls.from_uri(session, parent_vrf, uri)
            # Load all OSPF Router data from within the Switch
            ospf_dict[instance_tag] = ospf

        return ospf_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create update an existing OSPF Router.
            Checks whether the VRF exists in the switch. Calls self.update() if
            OSPF Router is being updated. Calls self.create() if a new OSPF
            Router is being created.
        :return modified: Boolean, True if object was created or modified.
        """
        if not self._parent_vrf.materialized:
            self._parent_vrf.apply()
        if self.materialized:
            return self.update()
        return self.create()

    def __get_passive_interfaces_to_correct_form(self):
        """
        Auxiliary method to set passive interfaces to correct form for
            requests.
        """
        formatted_interfaces = {}
        if self.passive_interfaces is not None:
            for iface in self.passive_interfaces:
                if isinstance(iface, str):
                    iface = self.session.api.get_module(
                        self.session, "Interface", iface
                    )
                iface.get()
                if not iface.materialized:
                    raise VerificationError(
                        "Interface {0}".format(iface.name),
                        "Object inside passive_interfaces not materialized",
                    )
                formatted_iface = iface.get_info_format()
                formatted_interfaces.update(formatted_iface)
        return formatted_interfaces

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing OSPF Router.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        ospf_router_data = utils.get_attrs(self, self.config_attrs)

        formatted_ifaces = self.__get_passive_interfaces_to_correct_form()
        if formatted_ifaces != {}:
            ospf_router_data["passive_interfaces"] = formatted_ifaces

        self.__modified = self._put_data(ospf_router_data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new  OSPF Router. Only returns if an
            exception is not raised.
        :return modified: True if entry was created.
        """
        ospf_router_data = utils.get_attrs(self, self.config_attrs)
        ospf_router_data["instance_tag"] = self.__instance_tag

        formatted_ifaces = self.__get_passive_interfaces_to_correct_form()
        if formatted_ifaces != {}:
            ospf_router_data["passive_interfaces"] = formatted_ifaces

        self.__modified = self._post_data(ospf_router_data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete  OSPF Router table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        self._parent_vrf.remove_ospf_router(self)
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_vrf, response_data):
        """
        Create a OspfRouter object given a response_data related to the
            OspfRouter object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_vrf: Vrf object where OspfRouter object is stored.
        :param response_data: The response must be a dictionary of the form:
            {id: URL}, with the URL being of the form:
            "/rest/v10.04/system/vrfs/<name>/ospf_routers/<id>"
        :return: OspfRouter object.
        """
        ospf_arr = session.api.get_keys(response_data, cls.resource_uri_name)
        instance_tag = ospf_arr[0]
        return cls(session, instance_tag, parent_vrf)

    @classmethod
    def from_uri(cls, session, parent_vrf, uri):
        """
        Create a OspfRouter object given a URI.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: tuple(OSPF Instance Tag: int, OSPF Router: OspfRouter).
        """
        # Obtain ID from URI like:
        # system/vrfs/{name}/ospf{version}_routers/{instance_tag}
        instance_tag = uri.split("/")[-1]

        # Create OspfRouter object
        ospf_obj = cls(session, instance_tag, parent_vrf)

        return instance_tag, ospf_obj

    def __str__(self):
        return "{0} with instance_tag {1}".format(
            type(self).__name__, self.instance_tag
        )

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific OSPF Router URI.
        return: Object's URI.
        """
        # PyaoscxModule's methods use self.path to store the URI
        return self.path

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: Object format depending on the API Version.
        """
        return self.session.api.get_index(self)

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.
        :return: Boolean True if the object was recently modified.
        """
        return self.modified

    def update_ospf_areas(self, new_area):
        """
        Update references to OSPF Areas. If an Area with the same area_id is
            found, update the reference to the new area, otherwise, add
            reference to the new area.
        :param new_area: Area to add reference to.
        """
        for area in self.areas:
            if area.area_id == new_area.area_id:
                # Make list element point to current object
                # See utils.list_attributes.ListDescriptor
                area = new_area
                return
        self.areas.append(new_area)

    def remove_ospf_area(self, area):
        """
        Update references to OSPF Areas. If an Area with the same area_id is
            found, delete the reference to it.
        :param new_area: Area to add reference to.
        """
        for area_ in self.areas:
            if area.area_id == area_.area_id:
                self.areas.remove(area_)
