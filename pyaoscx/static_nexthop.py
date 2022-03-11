# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import json
import logging
import re

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class StaticNexthop(PyaoscxModule):
    """
    Provide configuration management for Static Nexthop settings on AOS-CX
        devices.
    """

    indices = ["id"]
    resource_uri_name = "static_nexthops"

    def __init__(self, session, _id, parent_static_route, uri=None, **kwargs):

        self.session = session
        # Assign IP
        self.id = _id
        # Assign parent StaticRoute object
        self.__set_static_route(parent_static_route)
        self._uri = uri
        # List used to determine attributes related to the Static Nexthop
        # configuration
        self.config_attrs = []
        self.materialized = False
        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)

        # Attribute used to know if object was changed recently
        self.__modified = False

    def __set_static_route(self, parent_static_route):
        """
        Set parent StaticRoute object as an attribute for the StaticNexthop
            object.
        :param parent_static_route a Static_Route object.
        """
        # Set parent Static Route
        self.__parent_static_route = parent_static_route

        # Set URI
        self.base_uri = "{0}/{1}/static_nexthops".format(
            self.__parent_static_route.base_uri,
            self.__parent_static_route.reference_address,
        )

        # Verify Static Nexthop data doesn't exist already for Static Route
        for static_nexthop in self.__parent_static_route.static_nexthops:
            if static_nexthop.id == self.id:
                # Make list element point to current object
                static_nexthop = self
            else:
                # Add self to static_nexthops list in parent Static Route
                self.__parent_static_route.static_nexthops.append(self)

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a Static Nexthop table entry
            and fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is no exception is raised.
        """
        logging.info("Retrieving %s from switch", self)

        depth = depth or self.session.api.default_depth
        selector = selector or self.session.api.default_selector

        if not self.session.api.valid_depth(depth):
            depths = self.session.api.valid_depths
            raise Exception("ERROR: Depth should be {0}".format(depths))

        if selector not in self.session.api.valid_selectors:
            selectors = " ".join(self.session.api.valid_selectors)
            raise Exception(
                "ERROR: Selector should be one of {0}".format(selectors)
            )

        payload = {"depth": depth, "selector": selector}

        uri = "{0}/{1}".format(self.base_uri, self.id)
        try:
            response = self.session.request("GET", uri, params=payload)

        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        # Add dictionary as attributes for the object
        utils.create_attrs(self, data)

        # Determines if the Static Nexthop is configurable
        if selector in self.session.api.configurable_selectors:
            # Set self.config_attrs and delete ID from it
            utils.set_config_attrs(self, data, "config_attrs", ["id"])

        # Set original attributes
        self.__original_attributes = data
        # Remove ID
        if "id" in self.__original_attributes:
            self.__original_attributes.pop("id")

        # If the Static Route has a port inside the switch
        if "port" in data and self.port:
            port_response = self.port
            interface_cls = self.session.api.get_module(
                self.session, "Interface", ""
            )
            # Set port as a Interface Object
            self.port = interface_cls.from_response(
                self.session, port_response
            )
            # Materialize port
            self.port.get()

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True

        return True

    @classmethod
    def get_all(cls, session, parent_static_route):
        """
        Perform a GET call to retrieve all system Static Nexthop objects
            related to a Static Route, and create a dictionary containing
            StaticNexthop objects.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_static_route: StaticRoute object, parent for the Static
            Nexthops.
        :return: Dictionary containing Static Nexthop IDs as keys and a Static
            NexthopThis objects as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        uri = "{0}/{1}/static_nexthops".format(
            parent_static_route.base_uri, parent_static_route.reference_address
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        static_nexthop_dict = {}
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Create a StaticNexthop object and adds it to parent static_route
            # list
            _id, static_nexthop = StaticNexthop.from_uri(
                session, parent_static_route, uri
            )
            # Load all Static Nexthop data from within the Switch
            static_nexthop.get()
            static_nexthop_dict[_id] = static_nexthop

        return static_nexthop_dict

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update an existing Static Nexthop.
            Checks whether the static_nexthop exists in the switch. Calls
            self.update() if Static Nexthop being updated. Calls self.create()
            if a new Static Nexthop is being created.
        :return modified: Boolean, True if object was created or modified.
        """
        if not self.__parent_static_route.materialized:
            self.__parent_static_route.apply()

        modified = False
        if self.materialized:
            modified = self.update()
        else:
            modified = self.create()
        # Set internal attribute
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing static_nexthop.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Variable returned
        modified = False

        static_nexthop_data = utils.get_attrs(self, self.config_attrs)

        # Get port uri
        if hasattr(self, "port") and self.port:
            static_nexthop_data["port"] = self.port.get_info_format()

        uri = "{0}/{1}".format(self.base_uri, self.id)

        # Compare dictionaries
        if static_nexthop_data == self.__original_attributes:
            # Object was not modified
            modified = False

        else:
            post_data = json.dumps(static_nexthop_data)

            try:
                response = self.session.request("PUT", uri, data=post_data)

            except Exception as e:
                raise ResponseError("PUT", e)

            if not utils._response_ok(response, "PUT"):
                raise GenericOperationError(
                    response.text, response.status_code
                )

            logging.info("SUCCESS: Updating %s", self)

            # Set new original attributes
            self.__original_attributes = static_nexthop_data

            # Object was modified
            modified = True
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new static_nexthop. Only returns if no
            exception is raised.
        :return modified: Boolean, True if entry was created
        """
        static_nexthop_data = utils.get_attrs(self, self.config_attrs)
        static_nexthop_data["id"] = self.id

        # Get port uri
        if hasattr(self, "port") and self.port:
            static_nexthop_data["port"] = self.port.get_info_format()

        post_data = json.dumps(static_nexthop_data)

        try:
            response = self.session.request(
                "POST", self.base_uri, data=post_data
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if not utils._response_ok(response, "POST"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Adding %s", self)

        # Get all object's data
        self.get()
        # Object was created, thus modified
        return True

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete StaticNexthop table entry.
        """
        uri = "{0}/{1}".format(self.base_uri, self.id)

        try:
            response = self.session.request("DELETE", uri)

        except Exception as e:
            raise ResponseError("DELETE", e)

        if not utils._response_ok(response, "DELETE"):
            raise GenericOperationError(response.text, response.status_code)

        logging.info("SUCCESS: Deleting %s", self)

        # Delete back reference from VRF
        for static_nexthop in self.__parent_static_route.static_nexthops:
            if static_nexthop.id == self.id:
                self.__parent_static_route.static_nexthops.remove(
                    static_nexthop
                )

        # Delete object attributes
        utils.delete_attrs(self, self.config_attrs)

    @classmethod
    def from_response(cls, session, parent_static_route, response_data):
        """
        Create a StaticNexthop object given a response_data related to the
            Static Nexthop ID object.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_static_route: parent StaticRoute object where Static
            Nexthop is stored.
        :param response_data: The response must be a dictionary of the form:
            {
                id: "/rest/v10.04/system/static_routes/static_nexthops/id"
            }
        :return: StaticNexthop object.
        """
        static_nexthop_arr = session.api.get_keys(
            response_data, StaticNexthop.resource_uri_name
        )
        _id = static_nexthop_arr[0]
        return StaticNexthop(session, _id, parent_static_route)

    @classmethod
    def from_uri(cls, session, parent_static_route, uri):
        """
        Create a StaticNexthop object given a URI.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_static_route: parent static_route class where
            static_nexthop is stored.
        :param uri: a String with a URI.
        :return index, static_nexthop: tuple containing both the Static Nexthop
            object and the Static Nexthop's ID.
        """
        # Obtain ID from URI
        index_pattern = re.compile(r"(.*)static_nexthops/(?P<index>.+)")
        index = index_pattern.match(uri).group("index")

        # Create static_nexthop object
        static_nexthop_obj = StaticNexthop(
            session, index, parent_static_route, uri=uri
        )

        return index, static_nexthop_obj

    def __str__(self):
        return "Static Nexthop: {0}".format(self.id)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific Static Nexthop URI.
        return: Object's URI.
        """
        if self._uri is None:
            self._uri = "{0}{1}/{2}".format(
                self.session.resource_id,
                self.base_uri,
                self.id,
            )

        return self._uri

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Method used to obtain correct object format for referencing inside
            other objects.
        return: Object format depending on the API Version
        """
        return self.session.api.get_index(self)

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

    @classmethod
    def get_next_id(cls, session, parent_static_route):
        """
        Method used to obtain the ID for the next Static Nexthop. Thus perform
            a GET call to retrieve all system Static Nexthop inside a Static
            Route, and with it determine the next ID.
        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param parent_static_route: StaticRoute object, parent for the Static
            Nexthops.
        :return new_id: Integer with the new Id for the next Static Nexthop.
        """
        logging.info("Retrieving the switch static_nexthop")

        uri = "{0}/{1}/static_nexthops".format(
            parent_static_route.base_uri, parent_static_route.reference_address
        )

        try:
            response = session.request("GET", uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        next_id = None
        # Get all URI elements in the form of a list
        uri_list = session.api.get_uri_from_data(data)

        for uri in uri_list:
            # Obtain ID from uri
            _id, static_nexthop = StaticNexthop.from_uri(
                session, parent_static_route, uri
            )
            next_id = int(_id)

        # Set next ID
        if next_id is not None:
            next_id += 1
        else:
            next_id = 0
        return next_id

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################
