# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.configuration import Configuration

from pyaoscx.pyaoscx_module import PyaoscxModule


class Dns(PyaoscxModule):
    """
    Provide configuration management for DNS on AOS-CX devices. As it is a
        special module, behaves differently.
    """

    base_uri_vrf = "system/vrf"

    def __init__(
        self,
        session,
        vrf_name,
        domain_name=None,
        domain_list=None,
        domain_servers=None,
        host_v4_address_mapping=None,
        host_v6_address_mapping=None,
        uri=None,
    ):

        self.session = session
        self._uri = uri
        # List used to determine attributes related to the DNS configuration
        self.config_attrs = []
        self.materialized = False
        # Attributes needed for DNS
        self.vrf_name = vrf_name
        self.dns_domain_name = domain_name
        self.dns_domain_list = domain_list
        self.dns_name_servers = domain_servers
        self.dns_host_v4_address_mapping = host_v4_address_mapping
        self.dns_host_v6_address_mapping = host_v6_address_mapping

        # Attribute dictionary used to manage the original data
        # obtained from the GET
        self.__original_attributes = {}
        self.create_attrs = [
            "dns_domain_name",
            "dns_domain_list",
            "dns_name_servers",
            "dns_host_v4_address_mapping",
            "dns_host_v6_address_mapping",
        ]
        # Attribute used to know if object was changed recently
        self.__modified = False
        # VRF attribute where configurable attributes go
        self.__internal_vrf = None
        # Try to create VRF
        self.__internal_vrf = self.session.api.get_module(
            self.session, "Vrf", self.vrf_name
        )
        # Materialize internal VRF
        self.__internal_vrf.get()

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a DNS inside the VRF table
            entry and fill the object with the incoming attributes.
        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        # Get VRF
        vrf_obj = self.session.api.get_module(
            self.session, "Vrf", self.vrf_name
        )

        # Get vrf Object
        vrf_obj.get()

        # Sets internal VRF
        self.__internal_vrf = vrf_obj

        # Set attributes with incoming VRF attributes
        if self.dns_domain_name is None:
            self.dns_domain_name = self.__internal_vrf.dns_domain_name
        if self.dns_domain_list is None:
            self.dns_domain_list = self.__internal_vrf.dns_domain_list
        if self.dns_name_servers is None:
            self.dns_name_servers = self.__internal_vrf.dns_name_servers
        if self.dns_host_v4_address_mapping is None:
            self.dns_host_v4_address_mapping = (
                self.__internal_vrf.dns_host_v4_address_mapping
            )
        if self.dns_host_v6_address_mapping is None:
            self.dns_host_v6_address_mapping = (
                self.__internal_vrf.dns_host_v6_address_mapping
            )

        # Sets object as materialized
        # Information is loaded from the Device
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Method not required for DNS.
        """
        pass

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create a new DNS or update an existing DNS,
            configuring it inside the Vrf object. Checks whether the DNS exists
            in the switch. Calls self.update() if DNS configuration is being
            updated.
        :return modified: Boolean, True if object was created or modified.
        """
        modified = False
        # Apply changes
        modified = self.update()

        # Set internal attribute
        self.__modified = modified
        return modified

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing DNS.
        :return modified: True if Object was modified and a PUT request was
            made.
        """
        # Variable returned
        modified = False

        # Obtain variables
        self.__internal_vrf.dns_domain_name = self.dns_domain_name
        self.__internal_vrf.dns_domain_list = self.dns_domain_list
        self.__internal_vrf.dns_name_servers = self.dns_name_servers
        self.__internal_vrf.dns_host_v4_address_mapping = (
            self.dns_host_v4_address_mapping
        )
        self.__internal_vrf.dns_host_v6_address_mapping = (
            self.dns_host_v6_address_mapping
        )

        # Applies changes inside VRF
        modified = self.__internal_vrf.apply()
        return modified

    @PyaoscxModule.connected
    def create(self):
        """
        Method not implemented.
        """
        pass

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform DELETE call to delete DNS.
        """
        # Delete the dns settings inside the VRF
        self.dns_domain_name = None
        self.dns_domain_list = None
        self.dns_name_servers = None
        self.dns_host_v4_address_mapping = None
        self.dns_host_v6_address_mapping = None

        # Make changes
        return self.apply()

    @classmethod
    def from_response(cls, session, response_data):
        """
        Not applicable for DNS.
        """
        pass

    @classmethod
    def from_uri(cls, session, uri):
        """
        Not applicable for DNS.
        """
        pass

    def __str__(self):
        return "DNS object with VRF: '{0}'".format(self.vrf_name)

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Not applicable for DNS.
        """
        pass

    @PyaoscxModule.deprecated
    def get_info_format(self):
        """
        Not applicable for DNS.
        """
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

    ####################################################################
    # IMPERATIVE FUNCTIONS
    ####################################################################

    def setup_mgmt_nameservers(self, primary=None, secondary=None):
        """
        Setup primary and secondary name servers on a mgmt interface.
        :param primary: Primary nameservers on mgmt interface, a IPv4 address.
            Example: '10.10.2.10'.
        :param secondary: Secondary nameservers on mgmt interface,
            a IP address. Example: '10.10.2.10'.
        :return modified: Return True if coinfig was modified.
        """
        # Create configuration Object
        config = Configuration()

        # Return if configuration was modified
        return config.setup_mgmt_nameservers_dns(primary, secondary)

    def delete_mgmt_nameservers(self):
        """
        Delete primary and secondary name servers on a mgmt interface.
        :return modified: Return True if coinfig was modified.
        """
        # Create configuration Object
        config = Configuration()

        return config.delete_mgmt_nameservers_dns()

    def setup_dns(
        self,
        domain_name=None,
        domain_list=None,
        domain_servers=None,
        host_v4_address_mapping=None,
        host_v6_address_mapping=None,
    ):
        """
        Setup DNS client configuration within a Vrf object.
        :param domain_name: Domain name used for name resolution by the DNS
            client, if 'dns_domain_list' is not configured.
        :param domain_list: dict of DNS Domain list names to be used for
            address resolution, keyed by the resolution priority order.
            Example:
                {
                    0: "hpe.com"
                    1: "arubanetworks.com"
                }
        :param domain_servers: dict of DNS Name servers to be used for address
            resolution, keyed by the resolution priority order. Example:
                {
                    0: "4.4.4.10"
                    1: "4.4.4.12"
                }
        :param host_v4_address_mapping: dict of static host address
            configurations and the IPv4 address associated with them. Example:
                {
                    "host1": "5.5.44.5"
                    "host2": "2.2.44.2"
                }
        :param host_v6_address_mapping: dict of static host address
            configurations and the IPv6 address associated with them. Example:
                {
                    "host1": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
                }
        :return modified: Returns True if modified.
        """
        # Update Values

        if domain_name is not None:
            self.dns_domain_name = domain_name

        if domain_list is not None:
            self.dns_domain_list = domain_list

        if domain_servers is not None:
            self.dns_name_servers = domain_servers

        if host_v4_address_mapping is not None:
            self.dns_host_v4_address_mapping = host_v4_address_mapping

        if host_v6_address_mapping is not None:
            self.dns_host_v6_address_mapping = host_v6_address_mapping

        return self.apply()

    def delete_dns(
        self,
        domain_name=None,
        domain_list=None,
        domain_servers=None,
        host_v4_address_mapping=None,
        host_v6_address_mapping=None,
    ):
        """
        Delete DNS client configuration within a Vrf object.
        :param domain_name: If value is not None, it is deleted.
        :param domain_list: If value is not None, it is deleted.
        :param domain_servers: If value is not None, it is deleted.
        :param host_v4_address_mapping: If value is not None, it is deleted.
        :param host_v6_address_mapping: If value is not None, it is deleted.
        :return modified: Returns True if modified.
        """
        # Update Values

        if domain_name is not None:
            self.dns_domain_name = None

        if domain_list is not None:
            self.dns_domain_list = None

        if domain_servers is not None:
            self.dns_name_servers = None

        if host_v4_address_mapping is not None:
            self.dns_host_v4_address_mapping = None

        if host_v6_address_mapping is not None:
            self.dns_host_v6_address_mapping = None

        return self.apply()
