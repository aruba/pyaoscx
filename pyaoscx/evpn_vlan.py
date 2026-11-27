# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import ipaddress
import json
import logging

from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.parameter_error import ParameterError
from pyaoscx.exceptions.unsupported_capability_error import (
    UnsupportedCapabilityError,
)

from pyaoscx.utils import util as utils

from pyaoscx.pyaoscx_module import PyaoscxModule


class EvpnVlan(PyaoscxModule):
    """
    Provide configuration management for per-VLAN EVPN settings on AOS-CX
        devices. These resources live under system/evpn/evpn_vlans and are
        indexed by the VLAN ID. The VLAN must already exist.
    """

    collection_uri = "system/evpn/evpn_vlans"
    object_uri = collection_uri + "/{vlan}"

    indices = ["vlan"]
    resource_uri_name = "evpn_vlans"

    # Suppression feature -> (attribute prefix, IP version of the exemptions)
    SUPPRESSION_FEATURES = {
        "arp": ("arp_suppression", 4),
        "arp_extended": ("arp_suppression_extended", 4),
        "nd": ("nd_suppression", 6),
        "nd_extended": ("nd_suppression_extended", 6),
    }
    SUPPRESSION_CONFIGS = ("enable", "disable")
    # Same limit as the CLI, per VLAN and per feature
    MAX_SUPPRESSION_IP_EXEMPTIONS = 256

    def __init__(self, session, vlan, **kwargs):
        self.session = session
        self.vlan = vlan
        self.config_attrs = []
        self.materialized = False
        self._original_attributes = {}
        # Set arguments needed for correct creation
        utils.set_creation_attrs(self, **kwargs)
        self.__modified = False
        self.base_uri = self.collection_uri
        self.path = self.object_uri.format(vlan=self.vlan)

    @property
    def modified(self):
        return self.__modified

    @PyaoscxModule.connected
    def get(self, depth=None, selector=None):
        """
        Perform a GET call to retrieve data for a per-VLAN EVPN table entry
            and fill the object with the incoming attributes.

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised.
        """
        logging.info("Retrieving %s from switch", self)
        # The vlan attribute is a reference on the switch, keep the VLAN ID
        self._get_and_copy_data(depth, selector, self.indices)
        self.materialized = True
        return True

    @classmethod
    def get_all(cls, session):
        """
        Perform a GET call to retrieve all per-VLAN EVPN entries and create a
            dictionary containing each respective entry.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the switch.
        :return: Dictionary containing VLAN IDs as keys and EvpnVlan objects
            as values.
        """
        logging.info("Retrieving all %s data from switch", cls.__name__)

        try:
            response = session.request("GET", cls.collection_uri)
        except Exception as e:
            raise ResponseError("GET", e)

        if not utils._response_ok(response, "GET"):
            raise GenericOperationError(response.text, response.status_code)

        data = json.loads(response.text)

        collection = {}
        for uri in data.values():
            vlan, evpn_vlan = cls.from_uri(session, uri)
            collection[vlan] = evpn_vlan

        return collection

    @classmethod
    def from_uri(cls, session, uri):
        """
        Create an EvpnVlan object given a per-VLAN EVPN URI.

        :param cls: Object's class.
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
        :param uri: a String with a URI.
        :return: Tuple with the VLAN ID and the EvpnVlan object.
        """
        # The URI ends with the VLAN ID, e.g. system/evpn/evpn_vlans/190
        vlan = int(uri.rstrip("/").split("/")[-1])
        return vlan, cls(session, vlan)

    @PyaoscxModule.connected
    def apply(self):
        """
        Main method used to either create or update a per-VLAN EVPN table
            entry.

        :return: True if the object was modified.
        """
        if self.materialized:
            return self.update()
        return self.create()

    @PyaoscxModule.connected
    def update(self):
        """
        Perform a PUT call to apply changes to an existing per-VLAN EVPN
            entry.

        :return: True if object was modified and a PUT request was made.
        """
        data = utils.get_attrs(self, self.config_attrs)
        self.check_suppression(data)
        self.__modified = self._put_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def create(self):
        """
        Perform a POST call to create a new per-VLAN EVPN entry. Exception is
            raised if the object is unable to be created.

        :return: Boolean, True if entry was created.
        """
        data = utils.get_attrs(self, self.config_attrs)
        self.check_suppression(data)
        data["vlan"] = "{0}system/vlans/{1}".format(
            self.session.resource_prefix, self.vlan
        )
        self.__modified = self._post_data(data)
        return self.__modified

    @PyaoscxModule.connected
    def delete(self):
        """
        Perform a DELETE call to erase the per-VLAN EVPN table entry.
        """
        self._send_data(self.path, None, "DELETE", "Delete")
        utils.delete_attrs(self, self.config_attrs)

    def _suppression_attrs(self, feature):
        """
        Return the config and IP exemption attribute names of a suppression
            feature and its IP version.

        :param feature: 'arp', 'arp_extended', 'nd' or 'nd_extended'.
        :return: Tuple (config attribute, exemption attribute, IP version).
        """
        if feature not in self.SUPPRESSION_FEATURES:
            raise ParameterError(
                "Invalid suppression feature {0}, valid values are: "
                "{1}".format(feature, ", ".join(self.SUPPRESSION_FEATURES))
            )
        prefix, version = self.SUPPRESSION_FEATURES[feature]
        return prefix + "_config", prefix + "_ip_exemption", version

    def _use_attribute(self, attr):
        """
        Make sure an attribute is part of the request body. A firmware that
            does not know the attribute does not return it and PUT would
            silently ignore it, so an existing entry is refused.

        :param attr: Name of the attribute.
        """
        if attr in self.config_attrs:
            return
        if self.materialized:
            raise UnsupportedCapabilityError(
                "The attribute {0} of the EVPN VLAN {1} is not supported by "
                "this switch firmware".format(attr, self.vlan)
            )
        self.config_attrs.append(attr)

    def check_suppression(self, data=None):
        """
        Mirror the CLI: a suppression feature and its extended version cannot
            be enabled together on a VLAN. Only a change is refused, as the
            switch may already hold such a configuration.

        :param data: Request body, the current attributes by default.
        """
        if data is None:
            data = utils.get_attrs(self, self.config_attrs)
        for plain, extended in (
            ("arp", "arp_extended"),
            ("nd", "nd_extended"),
        ):
            attrs = [self._suppression_attrs(f)[0] for f in (plain, extended)]
            if all(data.get(a) == "enable" for a in attrs) and any(
                data.get(a) != self._original_attributes.get(a) for a in attrs
            ):
                raise ParameterError(
                    "{0} and {1} cannot be enabled together on the VLAN "
                    "{2}, disable one of them".format(
                        attrs[0], attrs[1], self.vlan
                    )
                )

    def set_suppression(self, feature, config):
        """
        Override the global EVPN suppression mode for this VLAN (CLI
            'arp-suppression', 'arp-suppression-extended', 'nd-suppression'
            and 'nd-suppression-extended' with 'enable' or 'disable' in the
            'evpn' / 'vlan' context). Changes are sent on apply() or
            update().

        :param feature: 'arp', 'arp_extended', 'nd' or 'nd_extended'. The
            extended versions also suppress on L2 VLANs, and cannot be
            enabled together with the plain version.
        :param config: 'enable' or 'disable' to override the global setting,
            or None to follow it (CLI 'no <feature>').
        :return: True if the value differs from the current one.
        """
        attr, _, _ = self._suppression_attrs(feature)
        if config is not None and config not in self.SUPPRESSION_CONFIGS:
            raise ParameterError(
                "Invalid {0} {1}, valid values are: {2} or None".format(
                    attr, config, ", ".join(self.SUPPRESSION_CONFIGS)
                )
            )
        self._use_attribute(attr)
        changed = getattr(self, attr, None) != config
        setattr(self, attr, config)
        return changed

    def set_suppression_ip_exemption(self, feature, addresses):
        """
        Set the IP addresses excluded from a suppression feature, so that
            their requests are flooded in the fabric (CLI
            'arp-suppression exclude <ip>' and 'nd-suppression exclude <ip>'
            in the 'evpn' / 'vlan' context). The list replaces the current
            one; changes are sent on apply() or update().

        :param feature: 'arp', 'arp_extended', 'nd' or 'nd_extended'. ARP
            features take IPv4 addresses, ND features IPv6 addresses.
        :param addresses: List of IP addresses, an empty list removes all
            exclusions. Order and duplicates are ignored.
        :return: True if the set of addresses differs from the current one.
        """
        _, attr, version = self._suppression_attrs(feature)
        wanted = set()
        for address in addresses or []:
            try:
                ip = ipaddress.ip_address(str(address).strip())
            except ValueError:
                raise ParameterError(
                    "Invalid IP address {0} for {1}".format(address, attr)
                )
            if ip.version != version:
                raise ParameterError(
                    "{0} takes IPv{1} addresses, got {2}".format(
                        attr, version, address
                    )
                )
            wanted.add(ip)
        if len(wanted) > self.MAX_SUPPRESSION_IP_EXEMPTIONS:
            raise ParameterError(
                "{0} accepts at most {1} addresses, got {2}".format(
                    attr, self.MAX_SUPPRESSION_IP_EXEMPTIONS, len(wanted)
                )
            )
        self._use_attribute(attr)
        current = set()
        for address in getattr(self, attr, None) or []:
            try:
                current.add(ipaddress.ip_address(address))
            except ValueError:
                pass
        if current == wanted:
            return False
        # The switch rejects duplicates with an internal error: send each
        # address once.
        setattr(self, attr, sorted(str(ip) for ip in wanted))
        return True

    @PyaoscxModule.deprecated
    def get_uri(self):
        """
        Method used to obtain the specific per-VLAN EVPN URI.

        :return: Object's URI.
        """
        return self.path

    @PyaoscxModule.deprecated
    def was_modified(self):
        """
        Getter method for the __modified attribute.

        :return: True if the object was recently modified.
        """
        return self.modified
