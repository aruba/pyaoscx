# (C) Copyright 2019-2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import os
import re

from ipaddress import ip_interface
from netaddr import mac_cisco, mac_unix_expanded
from netaddr import EUI as MacAddress
from netaddr.core import AddrFormatError
from requests_toolbelt.multipart.encoder import MultipartEncoder

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.parameter_error import ParameterError

ethertypes = {
    "aarp": 0x80F3,
    "appletalk": 0x809B,
    "arp": 0x0806,
    "fcoe": 0x8906,
    "fcoe-init": 0x8914,
    "ip": 0x0800,
    "ipv6": 0x86DD,
    "ipx-arpa": 0x8137,
    "ipx-non-arpa": 0x8138,
    "is-is": 0x22F4,
    "lldp": 0x88CC,
    "mpls-multicast": 0x8847,
    "mpls-unicast": 0x8848,
    "q-in-q": 0x9100,
    "rbridge": 0x8946,
    "trill": 0x22F3,
    "wake-on-lan": 0x0842,
}

r_ethertypes = {v: k for k, v in ethertypes.items()}

ip_protocols = {
    "ah": 51,
    "esp": 50,
    "gre": 47,
    "icmp": 1,
    "icmpv6": 58,
    "igmp": 2,
    "ospf": 89,
    "pim": 103,
    "sctp": 132,
    "tcp": 6,
    "udp": 17,
}

r_ip_protocols = {v: k for k, v in ip_protocols.items()}

dscp = {
    "AF11": 10,
    "AF12": 12,
    "AF13": 14,
    "AF21": 18,
    "AF22": 20,
    "AF23": 22,
    "AF31": 26,
    "AF32": 28,
    "AF33": 30,
    "AF41": 34,
    "AF42": 36,
    "AF43": 38,
    "CS0": 0,
    "CS1": 8,
    "CS2": 16,
    "CS3": 24,
    "CS4": 32,
    "CS5": 40,
    "CS6": 48,
    "CS7": 56,
    "EF": 46,
}

r_dscp = {v: k for k, v in dscp.items()}

icmp_types = {
    "echo-reply": 0,
    "destination-unreachable": 3,
    "source-quench": 4,
    "redirect": 5,
    "echo": 8,
    "router-advertisement": 9,
    "router-selection": 10,
    "time-exceeded": 11,
    "parameter-problem": 12,
    "timestamp": 13,
    "timestamp-reply": 14,
    "information-request": 15,
    "information-reply": 16,
    "address-mask-request": 17,
    "address-mask-reply": 18,
    "traceroute": 30,
    "extended-echo": 42,
    "extended-echo-reply": 43,
}

r_icmp_types = {v: k for k, v in icmp_types.items()}

icmpv6_types = {
    "destination-unreachable": 1,
    "packet-too-big": 2,
    "time-exceeded": 3,
    "parameter-problem": 4,
    "echo": 128,
    "echo-reply": 129,
    "multicast-listener-query": 130,
    "multicast-listener-report": 131,
    "multicast-listener-done": 132,
    "router-solicitation": 133,
    "router-advertisement": 134,
    "neighbor-solicitation": 135,
    "neighbor-advertisement": 136,
    "redirect-message": 137,
    "router-renumbering": 138,
    "icmp-node-information-query": 139,
    "icmp-node-information-response": 140,
    "mobile-prefix-solicitation": 146,
    "mobile-prefix-advertisement": 147,
    "duplicate-address-request-code-suffix": 157,
    "duplicate-address-confirmation-code-suffix": 158,
    "extended-echo": 160,
    "extended-echo-reply": 161,
}

r_icmpv6_types = {v: k for k, v in icmpv6_types.items()}

l4_ports = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "tacacs": 49,
    "dns": 53,
    "dhcp-server": 67,
    "dhcp-client": 68,
    "tftp": 69,
    "http": 80,
    "https": 443,
    "pop3": 110,
    "nntp": 119,
    "ntp": 123,
    "dce-rpc": 135,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ssn": 139,
    "snmp": 161,
    "snmp-trap": 162,
    "bgp": 179,
    "ldap": 389,
    "microsoft-ds": 445,
    "isakmp": 500,
    "syslog": 514,
    "imap4": 585,
    "radius": 1812,
    "radius-acct": 1813,
    "iscsi": 3260,
    "rdp": 3389,
    "nat-t": 4500,
    "vxlan": 4789,
}

r_l4_ports = {v: k for k, v in l4_ports.items()}


def create_attrs(obj, data_dictionary):
    """
    Given a dictionary object creates class attributes. The methods implements
        setattr() which sets the value of the specified attribute of the
        specified object. If the attribute is already created within the
        object. It's state changes only if the current value is not None.
        Otherwise it keeps the previous value.
    :param data_dictionary: dictionary containing the attributes.
    """
    import copy

    # Used to create a deep copy of the dictionary
    dictionary_var = copy.deepcopy(data_dictionary)

    # K is the argument and V is the value of the given argument
    for k, v in dictionary_var.items():
        # In case a key has '-' inside it's name.
        k = k.replace("-", "_")
        obj.__dict__[k] = v


def get_dict_keys(dict):
    """
    Function used to get a list of all the keys of the respective dictionary.
    :param dict: Dictionary object used to obtain the keys.
    :return: List containing the keys of the given dictionary.
    """
    list = []
    for key in dict.keys():
        list.append(key)

    return list


def check_args(obj, **kwargs):
    """
    Given a object determines if the coming arguments are not already inside
        the object. If attribute is inside the config_attrs, it is ignored.
    :param obj: object in which the attributes are being set to.
    :param **kwargs list of arguments used to create the attributes.
    :return correct: True if all arguments are correct.
    """
    arguments = get_dict_keys(kwargs)
    correct = True
    for argument in arguments:
        if hasattr(obj, argument):
            correct = False
    return correct


def delete_attrs(obj, attr_list):
    """
    Given an object and a list of strings, delete attributes with the same name
        as the one inside the list.
    :param attr_list: List of attribute names that will be deleted from object
    """
    for attr in attr_list:
        if hasattr(obj, attr):
            delattr(obj, attr)


def get_attrs(obj, config_attrs):
    """
    Given an object obtains the attributes different to None.
    :param obj: object containing the attributes.
    :param config_attrs: a list of all the configurable attributes within the
        object.
    :return attr_data_dict: A dictionary containing all the attributes of the
        given object that have a value different to None.
    """
    attr_data_dict = {}
    for attr_name in config_attrs:
        attr_data_dict[attr_name] = getattr(obj, attr_name)
    return attr_data_dict


def set_creation_attrs(obj, **kwargs):
    """
    Used when instantiating the class with new attributes. Sets the
        configuration attributes list, for proper management of attributes
        related to configuration.
    :param obj: Python object in which attributes are being set.
    :param **kwargs: a dictionary containing the possible future arguments for
        the object.
    """
    if check_args(obj, **kwargs):
        obj.__dict__.update(kwargs)
        set_config_attrs(obj, kwargs)
    else:
        raise Exception(
            "ERROR: Trying to create existing attributes inside the object"
        )


def set_config_attrs(
    obj, config_dict, config_attrs="config_attrs", unwanted_attrs=[]
):
    """
    Add a list of strings inside the object to represent each attribute for
        config purposes.
    :param config_dict: Dictionary where each key represents an attribute.
    :param config_attrs: String containing the name of the attribute referring
        to a list.
    :param unwanted_attrs: Attributes that should be deleted, since they can't
        be modified.
    """
    # Set new configuration attributes list
    new_config_attrs = get_dict_keys(config_dict)

    # Delete unwanted attributes from configuration attributes list
    for element in unwanted_attrs:
        if element in new_config_attrs:
            # Remove all occurrences of element inside
            # the list representing the attributes related
            # to configuration
            new_config_attrs = list(filter((element).__ne__, new_config_attrs))
    # Set config attributes list with new values
    obj.__setattr__(config_attrs, new_config_attrs)


def _response_ok(response, call_type):
    """
    Checks whether API HTTP response contains the associated OK code.
    :param response: Response object.
    :param call_type: String containing the HTTP request type.
    :return: True if response was OK.
    """
    ok_codes = {
        "GET": [200],
        "PUT": [200, 204],
        "POST": [201],
        "DELETE": [204],
    }

    return response.status_code in ok_codes[call_type]


def file_upload(session, file_path, complete_uri, try_pycurl=False):
    """
    Upload any file given a URI and the path to a file located on the local
        machine.
    :param session: pyaoscx.Session object used to represent a logical
            connection to the device.
    :param file_path: File name and path for local file uploading.
    :param complete_uri: Complete URI to perform the POST Request and upload
        the file. Example:
            "https://172.25.0.2/rest/v10.04/firmware?image=primary".
    :param try_pycurl: If True the function will try to use pycurl instead
        of requests.
    :return True if successful.
    """
    if try_pycurl:
        try:
            import pycurl
            from urllib.parse import urlencode

            use_pycurl = True
        except ImportError:
            use_pycurl = False
    else:
        use_pycurl = False

    file_name = os.path.basename(file_path)

    if use_pycurl:
        response = {}
        headers = {}

        def response_function(response_line):
            response["s"] = response_line.decode("iso-8859-1")
            return

        def header_function(header_line):
            header_line = header_line.decode("iso-8859-1")
            if ":" in header_line:
                name, value = header_line.split(":", 1)
                name = name.strip()
                value = value.strip()
                name = name.lower()
                if name == "set-cookie" and name in headers:
                    tmp_value = headers[name]
                    tmp_value = tmp_value.split(";")[0]
                    value = tmp_value + "; " + value
                headers[name] = value
            return

        # pycurl handles proxies diferently than requests
        for proto, ip in session.proxy.items():
            if proto in ["http", "https"]:
                proto = proto + "_proxy"
            if ip is None:
                os.environ.pop(proto, None)
            elif ip:
                os.environ[proto] = ip

        login_headers = ["Accept: */*", "x-use-csrf-token: true"]
        upload_headers = ["Accept: */*", "Content-Type: multipart/form-data"]
        logout_headers = ["Accept: */*"]
        login_data = {
            "username": session.username(),
            "password": session.password(),
        }
        postfields = urlencode(login_data)

        c = pycurl.Curl()
        c.setopt(c.URL, session.base_url + "login")
        c.setopt(c.HTTPHEADER, login_headers)
        c.setopt(c.CUSTOMREQUEST, "POST")
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.SSL_VERIFYPEER, False)
        c.setopt(c.SSL_VERIFYHOST, False)
        c.setopt(c.HEADERFUNCTION, header_function)
        c.setopt(c.WRITEFUNCTION, response_function)
        c.perform()
        c.close()

        token_id = "x-csrf-token"
        if "set-cookie" in headers:
            tmp_header = "Cookie: " + headers["set-cookie"]
            upload_headers.append(tmp_header)
            logout_headers.append(tmp_header)
        if token_id in headers:
            tmp_header = token_id + ": " + headers[token_id]
            upload_headers.append(tmp_header)
            logout_headers.append(tmp_header)

        c = pycurl.Curl()
        c.setopt(c.URL, complete_uri)
        c.setopt(c.HTTPHEADER, upload_headers)
        c.setopt(c.WRITEFUNCTION, response_function)
        c.setopt(c.CUSTOMREQUEST, "POST")
        c.setopt(c.SSL_VERIFYPEER, 0)
        c.setopt(c.SSL_VERIFYHOST, 0)
        c.setopt(
            c.HTTPPOST,
            [
                (
                    "fileupload",
                    (
                        c.FORM_FILE,
                        file_path,
                        c.FORM_FILENAME,
                        file_name,
                        c.FORM_CONTENTTYPE,
                        "application/octet-stream",
                    ),
                )
            ],
        )
        c.perform()
        status_code = c.getinfo(c.RESPONSE_CODE)
        c.close()

        c = pycurl.Curl()
        c.setopt(c.URL, session.base_url + "logout")
        c.setopt(c.HTTPHEADER, logout_headers)
        c.setopt(c.WRITEFUNCTION, response_function)
        c.setopt(c.CUSTOMREQUEST, "POST")
        c.setopt(c.SSL_VERIFYPEER, 0)
        c.setopt(c.SSL_VERIFYHOST, 0)
        c.perform()
        c.close()
        if status_code != 200:
            raise GenericOperationError(
                response["s"] + " (" + pycurl.version + ")", status_code
            )

        # Return true if successful
        return True
    # with requests
    else:
        file_param = {
            "fileupload": (
                file_name,
                open(file_path, "rb"),
                "application/octet-stream",
            )
        }
        m_part = MultipartEncoder(fields=file_param)
        file_header = {"Accept": "*/*", "Content-Type": m_part.content_type}

        try:
            file_header.update(session.s.headers)
            # Perform File Upload
            response_file_upload = session.s.post(
                complete_uri,
                verify=False,
                data=m_part,
                headers=file_header,
                proxies=session.proxy,
            )

        except Exception as e:
            raise ResponseError("POST", e)

        if response_file_upload.status_code != 200:
            raise GenericOperationError(
                response_file_upload.text, response_file_upload.status_code
            )

        # Return true if successful
        return True


def get_ip_version(ip):
    """
    Map if given IP address is v4 or v6. Will raise an exception if given
        address if invalid.
    :param ip: String with an IP address.
    :return: String with the IP version. Can be either ipv4 or ipv6.
    """
    try:
        if "/" in ip:
            ip_parts = iter(ip.split("/"))
            ip_addr = next(ip_parts)
            ip_mask = next(ip_parts)
            if not ip_mask.isnumeric():
                ip_mask = (
                    ipv6_netmask_to_cidr(ip_mask)
                    if ":" in ip_mask
                    else ipv4_netmask_to_cidr(ip_mask)
                )
                ip = ip_addr + "/" + str(ip_mask)
        ip_net = ip_interface(ip)
        return "ipv{0}".format(ip_net.version)
    except Exception as intr:
        msg = "Invalid IP: {0}".format(intr)
        raise ParameterError(msg)


def cidr_to_ipv4_netmask(cidr):
    """
    Convert CIDR mask format (/X) to net mask (/X.X.X.X)
    :param: CIDR mask to convert
    :return: String with IPv4 netmask
    """
    cidr = int(cidr)
    mask = (0xFFFFFFFF >> (32 - cidr)) << (32 - cidr)
    return (
        str((0xFF000000 & mask) >> 24)
        + "."
        + str((0x00FF0000 & mask) >> 16)
        + "."
        + str((0x0000FF00 & mask) >> 8)
        + "."
        + str((0x000000FF & mask))
    )


def ipv4_netmask_to_cidr(netmask):
    """
    Convert net mask (/X.X.X.X) to CIDR mask format (/X)
    :param: Net mask to convert
    :return: CIDR mask
    """
    return sum([bin(int(x)).count("1") for x in netmask.split(".")])


def cidr_to_ipv6_netmask(cidr):
    """
    Convert CIDR mask format (/X) to net mask (/X:X:X:X)
    :param: CIDR mask to convert
    :return: String with IPv6 netmask
    """
    cidr = int(cidr)
    all_bits = (2 << 127) - 1
    off_set = 128 - cidr
    raw_mask = hex(all_bits >> off_set << off_set)
    raw_mask = raw_mask.replace("0x", "").replace("L", "")
    mask_bytes = re.findall("....", raw_mask)
    new_mask = ":".join(mask_bytes)
    new_mask = new_mask.replace(":0000", "")
    if len(new_mask) < 39:
        new_mask += "::"
    return new_mask


def ipv6_netmask_to_cidr(netmask):
    """
    Convert net mask (/X:X:X:X) to CIDR mask format (/X)
    :param: Net mask to convert
    :return: CIDR mask
    """
    return sum(
        [
            bin(int("0x{0}".format(x if x != "" else "0"), 16)).count("1")
            for x in netmask.split(":")
        ]
    )


def fix_ip_mask(ip_address, version):
    """
    Fix Ip address mask in CIDR format to net mask
    :param ip_address: IP address with format (A.B.C.D/X)
    :param version: IP version (ipv4 or ipv6)
    :return: String with IP address with format (A.B.C.D/X.X.X.X)
    """
    if "/" in ip_address:
        ip_parts = iter(ip_address.split("/"))
        ip_addr = next(ip_parts)
        ip_mask = next(ip_parts)
        if ip_mask.isnumeric():
            ip_mask = (
                cidr_to_ipv4_netmask(ip_mask)
                if version == "ipv4"
                else cidr_to_ipv6_netmask(ip_mask)
            )
    else:  # host mask
        ip_addr = ip_address
        ip_mask = (
            "255.255.255.255"
            if version == "ipv4"
            else "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        )
    return ip_addr + "/" + ip_mask


def validate_mac_address(mac_addr, cisco_format=False):
    """
    Validate the correct formats for MAC address

    :param mac_addr: MAC address with any EUI format
    :param format: Flag to indicate if CISCO format is used
    :return: string with MAC address the format (XXXX.XXXX.XXXX)
        or (XX:XX:XX:XX:XX:XX)
    """
    try:
        mac = MacAddress(mac_addr)
        if cisco_format:
            mac.dialect = mac_cisco
        else:
            mac.dialect = mac_unix_expanded
    except AddrFormatError as exc:
        raise ParameterError("Invalid MAC address: {0}".format(exc))

    return str(mac)


def set_acl(pyaoscx_module, acl_name, list_type, direction):
    """
    Attach ACL to an interface or vlan

    :param pyaoscx_module: Pyaoscx module (interface or vlan)
    :param acl_name: The name of the ACL.
    :param list_type: The type of the ACL (mac, ipv4 or ipv6).
    :param direction: The direction of the ACL (in, out, routed-in,
        routed-out)
    :return: True if the object was changed
    """
    Interface = pyaoscx_module.session.api.get_module_class(
        pyaoscx_module.session, "Interface"
    )
    Vlan = pyaoscx_module.session.api.get_module_class(
        pyaoscx_module.session, "Vlan"
    )
    is_interface = isinstance(pyaoscx_module, Interface)
    is_vlan = isinstance(pyaoscx_module, Vlan)

    if not is_interface and not is_vlan:
        raise ParameterError("Pyaoscx module must be Interface or Vlan")

    valid_types = ["mac", "ipv4", "ipv6"]
    valid_dirs = ["in", "out", "routed-in", "routed-out"]
    if list_type not in valid_types:
        raise ParameterError(
            "Invalid list_type {0}, valid types are: {1}".format(
                list_type, ", ".join(valid_types)
            )
        )
    if direction not in valid_dirs:
        raise ParameterError(
            "Invalid direction {0}, valid directions are {1}".format(
                direction, ", ".join(valid_dirs)
            )
        )
    is_l3 = False
    if is_interface:
        intf_type = (
            "port"
            if pyaoscx_module.type in [None, "lag"]
            else pyaoscx_module.type
        )
        if intf_type == "tunnel":
            intf_type = "tunnels"
        is_l3 = (
            hasattr(pyaoscx_module, "routing")
            and pyaoscx_module.routing
            or pyaoscx_module.type == "vlan"
        )
    else:
        intf_type = "vlan"
    gen_type = list_type.replace("ip", "")
    if is_interface and intf_type == "vlan" and "routed" not in direction:
        raise ParameterError(
            "Direction {0} not valid for VLAN Interfaces".format(direction)
        )
    # Create Acl object
    acl_obj = pyaoscx_module.session.api.get_module(
        pyaoscx_module.session, "ACL", index_id=acl_name, list_type=list_type
    )
    acl_obj.get()
    capability_prefix = "classifier_acl_{0}_".format(gen_type)

    # Verify direction capabilities
    needed_caps = []
    need_check_dir = False
    if direction == "in" and intf_type == "subinterface":
        suffix = "subinterface_in"
        needed_caps.append(capability_prefix + suffix)
        need_check_dir = True
    elif direction == "out":
        suffix = intf_type + "_out"
        needed_caps.append(capability_prefix + suffix)
        if is_l3:
            suffix = "routed_" + intf_type + "_out"
            needed_caps.append(capability_prefix + suffix)
        need_check_dir = True
    elif "routed" in direction:
        suffix = direction.replace("-", "_")
        needed_caps.append(capability_prefix + suffix)
        suffix = suffix.replace("routed", "routed_{0}".format(intf_type))
        needed_caps.append(capability_prefix + suffix)
        need_check_dir = True

    if (
        need_check_dir
        and [cap for cap in needed_caps if cap in acl_obj.capabilities] == []
    ):
        raise ParameterError(
            "{0}: ACL {1} {2} could not be applied".format(
                pyaoscx_module.name, list_type, direction
            )
        )
    gen_dir = "ingress" if direction in ["in", "routed-in"] else "egress"

    acl_attr = "acl{0}_{1}_cfg".format(gen_type, direction.replace("-", "_"))
    # Validate previous acl against acl object
    prev_acl = getattr(pyaoscx_module, acl_attr)
    if prev_acl == acl_obj:
        return False

    for ace in acl_obj.cfg_aces.values():
        if intf_type == "vlan" and hasattr(ace, "vlan") and ace.vlan:
            raise ParameterError(
                "{0}: VLAN ID cannot be used in an ACL applied to VLAN".format(
                    pyaoscx_module.name
                )
            )

        if hasattr(ace, "protocol"):
            # Verify special capabilities for protocols AH (51) and ESP (50)
            ah_cap = "classifier_ace_{0}_ah_{1}".format(gen_type, gen_dir)
            esp_cap = "classifier_ace_esp_egress"
            proto = ace.protocol
            if (
                proto == 51
                and (gen_type != "v6" or gen_dir == "egress")
                and ah_cap not in acl_obj.capabilities
            ):
                raise ParameterError(
                    "{0}: Protocol AH not supported for {1}".format(
                        pyaoscx_module.name, gen_dir
                    )
                )
            if (
                proto == 50
                and gen_dir == "egress"
                and esp_cap not in acl_obj.capabilities
            ):
                raise ParameterError(
                    "{0}: Protocol ESP not supported for {1}".format(
                        pyaoscx_module.name, gen_dir
                    )
                )
        # Verify capabilities for egress
        if gen_dir == "egress":
            if hasattr(ace, "fragment") and ace.fragment:
                cap_frg = "classifier_acl_{0}_frg_egress".format(gen_type)
                if (
                    "classifier_ace_frg_egress" not in acl_obj.capabilities
                    and cap_frg not in acl_obj.capabilities
                ):
                    raise ParameterError(
                        (
                            "{0}: {1} ACLS fragments"
                            " not supported for egress"
                        ).format(pyaoscx_module.name, acl_obj.list_type)
                    )
            if hasattr(ace, "log") and ace.log:
                cap_log = "classifier_acl_log_{0}_egress".format(ace.action)
                if cap_log not in acl_obj.capabilities:
                    raise ParameterError(
                        (
                            "{0}: Logging of ACL {1}"
                            " not supported for egress"
                        ).format(pyaoscx_module.name, ace.action)
                    )
            if (
                gen_type == "v4"
                and "classifier_ace_v4_tcp_flg_egress"
                not in acl_obj.capabilities
            ):
                for tcp_flag in ace.cap_tcp_flags:
                    if hasattr(ace, tcp_flag) and getattr(ace, tcp_flag):
                        raise ParameterError(
                            "{0}: TCP Flags not supported for egress".format(
                                pyaoscx_module.name
                            )
                        )
    setattr(pyaoscx_module, acl_attr, acl_obj)

    return pyaoscx_module.apply()


def clear_acl(pyaoscx_module, list_type, direction):
    """
    Removes ACL from an interface or vlan

    :param pyaoscx_module: Pyaoscx module (interface or vlan)
    :param list_type: The type of the ACL (mac, ipv4 or ipv6).
    :param direction: The direction of the ACL (in, out, routed-in,
        routed-out)
    :return: True if the object was changed
    """
    valid_types = ["mac", "ipv4", "ipv6"]
    valid_dirs = ["in", "out", "routed-in", "routed-out"]
    if list_type not in valid_types:
        raise ParameterError(
            "Invalid list_type {0}, valid types are: {1}".format(
                list_type, ", ".join(valid_types)
            )
        )
    if direction not in valid_dirs:
        raise ParameterError(
            "Invalid direction {0}, valid directions are {1}".format(
                direction, ", ".join(valid_dirs)
            )
        )
    acl_attr = "acl{0}_{1}_cfg".format(
        list_type.replace("ip", ""), direction.replace("-", "_")
    )

    if hasattr(pyaoscx_module, acl_attr):
        if getattr(pyaoscx_module, acl_attr) is None:
            return False
        setattr(pyaoscx_module, acl_attr, None)
        setattr(pyaoscx_module, acl_attr + "_version", 0)
    else:
        raise ParameterError(
            "{0}: ACL {1} {2} not supported in this platform".format(
                pyaoscx_module.name, list_type, direction
            )
        )

    return pyaoscx_module.apply()
