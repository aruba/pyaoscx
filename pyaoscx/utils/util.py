# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from netaddr import IPNetwork
import os

from requests_toolbelt.multipart.encoder import MultipartEncoder

from pyaoscx.exceptions.generic_op_error import GenericOperationError
from pyaoscx.exceptions.response_error import ResponseError
from pyaoscx.exceptions.parameter_error import ParameterError


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
        ip_net = IPNetwork(ip)
        return "ipv{0}".format(ip_net.version)
    except ValueError:
        msg = "Invalid IP Address: {0}".format(ip)
        raise ParameterError(msg)
