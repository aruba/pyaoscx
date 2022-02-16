# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class UnsupportedCapabilityError(PyaoscxError):
    """
    Exception class for an PYAOSCX Unsupported Capability Error.
    """

    base_msg = "UNSUPPORTED CAPABILITY"
