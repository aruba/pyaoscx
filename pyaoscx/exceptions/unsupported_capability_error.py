# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class UnsupportedCapabilityError(PyaoscxError):
    """
    Exception class for an PYAOSCX Unsupported Capability Error.
    """

    def __init__(self, *args):
        if args:
            super().__init__(args[0])
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        base_msg = "UNSUPPORTED CAPABILITY"
        if self.message:
            base_msg = ": ".join((base_msg, self.message))
        return base_msg
