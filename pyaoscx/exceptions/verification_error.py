# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class VerificationError(PyaoscxError):
    """
    Exception class for a PYAOSCX Verification Error.
    """

    def __init__(self, *args):
        if args:
            super().__init__(args[1])
            self.module = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return "VERIFICATION ERROR: {0} DETAIL: {1}".format(
                self.module, self.message)
        else:
            return "VERIFICATION ERROR"
