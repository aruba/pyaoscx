# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.verification_error import VerificationError


class ParameterError(VerificationError):
    """
    Exception class for Verification fails of function of method parameters.
        Raised when wrong parameters are passed to functions from user code.
    """

    def __init__(self, *args):
        if args:
            super().__init__(*args[1:])
            self.module = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return "Parameter Error: {0} detail: {1}".format(
                self.module, self.message)
        else:
            return "Parameter Error"
