# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class ResponseError(PyaoscxError):
    """
    Exception class for a PYAOSCX Response Error.
    """

    def __init__(self, *args):
        if args:
            super().__init__(args[1])
            self.response = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return "RESPONSE ERROR in {0}: {1}".format(
                self.message, self.response
            )
        else:
            return "RESPONSE ERROR"
