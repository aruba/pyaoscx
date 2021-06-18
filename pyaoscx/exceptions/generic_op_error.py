# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class GenericOperationError(PyaoscxError):
    """"
    Class used to add information regarding a Generic Operation Error
    inside PYAOSCX
    """

    def __init__(self, *args):
        if args:
            super().__init__(args[0])
            self.response_code = args[1]
            try:
                self.extra_info = args[2]
            except IndexError:
                self.extra_info = None
        else:
            self.message = None
            self.extra_info = None

    def __str__(self):
        if self.message and self.extra_info:
            return "GENERIC OPERATION ERROR: {0} Code: {1}"\
                " on Module {2}".format(
                    self.message, self.response_code, self.extra_info)
        if self.message:
            return "GENERIC OPERATION ERROR: {0} Code: {1}".format(
                self.message, self.response_code)
        else:
            return "GENERIC OPERATION ERROR"
