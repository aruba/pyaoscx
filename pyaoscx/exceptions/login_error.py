# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class LoginError(PyaoscxError):
    """
    Exception raised for errors during login.
    """

    base_msg = "LOGIN ERROR"

    def __init__(self, *args):
        self.message = None
        self.status_code = None
        if args:
            msg = ", ".join((self.base_msg, str(args[0])))
            if len(args) > 1:
                self.status_code = args[1]
                msg = ", ".join(
                    str(a)
                    for a in (
                        msg,
                        *args[1:][1:],
                    )
                )
            self.message = msg
        else:
            self.message = self.base_msg
