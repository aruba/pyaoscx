# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class VerificationError(PyaoscxError):
    """
    PYAOSCX Verification Error Exception.
    """

    def __init__(self, *args):
        self.message = None
        self.module = None
        if args:
            if len(args) >= 1:
                self.module = args[0]
            if len(args) > 1:
                message = ", ".join(str(a) for a in args[1:])
                super().__init__(message)

    def __str__(self):
        base_msg = "VERIFICATION ERROR"
        msg_parts = [base_msg]
        if self.module:
            if self.message:
                msg_parts.append("{0} DETAIL".format(self.module))
                msg_parts.append(self.message)
            else:
                msg_parts.append(self.module)
        msg = ": ".join(msg_parts)
        return msg
