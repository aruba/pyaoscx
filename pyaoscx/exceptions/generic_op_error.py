# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class GenericOperationError(PyaoscxError):
    """
    PYAOSCX Generic Operation Error Exception.
    """
    base_msg = "GENERIC OPERATION ERROR"

    def __init__(self, *args):
        self.message = None
        self.response_code = None
        self.extra_info = None
        if args:
            self.message = args[0]
            if len(args) >= 2:
                self.response_code = args[1]
            if len(args) > 2:
                self.extra_info = ", ".join(str(a) for a in args[2:])

    def __str__(self):
        msg_parts = [self.base_msg]
        if self.message:
            msg_parts.append(str(self.message))
        if self.response_code:
            msg_parts.append("Code")
            msg_parts.append(str(self.response_code))
        if self.extra_info:
            msg_parts.append("on Module")
            msg_parts.append(str(self.extra_info))
        msg = ": ".join(msg_parts)
        return repr(msg)
