# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.pyaoscx_error import PyaoscxError


class GenericOperationError(PyaoscxError):
    """
    PYAOSCX Generic Operation Error Exception.
    """

    def __init__(self, *args):
        self.message = None
        self.response_code = None
        self.extra_info = None
        if args:
            super().__init__(args[0])
            if len(args) >= 2:
                self.response_code = args[1]
            if len(args) > 2:
                self.extra_info = ", ".join(str(a) for a in args[2:])

    def __str__(self):
        base_msg = "GENERIC OPERATION ERROR"
        msg_parts = [base_msg]
        if self.message:
            msg_parts.append(self.message)
        if self.response_code:
            msg_parts.append("Code")
            msg_parts.append(self.response_code)
        if self.extra_info:
            msg_parts.append("on Module")
            msg_parts.append(self.extra_info)
        msg = ": ".join(msg_parts)
        return msg
