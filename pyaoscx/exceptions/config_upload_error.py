# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.generic_op_error import GenericOperationError


class ConfigUploadError(GenericOperationError):
    """
    PYAOSCX Configuration Upload Error Exception.

    Raised when the switch rejects (part of) an uploaded CLI configuration.
    The switch answers with HTTP 200 and a body such as
    {"state": "failure", "errors": [{"line": ..., "context": [...],
    "command": ..., "message": ...}]}.
    """

    base_msg = "CONFIGURATION UPLOAD ERROR"

    def __init__(self, errors, operation=None, response_code=None):
        self.errors = errors or []
        self.operation = operation
        super(ConfigUploadError, self).__init__(
            self.format_errors(self.errors), response_code
        )

    @staticmethod
    def format_errors(errors):
        lines = []
        for error in errors:
            context = [
                c
                for c in error.get("context") or []
                if c != "configure terminal"
            ]
            lines.append(
                "line {0}{1}: '{2}': {3}".format(
                    error.get("line", "?"),
                    " ({0})".format(" > ".join(context)) if context else "",
                    str(error.get("command", "")).strip(),
                    error.get("message", ""),
                )
            )
        return "; ".join(lines)

    def __str__(self):
        return "{0}: {1}".format(self.base_msg, self.message)
