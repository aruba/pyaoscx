# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.verification_error import VerificationError


class ParameterError(VerificationError):
    """
    Exception raised when wrong parameters are passed to functions.
    """

    base_msg = "PARAMETER ERROR"
