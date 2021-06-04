# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0


class LoginError(Exception):
    """Exception raised for errors during login.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message, status_code=None):
        self.message = message
        self.status_code = status_code
