# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0


class PyaoscxError(Exception):
    """
    Base class for other PYAOSCX exceptions.
    """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self.message)
