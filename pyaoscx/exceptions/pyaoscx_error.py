# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0


class PyaoscxError(Exception):
    """
    Base class for other PYAOSCX exceptions.
    """

    base_msg = "PYAOSCX ERROR"

    def __init__(self, *args):
        self.message = ", ".join(
            (
                self.base_msg,
                *(str(a) for a in args),
            )
        )

    def __str__(self):
        return repr(self.message)
