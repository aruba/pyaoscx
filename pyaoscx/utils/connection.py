# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

import functools


def connected(fnct):
    '''
    Function used as a decorator to ensure the module has a established
    connection

    :param fnct: function which behavior is modified
    :return ensure_connected: Function
    '''
    @functools.wraps(fnct)
    def ensure_connected(self, *args):
        if not self.session.is_connected():
            self.session.open()
        return fnct(self, *args)
    return ensure_connected
