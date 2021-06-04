# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from abc import ABC, abstractclassmethod
from datetime import date

# List of the versions supported by the SDK
supported_versions = ['1', '10.04']


class API(ABC):
    '''
    Factory class that creates the version's specific API
    class.
    '''
    latest_version = '10.04'
    version = latest_version
    license = "Apache-2.0"

    def __str__(self):
        return self.version

    @classmethod
    def create(cls, target_version):
        '''
        Translate the version string name to a valid python symbol
        :param cls: API Class object
        :param target_version: String with the API Version
        :return api: API object
        '''

        target_version = 'v' + target_version.replace('.', '_')

        if target_version == 'v1':
            from pyaoscx.rest.v1.api import v1
        elif target_version == 'v10_04':
            from pyaoscx.rest.v10_04.api import v10_04
        else:
            raise Exception("Invalid version name")

        return locals()[target_version]()

    @abstractclassmethod
    def __init__(self):
        """
        This method must be overwritten in the derived classes
        to set up the internal attributes, like version as minimum.
        """
        pass
