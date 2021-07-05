# (C) Copyright 2019-2021 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from abc import ABC, abstractmethod
import functools

class PyaoscxModule(ABC):
    '''
    Provide an Interface class for pyaoscx Modules
    '''

    def connected(fnct):
        '''
        Function used as a decorator to ensure the module has a established
        connection

        :param fnct: function which behavior is modified
        :return ensure_connected: Function
        '''
        @functools.wraps(fnct)
        def ensure_connected(self, *args):
            if not self.session.connected:
                self.session.open()
            return fnct(self, *args)
        return ensure_connected

    base_uri = ""
    indices = []

    @abstractmethod
    @connected
    def get(self, depth=None, selector=None):
        '''
        Perform a GET call to retrieve data for a table entry and fill
        the object with the incoming attributes

        :param depth: Integer deciding how many levels into the API JSON that
            references will be returned.
        :param selector: Alphanumeric option to select specific information to
            return.
        :return: Returns True if there is not an exception raised
        '''
        pass

    @abstractmethod
    def get_all(cls, session):
        '''
        Perform a GET call to retrieve all system <pyaoscx_module_type> and create a dictionary
        of each object
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :return: Dictionary containing object IDs as keys their respective objects as
            values
        '''
        pass

    @abstractmethod
    @connected
    def apply(self):
        '''
        Main method used to either create or update an existing
        <pyaoscx_module_type>.
        Checks whether the <pyaoscx_module_type> exists in the switch
        Calls self.update() if object being updated
        Calls self.create() if a new <pyaoscx_module_type> is being created

        :return modified: Boolean, True if object was created or modified
            False otherwise
        '''
        pass

    @abstractmethod
    @connected
    def update(self):
        '''
        Perform a PUT call to apply changes to an existing
        <pyaoscx_module_type> table entry

        :return modified: True if Object was modified and a PUT request was made.
            False otherwise

        '''
        pass

    @abstractmethod
    @connected
    def create(self):
        '''
        Perform a POST call to create a new <pyaoscx_module_type>
        Only returns if an exception is not raise

        :return modified: Boolean, True if entry was created

        '''
        pass

    @abstractmethod
    @connected
    def delete(self):
        '''
        Perform DELETE call to delete <pyaoscx_module_type> table entry.

        '''
        pass

    def get_uri(self):
        '''
        Method used to obtain the specific <pyaoscx_module_type> URI
        return: Object's URI
        '''
        pass

    def get_info_format(self):
        '''
        Method used to obtain correct object format for referencing inside
        other objects
        return: Object format depending on the API Version
        '''
        pass

    @abstractmethod
    def from_uri(cls, session, uri):
        '''
        Create a <pyaoscx_module_type> object given a <pyaoscx_module_type> URI
        :param cls: Object's class
        :param session: pyaoscx.Session object used to represent a logical
            connection to the device
        :param uri: a String with a URI

        :return index, <pyaoscx_module_type>: tuple containing both the <pyaoscx_module_type> object and the
            <pyaoscx_module_type>'s ID
        '''
        pass
