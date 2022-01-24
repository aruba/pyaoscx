# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

from pyaoscx.exceptions.generic_op_error import GenericOperationError


class ListDescriptor(list):
    """
    Attribute descriptor class to keep track of a list that contains
        pyaoscx_module objects simulating a Reference to a resource. If the
        list changes, then every pyaoscx_module object has to be changed.
    """

    def __init__(
        self,
        name,
    ):
        self.name = name

    def __get__(self, instance, owner):
        """
        Method called when current attribute is used.
        :param instance: Instance of the current Object
        """
        return instance.__dict__[self.name]

    def __set__(self, instance, new_list):
        """
        Method called when current attribute is set.
        :param instance: Instance of the current Object.
        :param new_list: new list being set to current attribute object.
        """
        new_list = ReferenceList(new_list)
        prev_list = (
            instance.__dict__[self.name]
            if self.name in instance.__dict__
            else None
        )

        # Update value inside the instance dictionary
        instance.__dict__[self.name] = new_list

        # Check changes and delete
        if prev_list is not None and prev_list != new_list:

            # Reflect changes made inside the list
            for element in prev_list:
                if element not in new_list:
                    # Delete element reference
                    try:
                        element.delete()
                    except AttributeError:
                        # Ignore
                        pass


class ReferenceList(list):
    """
    Wrapper class for a Python List object.
        Modifies remove() method to use the pyaoscx.pyaoscx_module.delete()
        method when using remove on this special type list.
    """

    def __init__(self, value):
        list.__init__(self, value)

    def __setitem__(self, key, value):
        """
        Intercept the l[key]=value operations.
        Also covers slice assignment.
        """
        try:
            _ = self.__getitem__(key)
        except KeyError:
            list.__setitem__(self, key, value)
        else:
            list.__setitem__(self, key, value)

    def __delitem__(self, key):
        """
        Delete self.key.
        """
        _ = list.__getitem__(self, key)
        list.__delitem__(self, key)

    def pop(self):
        """
        Remove and return item at index (default last).
        """
        oldvalue = list.pop(self)
        return oldvalue

    def extend(self, newvalue):
        """
        Extend list by appending elements from iterable.
        """
        list.extend(self, newvalue)

    def insert(self, i, element):
        """
        Insert object before index.
        """
        list.insert(self, i, element)

    def remove(self, element):
        """
        Remove first occurrence of value.
        """
        _ = list.index(self, element)
        list.remove(self, element)
        try:
            # Delete element with a DELETE request
            element.delete()

        # If delete fails because table entry
        # is already deleted: IGNORE
        except GenericOperationError as error:
            # In case error is not 404, raise
            if error.response_code != 404:
                raise error

    def reverse(self):
        """
        Reverse *IN PLACE*.
        """
        list.reverse(self)

    def sort(self, cmpfunc=None):
        """
        Stable sort *IN PLACE*.
        """
        _ = self[:]
        list.sort(self, cmpfunc)
