# (C) Copyright 2024 Hewlett Packard Enterprise Development LP.
# Apache License 2.0

"""
Offline unit tests for pyaoscx.utils.util.delete_attrs.

delete_attrs must remove plain instance attributes but must not attempt to
delete class-level read-only properties (which would raise AttributeError:
"property ... has no deleter").
"""

import pyaoscx.utils.util as utils


class WithProperty:
    def __init__(self):
        self.plain = "value"
        self._hidden = "ro"

    @property
    def readonly(self):
        return self._hidden


def test_delete_attrs_removes_plain_attribute():
    obj = WithProperty()
    utils.delete_attrs(obj, ["plain"])
    assert not hasattr(obj, "plain")


def test_delete_attrs_skips_readonly_property():
    obj = WithProperty()
    # Must not raise even though "readonly" is a property without a deleter.
    utils.delete_attrs(obj, ["readonly", "plain"])
    # The property is still accessible, the plain attribute is gone.
    assert obj.readonly == "ro"
    assert not hasattr(obj, "plain")


def test_delete_attrs_ignores_missing_attribute():
    obj = WithProperty()
    utils.delete_attrs(obj, ["does_not_exist"])
    assert obj.plain == "value"
