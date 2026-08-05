import pytest
from adam.deception.catalogue import register_primitive, get_primitive_class
from adam.deception.plausibility import combine
from adam.deception.primitives.base import DeceptionPrimitive


def test_duplicate_primitive_registration():
    with pytest.raises(ValueError, match="already has a registered primitive"):
        @register_primitive("SPAWN_FAKE_DC_ARTIFACTS")
        class DummyPrimitive(DeceptionPrimitive):
            pass


def test_unregistered_primitive_lookup():
    with pytest.raises(KeyError, match="No deception primitive registered for action"):
        get_primitive_class("NONEXISTENT_ACTION_999")


def test_combine_empty_scores():
    assert combine() == 1.0
