"""
Unit tests for sensor registry geo parsing.
"""

import pytest

from nexus.intel.sensor_registry import parse_location_coords


def test_parse_location_coords_valid():
    coords = parse_location_coords("47.6205,-122.3493")
    assert coords == pytest.approx((47.6205, -122.3493))


def test_parse_location_coords_whitespace():
    coords = parse_location_coords(" 47.6 , -122.3 ")
    assert coords == pytest.approx((47.6, -122.3))


def test_parse_location_coords_invalid():
    assert parse_location_coords("Roof") is None


def test_parse_location_coords_out_of_range():
    assert parse_location_coords("95,0") is None
    assert parse_location_coords("0,181") is None


def test_parse_location_coords_missing():
    assert parse_location_coords(None) is None
