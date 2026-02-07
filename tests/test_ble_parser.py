import os
import sys

sys.path.append(os.path.abspath("src"))

from wicap.core.processing.ble_parser import BLEParser


def test_ble_parser_adv_line():
    parser = BLEParser()
    line = '"1700000000.123"|"AA:BB:CC:DD:EE:FF"|"1"|"-67"|"37"|"0x00"|"0x8e89bed6"|"0x004C"|"iPhone"|"0xFE9F"'
    event = parser.parse_line(line)

    assert event is not None
    assert event["protocol"] == "bt"
    assert event["event_type"] == "bt_adv_ind"
    assert event["bt"]["addr"] == "AA:BB:CC:DD:EE:FF"
    assert event["bt"]["addr_type"] == "random"
    assert event["bt"]["rssi"] == -67
    assert event["bt"]["channel"] == 37
    assert event["bt"]["company_id"] == "0x004C"
    assert event["vendor"] == "Apple, Inc."
    assert event["bt"]["local_name"] == "iPhone"
    assert event["bt"]["service_uuids"] == ["0000fe9f-0000-1000-8000-00805f9b34fb"]
    assert event["keys"]["rssi_dbm"] == -67


def test_ble_parser_scan_rsp():
    parser = BLEParser()
    line = '"1700000001.456"|"11:22:33:44:55:66"|"0"|"-80"|"38"|"0x04"|"0x8e89bed6"|||'
    event = parser.parse_line(line)

    assert event is not None
    assert event["event_type"] == "bt_scan_rsp"
    assert event["bt"]["addr"] == "11:22:33:44:55:66"
    assert event["bt"]["addr_type"] == "public"
    assert event["bt"]["rssi"] == -80
    assert event["bt"]["channel"] == 38


def test_ble_parser_alt_rssi_fallback():
    parser = BLEParser()
    line = '"1700000002.789"|"22:33:44:55:66:77"|"0"|""|"39"|"0x00"|"0x8e89bed6"|||"|"-55"'
    event = parser.parse_line(line)

    assert event is not None
    assert event["bt"]["addr"] == "22:33:44:55:66:77"
    assert event["bt"]["rssi"] == -55


def test_ble_parser_field_names_mapping():
    parser = BLEParser()
    field_names = [
        "frame.time_epoch",
        "btle.advertising_address",
        "btle.advertising_header.randomized_tx",
        "btle.rssi",
        "btle.channel",
        "btle.advertising_header.pdu_type",
        "btle.access_address",
        "btle.initiator_address",
        "btcommon.eir_ad.entry.company_id",
        "btcommon.eir_ad.entry.manufacturer_data",
        "btcommon.eir_ad.entry.device_name",
        "btcommon.eir_ad.entry.uuid_16",
        "btcommon.eir_ad.entry.uuid_32",
        "btcommon.eir_ad.entry.uuid_128",
    ]
    line = '"1700000003.123"|"AA:BB:CC:DD:EE:11"|"0"|"-72"|"37"|"0x00"|"0x8e89bed6"|"11:22:33:44:55:66"|"0x004C"|"0x4C000215"|"Beacon"|"0xFE9F"|"0x11223344"|"f000aa65-0451-4000-b000-000000000000"'
    event = parser.parse_line(line, field_names)

    assert event is not None
    assert event["bt"]["addr"] == "AA:BB:CC:DD:EE:11"
    assert event["bt"]["rssi"] == -72
    assert event["bt"]["peer_addr"] == "11:22:33:44:55:66"
    assert "0000fe9f-0000-1000-8000-00805f9b34fb" in event["bt"]["service_uuids"]
    assert "11223344-0000-1000-8000-00805f9b34fb" in event["bt"]["service_uuids"]
    assert "f000aa65-0451-4000-b000-000000000000" in event["bt"]["service_uuids"]
    assert event["bt"]["manufacturer_data_hash"] == "6bbe2b91645987cb60edd7b02b9437d8de5f272ba32b01fe41c7bd6ab21ddfd5"


def test_ble_parser_connection_event():
    parser = BLEParser()
    line = '"1700000004.000"|"AA:BB:CC:DD:EE:22"|"0"|"-50"|"37"|"0x05"|"0x12345678"|"0x004C"|"Device"|"0x180D"'
    event = parser.parse_line(line)

    assert event is not None
    assert event["event_type"] == "bt_connection_seen"
    assert event["bt"]["access_address"] == "0x12345678"
