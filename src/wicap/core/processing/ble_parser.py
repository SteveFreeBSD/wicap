"""
BLE Parser for WICAP.

Parses delimiter-separated values from tshark -T fields.
"""
import hashlib
import re
import time
from collections.abc import Iterable

try:
    from .ble_company_ids import lookup_company, normalize_company_id
except Exception:
    try:
        from wicap.core.processing.ble_company_ids import lookup_company, normalize_company_id
    except Exception:
        lookup_company = None
        normalize_company_id = None
try:
    from logger import get_logger
except ImportError:
    import logging
    def get_logger(name): return logging.getLogger(name)

logger = get_logger(__name__)

class BLEParser:
    def __init__(self):
        pass

    @staticmethod
    def _split_values(value: str) -> list[str]:
        if not value:
            return []
        parts = []
        for token in value.replace(";", ",").split(","):
            token = token.strip().strip('"')
            if token:
                parts.append(token)
        return parts

    @staticmethod
    def _normalize_uuid(value: str) -> str | None:
        if not value:
            return None
        token = value.strip().lower()
        token = token.replace("{", "").replace("}", "").replace("-", "")
        if token.startswith("0x"):
            token = token[2:]
        if len(token) == 4:
            return f"0000{token}-0000-1000-8000-00805f9b34fb"
        if len(token) == 8:
            return f"{token}-0000-1000-8000-00805f9b34fb"
        if len(token) == 32:
            return f"{token[0:8]}-{token[8:12]}-{token[12:16]}-{token[16:20]}-{token[20:32]}"
        if len(token) == 36 and "-" in value:
            return value.lower()
        return None

    @staticmethod
    def _normalize_manufacturer_data(value: str) -> str | None:
        if not value:
            return None
        token = str(value).strip().strip('"')
        if not token:
            return None
        token = token.split(",")[0].strip()
        if token.lower().startswith("0x"):
            token = token[2:]
        token = re.sub(r"[^0-9A-Fa-f]", "", token)
        if not token or len(token) < 4 or len(token) % 2 != 0:
            return None
        return token.lower()

    def _normalize_uuid_list(self, values: Iterable[str]) -> list[str]:
        seen = set()
        output = []
        for value in values:
            normalized = self._normalize_uuid(value)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)
        return output

    @staticmethod
    def _parse_pdu_type(value: str) -> tuple[int | None, str | None]:
        if not value:
            return None, None
        token = value.strip().split(",")[0].strip()
        token = token.replace("(", "").replace(")", "")
        if token.lower().startswith("0x"):
            try:
                return int(token, 16), None
            except ValueError:
                return None, None
        if token.isdigit():
            return int(token), None
        names = {
            "adv_ind": 0,
            "adv_direct_ind": 1,
            "adv_nonconn_ind": 2,
            "adv_scan_ind": 3,
            "scan_rsp": 4,
            "connect_ind": 5,
            "scan_req": 6,
            "adv_ext_ind": 7,
        }
        key = token.lower()
        if key in names:
            return names[key], token
        return None, None

    def parse_line(self, line: str, field_names: list[str] | None = None) -> dict | None:
        """
        Parse a single line of pipe-delimited tshark fields.
        Expected format (11 fields):
        time_epoch|addr|randomized_tx|rssi|channel|pdu_type|access_addr|company_id|device_name|uuid_16|alt_rssi
        """
        try:
            line = line.strip()
            if not line:
                return None

            parts = [p.strip('"') for p in line.split("|")]

            if field_names:
                values = {}
                for idx, name in enumerate(field_names):
                    values[name] = parts[idx] if idx < len(parts) else ""

                ts_str = values.get("frame.time_epoch", "")
                addr = values.get("btle.advertising_address", "")
                initiator_addr = (
                    values.get("btle.initiator_address_resolved", "")
                    or values.get("btle.initiator_address", "")
                )
                randomized_tx = values.get("btle.advertising_header.randomized_tx", "")
                rssi_str = (
                    values.get("nordic_ble.rssi", "")
                    or values.get("btle.rssi", "")
                )
                channel_str = (
                    values.get("nordic_ble.channel", "")
                    or values.get("btle.channel", "")
                )
                pdu_type_str = values.get("btle.advertising_header.pdu_type", "")
                access_address = values.get("btle.access_address", "")
                company_id = values.get("btcommon.eir_ad.entry.company_id", "")
                manufacturer_data = values.get("btcommon.eir_ad.entry.manufacturer_data", "")
                device_name = values.get("btcommon.eir_ad.entry.device_name", "")
                uuid_16 = (
                    values.get("btcommon.eir_ad.entry.uuid_16", "")
                    or values.get("btcommon.eir_ad.entry.service_uuid_16", "")
                )
                uuid_32 = (
                    values.get("btcommon.eir_ad.entry.uuid_32", "")
                    or values.get("btcommon.eir_ad.entry.service_uuid_32", "")
                )
                uuid_128 = (
                    values.get("btcommon.eir_ad.entry.uuid_128", "")
                    or values.get("btcommon.eir_ad.entry.service_uuid_128", "")
                    or values.get("btcommon.eir_ad.entry.service_uuid", "")
                )
                alt_rssi_str = ""
            else:
                if len(parts) < 11:
                    parts.extend([""] * (11 - len(parts)))

                ts_str = parts[0]
                addr = parts[1]
                initiator_addr = ""
                randomized_tx = parts[2]
                rssi_str = parts[3].split(",")[0]
                alt_rssi_str = parts[10].split(",")[0] if len(parts) > 10 else ""
                channel_str = parts[4].split(",")[0]
                pdu_type_str = parts[5]
                access_address = parts[6]
                company_id = parts[7].split(",")[0] if parts[7] else ""
                manufacturer_data = ""
                device_name = parts[8].split(",")[0] if parts[8] else ""
                uuid_16 = parts[9]
                uuid_32 = ""
                uuid_128 = ""

            # Basic validation
            if not addr or not ts_str:
                return None
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", addr):
                return None

            try:
                ts_epoch = float(ts_str)
            except ValueError:
                ts_epoch = time.time()

            try:
                rssi = int(rssi_str) if rssi_str else None
            except ValueError:
                rssi = None
            if rssi is None and alt_rssi_str:
                try:
                    rssi = int(alt_rssi_str)
                except ValueError:
                    rssi = None

            try:
                channel = int(channel_str)
            except ValueError:
                channel = None

            addr_type = None
            if randomized_tx in ("1", "true", "True"):
                addr_type = "random"
            elif randomized_tx in ("0", "false", "False"):
                addr_type = "public"

            pdu_code, pdu_label = self._parse_pdu_type(pdu_type_str)
            pdu_map = {
                0: "bt_adv_ind",
                1: "bt_adv_direct",
                2: "bt_adv_nonconn",
                3: "bt_adv_scan",
                4: "bt_scan_rsp",
                5: "bt_connection_seen",
                6: "bt_scan_req",
                7: "bt_adv_ext",
            }
            event_type = pdu_map.get(pdu_code, "bt_adv_seen")

            if access_address:
                access_lower = access_address.lower()
                if access_lower not in ("0x8e89bed6", "8e89bed6") and pdu_code != 4:
                    event_type = "bt_connection_seen"

            raw_uuids = []
            raw_uuids.extend(self._split_values(uuid_16))
            raw_uuids.extend(self._split_values(uuid_32))
            raw_uuids.extend(self._split_values(uuid_128))
            services = self._normalize_uuid_list(raw_uuids)

            normalized_company_id = (
                normalize_company_id(company_id) if normalize_company_id else None
            )
            company_name = (
                lookup_company(normalized_company_id) if lookup_company else None
            )
            normalized_mfg = self._normalize_manufacturer_data(manufacturer_data)
            manufacturer_data_hash = (
                hashlib.sha256(normalized_mfg.encode()).hexdigest()
                if normalized_mfg
                else None
            )

            event = {
                "event_type": event_type,
                "protocol": "bt",
                "ts_epoch": ts_epoch,
                "channel": channel or 0,
                "score": 0,
                "dwell_triggered": False,
                "vendor": company_name,
                "keys": {
                    "sa": addr,
                    "da": initiator_addr or None,
                    "bssid": None,
                    "ssid": device_name if device_name else None,
                    "rssi_dbm": rssi,
                },
                "bt": {
                    "addr": addr,
                    "peer_addr": initiator_addr or None,
                    "addr_type": addr_type,
                    "rssi": rssi,
                    "channel": channel,
                    "adv_type": pdu_label or pdu_type_str,
                    "adv_type_code": pdu_code,
                    "access_address": access_address if access_address else None,
                    "company_id": normalized_company_id or (company_id if company_id else None),
                    "company_name": company_name,
                    "local_name": device_name if device_name else None,
                    "service_uuids": services,
                    "manufacturer_data_hash": manufacturer_data_hash,
                },
            }

            return event

        except Exception as e:
            logger.debug(f"BLE Parse error: {e}")
            return None
