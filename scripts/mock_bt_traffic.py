
"""
Dev-only helper to inject synthetic BLE data into SQL for UI testing.

Prefer scripts/mine_bt_pcaps.py for real backfill from captured pcaps.
"""

import random
import time

import pyodbc

from nexus.config import NexusConfig


def get_connection():
    config = NexusConfig.from_env()
    return pyodbc.connect(config.get_sql_connection_string())

VENDORS = [
    ("Apple, Inc.", 0x004C),
    ("Samsung Electronics", 0x0075),
    ("Microsoft", 0x0006),
    ("Fitbit", 0x00F0),
    ("Garmin", 0x07D0),
    ("Nordic Semiconductor", 0x0059),
    ("Tile", 0x01EF),
]

DEVICES = []
for _i in range(20):
    mac = ":".join([f"{random.randint(0, 255):02X}" for _ in range(6)])
    vendor, cid = random.choice(VENDORS)
    name = f"{vendor.split()[0]} Device {random.randint(100, 999)}" if random.random() > 0.3 else None
    DEVICES.append({"addr": mac, "vendor": vendor, "name": name})

def seed_data(conn):
    cursor = conn.cursor()
    print(f"Injecting data for {len(DEVICES)} devices...")

    for device in DEVICES:
        rssi = random.randint(-95, -40)

        # Merge device
        cursor.execute("""
            MERGE bt_devices AS target
            USING (SELECT ? as addr) AS source
            ON (target.addr = source.addr)
            WHEN MATCHED THEN
                UPDATE SET last_seen = SYSDATETIME(), rssi_last = ?, updated_at = SYSDATETIME()
            WHEN NOT MATCHED THEN
                INSERT (addr, vendor, first_seen, last_seen, rssi_last, local_name, device_type)
                VALUES (?, ?, SYSDATETIME(), SYSDATETIME(), ?, ?, 'BLE');
        """, (device["addr"], rssi, device["addr"], device["vendor"], rssi, device["name"]))

        # Insert observation
        cursor.execute("""
            INSERT INTO bt_observations (addr, ts_epoch, rssi, channel, adv_type)
            VALUES (?, ?, ?, ?, 'ADV_IND')
        """, (device["addr"], time.time(), rssi, random.choice([37, 38, 39])))

    conn.commit()
    print("Data batch injected.")

if __name__ == "__main__":
    try:
        conn = get_connection()
        while True:
            seed_data(conn)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}")
