

import pyodbc

from nexus.config import NexusConfig


def get_connection():
    config = NexusConfig.from_env()
    return pyodbc.connect(config.get_sql_connection_string())

def apply_schema(conn):
    cursor = conn.cursor()

    print("Checking bt_devices...")
    cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'bt_devices'")
    if not cursor.fetchone():
        print("Creating bt_devices table...")
        cursor.execute("""
            CREATE TABLE bt_devices (
                addr CHAR(17) NOT NULL PRIMARY KEY,
                addr_type VARCHAR(16),
                vendor NVARCHAR(100),
                device_type VARCHAR(32),
                first_seen DATETIME2 DEFAULT SYSDATETIME(),
                last_seen DATETIME2 DEFAULT SYSDATETIME(),
                rssi_avg INT,
                rssi_max INT,
                rssi_last INT,
                rssi_sample_count INT DEFAULT 0,
                rssi_last_seen DATETIME2,
                services NVARCHAR(MAX),
                local_name NVARCHAR(128),
                manufacturer_data_hash CHAR(64),
                updated_at DATETIME2 DEFAULT SYSDATETIME()
            )
        """)
    else:
        print("bt_devices already exists.")

    print("Checking bt_observations...")
    cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'bt_observations'")
    if not cursor.fetchone():
        print("Creating bt_observations table...")
        cursor.execute("""
            CREATE TABLE bt_observations (
                id BIGINT IDENTITY PRIMARY KEY,
                addr CHAR(17) NOT NULL,
                sensor_id CHAR(8),
                ts_epoch DECIMAL(19,9) NOT NULL,
                rssi INT,
                channel INT,
                adv_type VARCHAR(32),
                company_id CHAR(6),
                service_uuids NVARCHAR(MAX),
                local_name NVARCHAR(128),
                inserted_at DATETIME2 DEFAULT SYSDATETIME()
            )
        """)
        cursor.execute("CREATE INDEX IX_bt_observations_addr ON bt_observations(addr, ts_epoch DESC)")
        cursor.execute("CREATE INDEX IX_bt_observations_time ON bt_observations(ts_epoch)")
    else:
        print("bt_observations already exists.")

    conn.commit()
    print("Schema migration complete.")

if __name__ == "__main__":
    try:
        conn = get_connection()
        apply_schema(conn)
        conn.close()
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
