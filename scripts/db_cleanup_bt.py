
import pyodbc

from nexus.config import NexusConfig


def get_connection():
    config = NexusConfig.from_env()
    return pyodbc.connect(config.get_sql_connection_string())

def clear_data():
    conn = get_connection()
    cursor = conn.cursor()

    print("Clearing bt_observations...")
    cursor.execute("TRUNCATE TABLE bt_observations")

    print("Clearing bt_devices...")
    cursor.execute("DELETE FROM bt_devices") # DELETE because referenced? No FKs yet, but safer.

    conn.commit()
    conn.close()
    print("Bluetooth data cleared.")

if __name__ == "__main__":
    try:
        clear_data()
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
