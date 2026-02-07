
from app.services.state import get_db_connection

try:
    conn = get_db_connection()
    cursor = conn.cursor()

    print("--- Debugging Network Map Data ---")

    # Check Time
    cursor.execute("SELECT GETDATE(), GETUTCDATE()")
    row = cursor.fetchone()
    print(f"Server Time (Local): {row[0]}")
    print(f"Server Time (UTC):   {row[1]}")

    # Check Max Inserted At
    cursor.execute("SELECT MAX(inserted_at) FROM curated_events")
    max_time = cursor.fetchone()[0]
    print(f"Latest Event Time:   {max_time}")

    # Check Event Types Distribution
    print("\n--- Event Types Distribution (Last 60m) ---")
    cursor.execute(
        """
        SELECT event_type, COUNT(*)
        FROM curated_events
        WHERE inserted_at > DATEADD(minute, -60, GETDATE())
        GROUP BY event_type
    """
    )
    for row in cursor.fetchall():
        print(f"{row[0]}: {row[1]}")

    # Check Sample Payload for 'new_bssid' or 'open_network'
    print("\n--- Sample 'new_bssid' Payload ---")
    cursor.execute("SELECT TOP 1 payload FROM curated_events WHERE event_type='new_bssid'")
    row = cursor.fetchone()
    if row:
        print(row[0])

    print("\n--- Sample 'probe' Payload ---")
    cursor.execute("SELECT TOP 1 payload FROM curated_events WHERE event_type='probe'")
    row = cursor.fetchone()
    if row:
        print(row[0])

    print("\n--- Sample 'strong_rssi' Payload ---")
    cursor.execute("SELECT TOP 1 payload FROM curated_events WHERE event_type='strong_rssi'")
    row = cursor.fetchone()
    if row:
        print(row[0])

    conn.close()
except Exception as exc:
    print(f"Error: {exc}")
