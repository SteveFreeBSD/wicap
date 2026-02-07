import pyodbc

from nexus.config import NexusConfig


def get_connection():
    config = NexusConfig.from_env()
    return pyodbc.connect(config.get_sql_connection_string())


def apply_schema(conn):
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'device_identity_clusters'")
    if not cursor.fetchone():
        cursor.execute(
            """
            CREATE TABLE device_identity_clusters (
                cluster_id CHAR(12) NOT NULL PRIMARY KEY,
                member_count INT NOT NULL,
                confidence FLOAT NOT NULL,
                signals NVARCHAR(MAX),
                updated_at DATETIME2 DEFAULT SYSDATETIME()
            )
            """
        )

    cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'device_identity_members'")
    if not cursor.fetchone():
        cursor.execute(
            """
            CREATE TABLE device_identity_members (
                cluster_id CHAR(12) NOT NULL,
                identifier NVARCHAR(64) NOT NULL,
                protocol VARCHAR(8),
                vendor NVARCHAR(100),
                device_type VARCHAR(32),
                local_name NVARCHAR(128),
                first_seen DATETIME2,
                last_seen DATETIME2,
                CONSTRAINT PK_device_identity_members PRIMARY KEY (cluster_id, identifier)
            )
            """
        )

    cursor.execute(
        """
        IF NOT EXISTS (
            SELECT 1 FROM sys.indexes
            WHERE name = 'IX_identity_members_identifier' AND object_id = OBJECT_ID('device_identity_members')
        )
        CREATE INDEX IX_identity_members_identifier ON device_identity_members(identifier);
        """
    )

    conn.commit()


if __name__ == "__main__":
    conn = get_connection()
    try:
        apply_schema(conn)
    finally:
        conn.close()
