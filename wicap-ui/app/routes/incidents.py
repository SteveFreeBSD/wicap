
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import app.services.state as state

router = APIRouter()

# --- Schemas ---

class IncidentSummary(BaseModel):
    incident_id: str
    title: str
    status: str
    severity: int
    alert_count: int
    first_seen: str
    last_seen: str

class IncidentDetail(IncidentSummary):
    description: str | None
    alerts: list[dict] = []

# --- Endpoints ---

@router.get("/api/incidents", response_model=list[IncidentSummary])
async def list_incidents(
    status: str = Query("active", pattern="^(active|resolved|archived|all)$"),
    limit: int = 50
):
    """List incidents, filtered by status."""
    conn = state.get_db_connection()
    cursor = conn.cursor()

    try:
        sql = """
        SELECT TOP (?)
            incident_id, title, status, severity, alert_count, first_seen, last_seen
        FROM incidents
        """
        params = [limit]

        if status != "all":
            sql += " WHERE status = ?"
            params.append(status)

        sql += " ORDER BY last_seen DESC"

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        return [
            {
                "incident_id": r[0],
                "title": r[1],
                "status": r[2],
                "severity": r[3],
                "alert_count": r[4],
                "first_seen": str(r[5]),
                "last_seen": str(r[6]),
            }
            for r in rows
        ]
    finally:
        conn.close()

@router.get("/api/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: str):
    """Get incident details and contained alerts."""
    conn = state.get_db_connection()
    cursor = conn.cursor()

    try:
        # 1. Fetch Incident
        cursor.execute("""
            SELECT incident_id, title, status, severity, alert_count, first_seen, last_seen, description
            FROM incidents
            WHERE incident_id = ?
        """, [incident_id])
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident = {
            "incident_id": row[0],
            "title": row[1],
            "status": row[2],
            "severity": row[3],
            "alert_count": row[4],
            "first_seen": str(row[5]),
            "last_seen": str(row[6]),
            "description": row[7],
            "alerts": []
        }

        # 2. Fetch Alerts
        cursor.execute("""
            SELECT TOP 100
                alert_id, alert_type, title, severity, ts_epoch, source_mac, description
            FROM attack_alerts
            WHERE incident_id = ?
            ORDER BY ts_epoch DESC
        """, [incident_id])

        incident["alerts"] = [
            {
                "alert_id": r[0],
                "alert_type": r[1],
                "title": r[2],
                "severity": r[3],
                "ts_epoch": r[4],
                "source_mac": r[5],
                "description": r[6]
            }
            for r in cursor.fetchall()
        ]

        return incident
    finally:
        conn.close()

@router.post("/api/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str):
    """Mark an incident as resolved."""
    conn = state.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE incidents
            SET status = 'resolved', updated_at = SYSDATETIME()
            WHERE incident_id = ?
        """, [incident_id])
        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Incident not found")

        return {"status": "resolved", "incident_id": incident_id}
    finally:
        conn.close()
