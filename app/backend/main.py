import os
import time
import threading
import psutil
import logging
import uuid

import psycopg2
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from models import Incident

app = FastAPI(title="Aegis Orders API")

logging.basicConfig(
    filename="logs/aegis.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("aegis")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time

    logger.info(
        "HTTP %s %s status=%s duration=%.3fs",
        request.method,
        request.url.path,
        response.status_code,
        duration,
    )

    return response

#  Metrics for Prometheus

request_count = Counter(
    "aegis_http_requests_total",
    "Total number of HTTP requests"
)

cpu_usage = Gauge(
    "aegis_cpu_usage_percent",
    "Aegis backend CPU usage percentage"
)

request_latency = Histogram(
    "aegis_http_request_duration_seconds",
    "HTTP request duration in seconds"
)

error_count = Counter(
    "aegis_http_errors_total",
    "Total number of HTTP 4xx and 5xx responses"
)

process = psutil.Process()

def update_cpu_usage():
    while True:
        cpu_usage.set(process.cpu_percent(interval=1))


threading.Thread(
    target=update_cpu_usage,
    daemon=True
).start()

@app.middleware("http")
async def count_requests(request, call_next):
    request_count.inc()

    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time
    request_latency.observe(duration)

    if response.status_code >= 400:
        error_count.inc()

    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=os.getenv("DB_PORT", "5433"),
        database=os.getenv("DB_NAME", "aegi"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres"),
        connect_timeout=5,
    )


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/ready")
def readiness():
    try:
        connection = get_db_connection()
        connection.close()
        return {"status": "ready", "database": "connected"}
    except Exception:
        return {"status": "not_ready", "database": "unavailable"}


@app.get("/orders")
def get_orders():
    connection = get_db_connection()

    cursor = connection.cursor()
    cursor.execute("SELECT id, status FROM orders ORDER BY id")

    orders = [
        {"id": row[0], "status": row[1]}
        for row in cursor.fetchall()
    ]

    cursor.close()
    connection.close()

    return {"orders": orders}

@app.get("/metrics")
def metrics():
    return Response(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
    
@app.get("/cpu-load")
def cpu_load(seconds: int = 30):
    end_time = time.time() + seconds

    while time.time() < end_time:
        _ = 12345 * 67890

    return {
        "status": "completed",
        "duration": seconds
    }
    
@app.get("/slow")
def slow_request(seconds: int = 5):
    time.sleep(seconds)

    return {
        "status": "completed",
        "duration": seconds
    }
    
memory_hogs = []

@app.get("/memory-load")
def memory_load(mb: int = 100):
    data = bytearray(mb * 1024 * 1024)
    memory_hogs.append(data)

    return {
        "status": "allocated",
        "memory_mb": mb,
        "total_allocated_mb": len(memory_hogs) * mb
    }
    
@app.post("/alerts")
async def receive_alert(request: Request):
    alert_data = await request.json()

    alert = alert_data["alerts"][0]
    print("🚨 ALERT PAYLOAD:")
    print(alert)
    fingerprint = alert["fingerprint"]

    conn = get_db_connection()
    cursor = conn.cursor()

    if alert["status"] == "firing":

        # Check whether this alert already has an active incident
        cursor.execute(
            """
            SELECT incident_id
            FROM incidents
            WHERE alert_fingerprint = %s
              AND status = 'firing'
            LIMIT 1
            """,
            (fingerprint,),
        )

        existing = cursor.fetchone()

        if existing:
            incident_id = existing[0]
        else:
            incident_id = str(uuid.uuid4())

            cursor.execute(
                """
                INSERT INTO incidents (
                    incident_id,
                    alert_fingerprint,
                    alert_name,
                    incident_type,
                    severity,
                    service,
                    status,
                    started_at,
                    description
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    incident_id,
                    fingerprint,
                    alert["labels"]["alertname"],
                    alert["labels"]["incident_type"],
                    alert["labels"]["severity"],
                    alert["labels"]["instance"],
                    alert["status"],
                    alert["startsAt"],
                    alert["annotations"]["description"],
                ),
            )

    else:
        # Resolve the currently active incident for this alert
        cursor.execute(
            """
            UPDATE incidents
            SET status = %s
            WHERE alert_fingerprint = %s
              AND status = 'firing'
            """,
            (
                alert["status"],
                fingerprint,
            ),
        )

        cursor.execute(
            """
            SELECT incident_id
            FROM incidents
            WHERE alert_fingerprint = %s
            ORDER BY started_at DESC
            LIMIT 1
            """,
            (fingerprint,),
        )

        existing = cursor.fetchone()
        incident_id = existing[0] if existing else str(uuid.uuid4())

    conn.commit()
    cursor.close()
    conn.close()

    incident = Incident(
        incident_id=incident_id,
        alert_name=alert["labels"]["alertname"],
        incident_type=alert["labels"]["incident_type"],
        severity=alert["labels"]["severity"],
        service=alert["labels"]["instance"],
        status=alert["status"],
        started_at=alert["startsAt"],
        description=alert["annotations"]["description"],
    )

    print("🚨 Aegis Incident:")
    print(incident.model_dump())

    return {
        "status": "received",
        "incident": incident.model_dump(),
    }
    
@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            incident_id,
            alert_name,
            incident_type,
            severity,
            service,
            status,
            started_at,
            description
        FROM incidents
        WHERE incident_id = %s
        """,
        (incident_id,),
    )

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "incident_id": row[0],
        "alert_name": row[1],
        "incident_type": row[2],
        "severity": row[3],
        "service": row[4],
        "status": row[5],
        "started_at": row[6],
        "description": row[7],
    }