from pydantic import BaseModel
from typing import Optional


class Incident(BaseModel):
    incident_id: str
    alert_name: str
    incident_type: str
    severity: str
    service: str
    status: str
    started_at: str
    description: Optional[str] = None