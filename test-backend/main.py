from fastapi import FastAPI, WebSocket
from pydantic import BaseModel
from typing import List
import asyncio

app = FastAPI()

# In-memory storage (for hackathon)
alerts = []
clients = []

# -------- DATA MODEL --------
class Telemetry(BaseModel):
    process: str
    file_writes: int
    entropy: float
    api_calls: List[str]
    timestamp: str


# -------- DETECTION LOGIC --------
def detect_threat(data: Telemetry):
    score = 0
    reasons = []

    # Rule 1: High entropy
    if data.entropy > 7.5:
        score += 50
        reasons.append("High entropy detected")

    # Rule 2: Mass file writes
    if data.file_writes > 50:
        score += 40
        reasons.append("Mass file modification")

    # Rule 3: Suspicious API pattern
    if "NtWriteFile" in data.api_calls:
        score += 20
        reasons.append("Suspicious API usage")

    return score, reasons


# -------- API ENDPOINT --------
@app.post("/ingest")
async def ingest(data: Telemetry):
    score, reasons = detect_threat(data)

    alert = {
        "process": data.process,
        "score": score,
        "reasons": reasons,
        "timestamp": data.timestamp
    }

    # Save alert if suspicious
    if score > 50:
        alerts.append(alert)

        # Send to dashboard (WebSocket clients)
        for client in clients:
            await client.send_json(alert)

    return {"status": "ok", "score": score}


# -------- GET ALERTS --------
@app.get("/alerts")
def get_alerts():
    return alerts


# -------- WEBSOCKET (REAL-TIME DASHBOARD) --------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)

    try:
        while True:
            await asyncio.sleep(1)
    except:
        clients.remove(websocket)