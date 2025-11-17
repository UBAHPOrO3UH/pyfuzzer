from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid
import time
import asyncio
from fuzzer.engine import run_scan

app = FastAPI()
scans = {}  # in-memory

class StartScan(BaseModel):
    target: str
    base_url: str

@app.post("/scan/start")
async def start_scan(req: StartScan):
    scan_id = str(uuid.uuid4())

    scans[scan_id] = {"status": "running", "started": time.time()}

    asyncio.create_task(
        run_scan(scan_id, req.target, req.base_url)
    )

    return {"scan_id": scan_id, "status": "started"}

@app.get("/scan/{scan_id}/status")
def status(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404)
    return scans[scan_id]

@app.get("/scan/{scan_id}/report")
def report(scan_id: str):
    import os, json
    p = f"reports/{scan_id}.json"
    if not os.path.exists(p):
        raise HTTPException(404)
    return json.load(open(p))
