
import asyncio
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from fuzzer.core import SimpleAuthFuzzer
from fuzzer.reporter import Reporter
from pathlib import Path
from typing import Optional
import json

app = FastAPI(title="WebAuth Fuzzer - Prototype")

CURRENT_TASK = {"task": None, "status": "idle", "last_result": None}

class StartRequest(BaseModel):
    base_url: str
    login_path: str = "/login"
    username: str = "admin"
    mode: str = "password"
    max_attempts: int = 200

def _run_fuzzer_background(req: StartRequest):
    async def _inner():
        CURRENT_TASK["status"] = "running"
        reporter = Reporter("outputs/results.json")
        f = SimpleAuthFuzzer(
            base_url=req.base_url,
            login_path=req.login_path,
            login_method="POST",
            username_field="username",
            password_field="password",
            username=req.username,
            wordlist_paths=None,
            concurrency=req.concurrency,
            reporter=reporter
        )
        try:
            await f.run(check_path="/", max_attempts=req.max_attempts)
            CURRENT_TASK["status"] = "finished"
            CURRENT_TASK["last_result"] = "outputs/results.json"
        except Exception as e:
            CURRENT_TASK["status"] = f"error: {e}"
    return asyncio.create_task(_inner())

@app.post("/start")
async def start(req: StartRequest, background: BackgroundTasks):
    reporter = Reporter("outputs/results.json")
    f = SimpleAuthFuzzer(base_url=req.base_url, login_path=req.login_path, username=req.username, reporter=reporter)
    async def bg():
        if req.mode=="password":
            await f.run_password_mode(max_attempts=req.max_attempts)
        elif req.mode=="jwt":
            await f.run_jwt_mode(sample_count=req.max_attempts)
        elif req.mode=="fixation":
            await f.run_session_fixation(max_attempts=req.max_attempts)
        else:
            await f.run_password_mode(max_attempts=req.max_attempts)
    background.add_task(bg)
    return {"status":"started", "mode":req.mode}

@app.get("/status")
async def status():
    return {"status": CURRENT_TASK["status"]}

@app.get("/results")
async def results():
    try:
        with open("outputs/results.json", "r", encoding="utf-8") as f:
            return {"path": "outputs/results.json", "content": f.read()}
    except FileNotFoundError:
        return {"path": None, "content": None}

def safe_div(a: int, b: int) -> Optional[float]:
    if b == 0:
        return None
    return a / b

@app.get("/metrics")
async def metrics():
    p = Path("outputs/results.json")
    if not p.exists():
        return {"error": "no results file"}
    data = json.loads(p.read_text(encoding="utf-8"))
    # password mode -> UAR
    pwd = [d for d in data if d.get("mode") == "password"]
    total_pwd = len(pwd)
    success_pwd = sum(1 for x in pwd if x.get("ok"))
    UAR = safe_div(success_pwd, total_pwd)

    # jwt mode -> UAFT
    jwt = [d for d in data if d.get("mode") == "jwt"]
    total_jwt = len(jwt)
    success_jwt = sum(1 for x in jwt if x.get("ok"))
    UAFT = safe_div(success_jwt, total_jwt)

    # fixation -> USFX
    fix = [d for d in data if d.get("mode") in ("fixation", "fix")]
    total_fix = len(fix)
    success_fix = sum(1 for x in fix if x.get("ok"))
    USFX = safe_div(success_fix, total_fix)

    # replay -> URPR
    rep = [d for d in data if d.get("mode") == "replay"]
    total_rep = len(rep)
    success_rep = sum(1 for x in rep if x.get("ok"))
    URPR = safe_div(success_rep, total_rep)

    # logout -> ULIR
    lo = [d for d in data if d.get("mode") == "logout"]
    total_lo = len(lo)
    success_lo = sum(1 for x in lo if x.get("ok"))
    ULIR = safe_div(success_lo, total_lo)

    # UTLA (TTL) — requires fields 'observed_ttl' and 'config_ttl' in records; if absent return null
    ttl_entries = [d for d in data if d.get("mode") == "ttl" and ("observed_ttl" in d and "config_ttl" in d)]
    if ttl_entries:
        # UTLA = mean(1 - |tobs - tcfg| / tcfg)
        vals = []
        for e in ttl_entries:
            tobs = float(e.get("observed_ttl", 0))
            tcfg = float(e.get("config_ttl", 0)) or 1.0
            vals.append(1.0 - abs(tobs - tcfg) / tcfg)
        UTLA = sum(vals) / len(vals)
    else:
        UTLA = None

    return {
        "UAR": UAR,
        "UAR_details": {"total_attempts": total_pwd, "successful": success_pwd},
        "UAFT": UAFT,
        "UAFT_details": {"total_attempts": total_jwt, "successful": success_jwt},
        "USFX": USFX,
        "USFX_details": {"total_attempts": total_fix, "successful": success_fix},
        "URPR": URPR,
        "URPR_details": {"total_attempts": total_rep, "successful": success_rep},
        "ULIR": ULIR,
        "ULIR_details": {"total_attempts": total_lo, "successful": success_lo},
        "UTLA": UTLA,
        "notes": "Metrics computed from outputs/results.json. Fields with null mean insufficient data in results."
    }