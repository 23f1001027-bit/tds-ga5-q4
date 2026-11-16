"""
Agent-harness safety layer (deterministic, rule-based).

POST /classify   {profile, batchId, policy, cases:[...]}  ->  {profile, batchId, results:[...]}
GET  /classify   classifier configuration (kept available for Check/Save)
GET  /dump       every batch received since start (for offline analysis)
"""
import json
import os
import re
import time
from collections import deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

VERSION = "rules-v2"
app = FastAPI(title="agent-harness-safety")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
CAPTURE: deque = deque(maxlen=40)


from rules import decide, OPTS  # noqa: E402


# ----------------------------------------------------------------------------- HTTP
CONFIG = {"name": "agent-harness-safety", "version": VERSION, "method": "deterministic rules over user messages, "
          "resolved tool metadata, isolation facts, preflight/rollback observations",
          "profile": "agent-harness-2026-09", "route": "POST /classify", "options": OPTS}


@app.get("/")
@app.get("/classify")
def config():
    return CONFIG


@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/dump")
def dump():
    return list(CAPTURE)


@app.post("/")
@app.post("/classify")
async def classify(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    cases = body.get("cases") or []
    results = []
    for c in cases:
        try:
            results.append(decide(c))
        except Exception as e:  # never drop a case
            print("ERROR", c.get("caseId"), repr(e), flush=True)
            results.append({"caseId": c.get("caseId"), "requestDecision": "review",
                            "toolDecision": "review" if c.get("proposedTool") else "none",
                            "route": "primary", "trajectory": "watch"})
    out = {"profile": body.get("profile", "agent-harness-2026-09"), "batchId": body.get("batchId"),
           "results": results}
    CAPTURE.append({"t": time.strftime("%H:%M:%S"), "request": body, "response": out})
    print("BATCH", body.get("batchId"), len(cases), flush=True)
    return JSONResponse(out)
