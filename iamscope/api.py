from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from iamscope.engine import analyze_policy, diff_policies

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
app = FastAPI(title="IAMScope API", version="0.2.0", description="Offline IAM policy risk analysis. No AWS credentials or cloud calls.")
app.mount("/assets", StaticFiles(directory=WEB), name="assets")


class AnalyzeRequest(BaseModel):
    policy: dict[str, Any]
    policy_name: str = Field(default="pasted-policy", max_length=120)


class DiffRequest(BaseModel):
    before: dict[str, Any]
    after: dict[str, Any]


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "IAMScope API", "version": "0.2.0", "mode": "offline-static-analysis"}


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    try:
        return analyze_policy(request.policy, policy_name=request.policy_name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/diff")
def diff(request: DiffRequest) -> dict[str, Any]:
    try:
        return diff_policies(request.before, request.after)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(WEB / "index.html")
