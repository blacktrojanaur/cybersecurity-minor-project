"""
testbed/resource_app – Protected resource application  (port 8090)
===================================================================
Simulates an internal application with 4 protected segments:
  /hr        – HR records (only hr_manager, sysadmin)
  /finance   – Finance data (analyst, finance_lead, sysadmin)
  /code      – Source code (developer, sysadmin)
  /admin     – Admin panel (sysadmin only)

Every request is checked against M2's enforcement API (PEP).
Deny/restrict decisions return 403/401 with explanation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.logging_utils import get_logger
from common.auth import service_token_headers
from common.config import get_settings

log = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title="Protected Resource App",
    description="Simulated internal resources with M2 enforcement on every request.",
    version="1.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Synthetic resource data ───────────────────────────────────────────────────

_RESOURCES = {
    "/hr": {"name": "HR Records", "sensitivity": "high",
             "records": [{"id": 1, "name": "Employee A", "dept": "Engineering"},
                         {"id": 2, "name": "Employee B", "dept": "Finance"}]},
    "/hr/records": {"name": "HR Detail Records", "sensitivity": "high",
                    "records": [{"employee_id": "EMP001", "salary_band": "L4"}]},
    "/hr/payroll": {"name": "Payroll Data", "sensitivity": "critical",
                    "records": [{"month": "2024-06", "total_processed": 1500000}]},
    "/hr/org-chart": {"name": "Org Chart", "sensitivity": "low",
                      "records": [{"dept": "Engineering", "head": "alice"}]},
    "/finance": {"name": "Finance Overview", "sensitivity": "high",
                 "records": [{"q": "Q2-2024", "revenue": 50000000}]},
    "/finance/reports": {"name": "Finance Reports", "sensitivity": "high",
                         "records": [{"report": "Annual", "year": 2023}]},
    "/finance/audit": {"name": "Finance Audit Trail", "sensitivity": "critical",
                       "records": [{"audit_id": "AUD-001", "status": "clean"}]},
    "/code": {"name": "Source Code", "sensitivity": "medium",
              "records": [{"repo": "platform", "commits": 1247}]},
    "/code/repo-a": {"name": "Repo A", "sensitivity": "medium",
                     "records": [{"file": "main.py", "lines": 500}]},
    "/code/repo-b": {"name": "Repo B", "sensitivity": "medium",
                     "records": [{"file": "api.py", "lines": 300}]},
    "/admin": {"name": "Admin Panel", "sensitivity": "critical",
               "records": [{"setting": "max_sessions", "value": 1000}]},
}


# ── M2 PEP check ─────────────────────────────────────────────────────────────

_USER_ROLES = {
    "alice": "developer",
    "bob": "analyst",
    "carol": "hr_manager",
    "dave": "sysadmin",
    "eve": "viewer",
    "frank": "developer",
    "grace": "finance_lead",
    "henry": "viewer",
    "iris": "developer",
}


def _extract_bearer(authorization: str) -> str:
    """Extract session_id from 'Authorization: Bearer <session_id>' header."""
    if authorization.startswith("Bearer "):
        return authorization[7:].strip()
    return ""


def _resolve_role(session_id: str, header_role: str) -> str:
    """Resolve effective role from explicit header or inferred user session."""
    if header_role and header_role != "viewer":
        return header_role
    parts = session_id.split("-")
    if len(parts) >= 2:
        uid = parts[1]
        if uid in _USER_ROLES:
            return _USER_ROLES[uid]
    return header_role or "viewer"


async def _enforce(session_id: str, resource_path: str, user_role: str) -> dict[str, Any]:
    """Call M2 /policy/enforce and return the enforcement result."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.post(
                f"{settings.m2_url}/policy/enforce",
                json={"session_id": session_id, "resource_path": resource_path,
                      "user_role": user_role},
                headers=service_token_headers(),
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("m2_enforce_failed", error=str(exc))
        # Fail-closed: deny on M2 unavailability
        return {"decision": "deny", "reason": "Policy enforcement unavailable; failing closed."}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "resource_app", "version": "1.0.0"}


@app.get("/hr")
@app.get("/hr/{path:path}")
async def hr_resource(
    request: Request,
    path: str = "",
    x_session_id: str = Header(default=""),
    authorization: str = Header(default=""),
    x_user_role: str = Header(default="viewer"),
) -> dict[str, Any]:
    session_id = x_session_id or _extract_bearer(authorization)
    resource_path = "/hr" + (f"/{path}" if path else "")
    return await _serve_resource(resource_path, session_id, x_user_role)


@app.get("/finance")
@app.get("/finance/{path:path}")
async def finance_resource(
    request: Request,
    path: str = "",
    x_session_id: str = Header(default=""),
    authorization: str = Header(default=""),
    x_user_role: str = Header(default="viewer"),
) -> dict[str, Any]:
    session_id = x_session_id or _extract_bearer(authorization)
    resource_path = "/finance" + (f"/{path}" if path else "")
    return await _serve_resource(resource_path, session_id, x_user_role)


@app.get("/code")
@app.get("/code/{path:path}")
async def code_resource(
    request: Request,
    path: str = "",
    x_session_id: str = Header(default=""),
    authorization: str = Header(default=""),
    x_user_role: str = Header(default="viewer"),
) -> dict[str, Any]:
    session_id = x_session_id or _extract_bearer(authorization)
    resource_path = "/code" + (f"/{path}" if path else "")
    return await _serve_resource(resource_path, session_id, x_user_role)


@app.get("/admin")
@app.get("/admin/{path:path}")
async def admin_resource(
    request: Request,
    path: str = "",
    x_session_id: str = Header(default=""),
    authorization: str = Header(default=""),
    x_user_role: str = Header(default="viewer"),
) -> dict[str, Any]:
    session_id = x_session_id or _extract_bearer(authorization)
    resource_path = "/admin" + (f"/{path}" if path else "")
    return await _serve_resource(resource_path, session_id, x_user_role)


async def _serve_resource(
    resource_path: str, session_id: str, user_role: str
) -> dict[str, Any]:
    if not session_id:
        raise HTTPException(status_code=401, detail="Missing session token or X-Session-Id header.")

    effective_role = _resolve_role(session_id, user_role)
    enforcement = await _enforce(session_id, resource_path, effective_role)
    decision = enforcement.get("decision", "deny")

    if decision == "deny":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Access denied",
                "reason": enforcement.get("reason", "Policy decision: deny"),
                "session_id": session_id,
                "resource": resource_path,
            },
        )
    if decision == "step_up":
        raise HTTPException(
            status_code=401,
            detail={
                "error": "MFA required",
                "reason": enforcement.get("reason", "Step-up authentication required"),
                "session_id": session_id,
                "resource": resource_path,
            },
        )

    # Find closest matching resource
    resource = None
    for prefix in sorted(_RESOURCES.keys(), key=len, reverse=True):
        if resource_path.startswith(prefix):
            resource = _RESOURCES[prefix]
            break

    if not resource:
        raise HTTPException(status_code=404, detail=f"Resource '{resource_path}' not found.")

    # For restrict decisions: return metadata only (no data)
    if decision == "restrict":
        return {
            "resource": resource_path,
            "name": resource["name"],
            "sensitivity": resource["sensitivity"],
            "decision": "restrict",
            "data": None,
            "notice": "Access restricted to read-only metadata. Full data requires compliant session.",
        }

    return {
        "resource": resource_path,
        "name": resource["name"],
        "sensitivity": resource["sensitivity"],
        "decision": "allow",
        "data": resource["records"],
    }
