"""FastAPI web API and interactive UI for netkit-guard (strictly private/loopback audits)."""

from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from netkit_guard import __version__
from netkit_guard.models import SubnetRequirement
from netkit_guard.port_auditor import DEFAULT_PORTS, UnauthorizedTargetError, audit_ports
from netkit_guard.subnetting import SubnetError, allocate_vlsm, detect_overlaps, inspect_network

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="netkit-guard",
    version=__version__,
    description="Suite web de Subnetting/VLSM, detección de solapamientos y auditoría local de puertos TCP.",
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


class VLSMRequirementIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    hosts_needed: int = Field(ge=1, le=16_000_000)


class VLSMRequest(BaseModel):
    base_cidr: str
    requirements: list[VLSMRequirementIn] = Field(min_length=1, max_length=64)


class OverlapsRequest(BaseModel):
    cidrs: list[str] = Field(min_length=2, max_length=64)


class PortAuditRequest(BaseModel):
    host: str = Field(default="127.0.0.1", min_length=1, max_length=120)
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS), max_length=128)
    expected_ports: list[int] = Field(default_factory=list, max_length=128)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "netkit-guard", "version": __version__}


@app.get("/api/v1/network-info")
def api_network_info(cidr: str) -> dict:
    try:
        return asdict(inspect_network(cidr))
    except SubnetError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/vlsm")
def api_vlsm(payload: VLSMRequest) -> dict:
    reqs = [SubnetRequirement(name=r.name, hosts_needed=r.hosts_needed) for r in payload.requirements]
    try:
        return asdict(allocate_vlsm(payload.base_cidr, reqs))
    except SubnetError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/overlaps")
def api_overlaps(payload: OverlapsRequest) -> dict:
    try:
        pairs = detect_overlaps(payload.cidrs)
    except SubnetError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"overlaps": [asdict(p) for p in pairs], "has_overlaps": len(pairs) > 0}


@app.post("/api/v1/audit-ports")
async def api_audit_ports(payload: PortAuditRequest) -> dict:
    """Strictly restricted to loopback and RFC1918 private hosts to prevent SSRF."""
    try:
        report = await audit_ports(
            host=payload.host,
            ports=payload.ports,
            expected_ports=set(payload.expected_ports),
            timeout=0.5,
            allow_external=False,
        )
    except UnauthorizedTargetError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return asdict(report)


@app.get("/", include_in_schema=False)
def serve_ui() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
