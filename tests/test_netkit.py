"""Unit and integration tests for VLSM subnetting, overlaps, and defensive port auditing."""

import asyncio

from fastapi.testclient import TestClient
import pytest

from netkit_guard.models import SubnetRequirement
from netkit_guard.port_auditor import UnauthorizedTargetError, audit_ports
from netkit_guard.subnetting import SubnetError, allocate_vlsm, detect_overlaps, inspect_network
from netkit_guard.web import app


def test_inspect_ipv4_network() -> None:
    info = inspect_network("192.168.10.0/24")
    assert info.network_address == "192.168.10.0"
    assert info.broadcast_address == "192.168.10.255"
    assert info.netmask == "255.255.255.0"
    assert info.usable_hosts == 254
    assert info.is_private is True


def test_vlsm_allocation_is_non_overlapping_and_optimal() -> None:
    plan = allocate_vlsm(
        "192.168.10.0/24",
        [
            SubnetRequirement(name="Enlace", hosts_needed=2),
            SubnetRequirement(name="Ventas", hosts_needed=50),
            SubnetRequirement(name="TI", hosts_needed=20),
        ],
    )
    # Sorted largest first: Ventas (/26), TI (/27), Enlace (/30)
    assert [s.name for s in plan.subnets] == ["Ventas", "TI", "Enlace"]
    assert [s.cidr for s in plan.subnets] == [
        "192.168.10.0/26",
        "192.168.10.64/27",
        "192.168.10.96/30",
    ]
    assert detect_overlaps([s.cidr for s in plan.subnets]) == []


def test_vlsm_overflow_raises_clear_error() -> None:
    with pytest.raises(SubnetError):
        allocate_vlsm(
            "192.168.10.0/28",  # only 16 addresses
            [SubnetRequirement(name="Grande", hosts_needed=20)],
        )


def test_detect_overlaps_finds_conflicting_subnets() -> None:
    overlaps = detect_overlaps(["10.0.0.0/24", "10.0.0.128/25", "10.0.1.0/24"])
    assert len(overlaps) == 1
    assert overlaps[0].network_a == "10.0.0.0/24"
    assert overlaps[0].network_b == "10.0.0.128/25"


def test_port_auditor_detects_local_ephemeral_server_and_blocks_public_ip() -> None:
    async def _run() -> None:
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            report = await audit_ports("127.0.0.1", ports=[port], expected_ports=set())
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == port

            baseline_report = await audit_ports("127.0.0.1", ports=[port], expected_ports={22})
            assert baseline_report.open_ports[0].status == "unexpected"
            assert baseline_report.open_ports[0].severity == "HIGH"

    asyncio.run(_run())

    with pytest.raises(UnauthorizedTargetError):
        asyncio.run(audit_ports("8.8.8.8", ports=[53], allow_external=False))


def test_web_api_blocks_public_ssrf_and_returns_security_headers() -> None:
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.headers["x-frame-options"] == "DENY"

    blocked = client.post("/api/v1/audit-ports", json={"host": "8.8.8.8", "ports": [53]})
    assert blocked.status_code == 403
