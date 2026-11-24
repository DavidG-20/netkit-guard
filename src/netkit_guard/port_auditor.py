"""Defensive async TCP port auditor with loopback/private network guardrails."""

import asyncio
import ipaddress
import socket

from netkit_guard.models import PortAuditReport, PortFinding

COMMON_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

DEFAULT_PORTS: list[int] = sorted(COMMON_SERVICES.keys())


class UnauthorizedTargetError(ValueError):
    """Raised when attempting to audit a non-private host without explicit permission."""


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_safe_internal_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Allow only loopback or true RFC1918 LAN addresses (blocks 169.254.169.254 metadata & 0.0.0.0)."""
    if ip_obj.is_unspecified or ip_obj.is_link_local or ip_obj.is_multicast:
        return False
    if ip_obj.is_loopback:
        return True
    return isinstance(ip_obj, ipaddress.IPv4Address) and any(
        ip_obj in net for net in RFC1918_NETWORKS
    )


def resolve_and_validate_host(host: str, allow_external: bool = False) -> str:
    """Resolve host to an IP address and enforce private/loopback restriction by default."""
    cleaned = host.strip()
    if not cleaned:
        raise UnauthorizedTargetError("Debes indicar un host o dirección IP válida.")

    try:
        ip_str = socket.gethostbyname(cleaned)
        ip_obj = ipaddress.ip_address(ip_str)
    except (OSError, ValueError) as exc:
        raise UnauthorizedTargetError(f"No se pudo resolver el host '{cleaned}': {exc}") from exc

    if not allow_external and not _is_safe_internal_ip(ip_obj):
        raise UnauthorizedTargetError(
            f"Objetivo '{cleaned}' ({ip_str}) bloqueado por seguridad: solo se permiten "
            "hosts loopback (127.0.0.0/8) o redes privadas LAN (RFC1918) por defecto."
        )
    return ip_str


async def _probe_port(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> bool:
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False


async def audit_ports(
    host: str,
    ports: list[int] | None = None,
    expected_ports: set[int] | None = None,
    timeout: float = 0.5,
    max_concurrency: int = 100,
    allow_external: bool = False,
) -> PortAuditReport:
    """Concurrently probe TCP ports and compare open ports against an optional baseline."""
    resolved_ip = resolve_and_validate_host(host, allow_external=allow_external)
    target_ports = sorted({p for p in (ports or DEFAULT_PORTS) if 1 <= p <= 65535})
    expected = expected_ports or set()

    semaphore = asyncio.Semaphore(max_concurrency)
    results = await asyncio.gather(
        *[_probe_port(resolved_ip, port, timeout, semaphore) for port in target_ports]
    )

    open_findings: list[PortFinding] = []
    open_set: set[int] = set()
    for port, is_open in zip(target_ports, results, strict=True):
        if not is_open:
            continue
        open_set.add(port)
        is_expected = not expected or port in expected
        open_findings.append(
            PortFinding(
                port=port,
                service=COMMON_SERVICES.get(port, "Desconocido"),
                status="expected" if is_expected else "unexpected",
                severity="OK" if is_expected else "HIGH",
            )
        )

    missing_expected = sorted(expected - open_set) if expected else []
    return PortAuditReport(
        host=host,
        resolved_ip=resolved_ip,
        scanned_ports=len(target_ports),
        open_ports=open_findings,
        missing_expected_ports=missing_expected,
    )
