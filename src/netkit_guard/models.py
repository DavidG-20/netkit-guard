"""Typed data models for subnetting, VLSM plans, overlaps, and port audits."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class NetworkInfo:
    """Detailed CIDR breakdown for an IPv4 network."""

    cidr: str
    network_address: str
    broadcast_address: str
    netmask: str
    wildcard_mask: str
    prefix_length: int
    total_addresses: int
    usable_hosts: int
    first_usable: str
    last_usable: str
    is_private: bool


@dataclass(frozen=True)
class SubnetRequirement:
    """Named host requirement for VLSM allocation."""

    name: str
    hosts_needed: int


@dataclass(frozen=True)
class AllocatedSubnet:
    """Single subnet allocated by the VLSM engine."""

    name: str
    hosts_needed: int
    cidr: str
    netmask: str
    network_address: str
    first_usable: str
    last_usable: str
    broadcast_address: str
    usable_hosts: int
    wasted_hosts: int


@dataclass
class VLSMPlan:
    """Complete VLSM addressing plan for a base CIDR block."""

    base_cidr: str
    total_base_addresses: int
    allocated_addresses: int
    unused_addresses: int
    utilization_percent: float
    subnets: list[AllocatedSubnet] = field(default_factory=list)


@dataclass(frozen=True)
class OverlapPair:
    """Two CIDR networks that share overlapping IP addresses."""

    network_a: str
    network_b: str


@dataclass(frozen=True)
class PortFinding:
    """Result of auditing a single open TCP port."""

    port: int
    service: str
    status: str  # expected | unexpected
    severity: str  # OK | HIGH


@dataclass
class PortAuditReport:
    """Summary of an async TCP port audit against an optional baseline."""

    host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: list[PortFinding] = field(default_factory=list)
    missing_expected_ports: list[int] = field(default_factory=list)
