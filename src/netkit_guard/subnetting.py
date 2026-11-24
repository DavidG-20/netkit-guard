"""IPv4 CIDR inspection, VLSM subnet allocation, and overlap detection engine."""

import ipaddress
import math

from netkit_guard.models import (
    AllocatedSubnet,
    NetworkInfo,
    OverlapPair,
    SubnetRequirement,
    VLSMPlan,
)


class SubnetError(ValueError):
    """Raised on invalid CIDR input or insufficient address space for VLSM."""


def _parse_ipv4_network(cidr: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise SubnetError(f"Red IPv4 CIDR inválida '{cidr}': {exc}") from exc


def inspect_network(cidr: str) -> NetworkInfo:
    """Return full IPv4 network details for a given CIDR."""
    net = _parse_ipv4_network(cidr)
    total = net.num_addresses
    if net.prefixlen == 32:
        usable = 1
        first_usable = str(net.network_address)
        last_usable = str(net.network_address)
    elif net.prefixlen == 31:
        usable = 2
        first_usable = str(net.network_address)
        last_usable = str(net.broadcast_address)
    else:
        usable = max(0, total - 2)
        first_usable = str(net.network_address + 1)
        last_usable = str(net.broadcast_address - 1)

    return NetworkInfo(
        cidr=str(net),
        network_address=str(net.network_address),
        broadcast_address=str(net.broadcast_address),
        netmask=str(net.netmask),
        wildcard_mask=str(net.hostmask),
        prefix_length=net.prefixlen,
        total_addresses=total,
        usable_hosts=usable,
        first_usable=first_usable,
        last_usable=last_usable,
        is_private=net.is_private,
    )


def _prefix_for_hosts(hosts_needed: int) -> int:
    if hosts_needed < 1:
        raise SubnetError("El número de hosts requeridos debe ser al menos 1.")
    total_needed = hosts_needed + 2  # network + broadcast
    host_bits = math.ceil(math.log2(total_needed))
    prefix = 32 - host_bits
    if prefix < 0:
        raise SubnetError(f"Demasiados hosts solicitados ({hosts_needed}) para IPv4.")
    return prefix


def allocate_vlsm(base_cidr: str, requirements: list[SubnetRequirement]) -> VLSMPlan:
    """Allocate non-overlapping subnets inside base_cidr using VLSM (largest first)."""
    if not requirements:
        raise SubnetError("Debes indicar al menos un requisito de subred.")

    base = _parse_ipv4_network(base_cidr)
    sorted_reqs = sorted(requirements, key=lambda r: r.hosts_needed, reverse=True)

    current_ip = int(base.network_address)
    end_ip = int(base.broadcast_address)
    allocated: list[AllocatedSubnet] = []
    allocated_total = 0

    for req in sorted_reqs:
        prefix = _prefix_for_hosts(req.hosts_needed)
        block_size = 1 << (32 - prefix)

        # Align current_ip to the block boundary
        if current_ip % block_size != 0:
            current_ip += block_size - (current_ip % block_size)

        if current_ip + block_size - 1 > end_ip:
            raise SubnetError(
                f"Espacio insuficiente en {base} para asignar '{req.name}' "
                f"({req.hosts_needed} hosts, requiere /{prefix})."
            )

        subnet = ipaddress.IPv4Network((current_ip, prefix))
        usable = max(0, subnet.num_addresses - 2)
        allocated.append(
            AllocatedSubnet(
                name=req.name.strip() or "Subred",
                hosts_needed=req.hosts_needed,
                cidr=str(subnet),
                netmask=str(subnet.netmask),
                network_address=str(subnet.network_address),
                first_usable=str(subnet.network_address + 1),
                last_usable=str(subnet.broadcast_address - 1),
                broadcast_address=str(subnet.broadcast_address),
                usable_hosts=usable,
                wasted_hosts=usable - req.hosts_needed,
            )
        )
        allocated_total += subnet.num_addresses
        current_ip += block_size

    unused = base.num_addresses - allocated_total
    utilization = round((allocated_total / base.num_addresses) * 100, 2)

    return VLSMPlan(
        base_cidr=str(base),
        total_base_addresses=base.num_addresses,
        allocated_addresses=allocated_total,
        unused_addresses=unused,
        utilization_percent=utilization,
        subnets=allocated,
    )


def detect_overlaps(cidrs: list[str]) -> list[OverlapPair]:
    """Return every pair of CIDR networks that overlap."""
    networks = [_parse_ipv4_network(c) for c in cidrs]
    overlaps: list[OverlapPair] = []
    for idx, net_a in enumerate(networks):
        for net_b in networks[idx + 1 :]:
            if net_a.overlaps(net_b):
                overlaps.append(OverlapPair(network_a=str(net_a), network_b=str(net_b)))
    return overlaps
