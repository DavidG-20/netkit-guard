"""CLI entry point for netkit-guard (Typer + Rich)."""

import asyncio
from rich.console import Console
from rich.table import Table
import typer
import uvicorn

from netkit_guard.models import SubnetRequirement
from netkit_guard.port_auditor import (
    DEFAULT_PORTS,
    UnauthorizedTargetError,
    audit_ports,
)
from netkit_guard.subnetting import (
    SubnetError,
    allocate_vlsm,
    detect_overlaps,
    inspect_network,
)

app = typer.Typer(
    name="netkit",
    help="Suite de Redes y Seguridad: Subnetting/VLSM, solapamientos y auditor de puertos TCP.",
    no_args_is_help=True,
)
console = Console()


def _parse_ports(raw: str | None) -> list[int]:
    if not raw:
        return DEFAULT_PORTS
    ports: set[int] = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end or start < 1 or end > 65535:
                raise typer.BadParameter(f"Rango de puertos inválido: {token}")
            ports.update(range(start, end + 1))
        else:
            port = int(token)
            if port < 1 or port > 65535:
                raise typer.BadParameter(f"Puerto inválido: {port}")
            ports.add(port)
    return sorted(ports)


@app.command("info")
def network_info(cidr: str = typer.Argument(..., help="Red IPv4 en formato CIDR (ej. 192.168.10.0/24).")) -> None:
    """Muestra el desglose completo de una red IPv4 CIDR."""
    try:
        info = inspect_network(cidr)
    except SubnetError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title=f"Análisis CIDR: {info.cidr}", show_header=False)
    table.add_column("Campo", style="cyan bold")
    table.add_column("Valor", style="bold")
    table.add_row("Red", info.network_address)
    table.add_row("Broadcast", info.broadcast_address)
    table.add_row("Máscara", f"{info.netmask} (/{info.prefix_length})")
    table.add_row("Wildcard", info.wildcard_mask)
    table.add_row("Rango utilizable", f"{info.first_usable} — {info.last_usable}")
    table.add_row("Hosts utilizables", f"{info.usable_hosts} (total: {info.total_addresses})")
    table.add_row("Tipo", "Privada (RFC1918)" if info.is_private else "Pública / Especial")
    console.print(table)


@app.command("vlsm")
def vlsm_plan(
    base_cidr: str = typer.Argument(..., help="Red base IPv4 (ej. 192.168.10.0/24)."),
    req: list[str] = typer.Option(
        ...,
        "--req",
        "-r",
        help="Requisito en formato 'Nombre:Hosts' (repetible, ej. -r Ventas:50 -r TI:20).",
    ),
) -> None:
    """Calcula un plan de subredes VLSM optimizado sin solapamientos."""
    requirements: list[SubnetRequirement] = []
    for item in req:
        if ":" not in item:
            console.print(f"[red]Formato inválido '{item}'.[/red] Usa Nombre:Hosts (ej. Ventas:50).")
            raise typer.Exit(code=2)
        name, hosts_s = item.split(":", 1)
        try:
            requirements.append(SubnetRequirement(name=name.strip(), hosts_needed=int(hosts_s)))
        except ValueError as exc:
            console.print(f"[red]Número de hosts inválido en '{item}'.[/red]")
            raise typer.Exit(code=2) from exc

    try:
        plan = allocate_vlsm(base_cidr, requirements)
    except SubnetError as exc:
        console.print(f"[red]Error VLSM:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title=f"Plan VLSM sobre {plan.base_cidr} (uso: {plan.utilization_percent}%)")
    table.add_column("Área", style="bold")
    table.add_column("Pedidos", justify="right")
    table.add_column("Subred CIDR", style="cyan bold")
    table.add_column("Máscara")
    table.add_column("Rango utilizable", style="green")
    table.add_column("Broadcast")
    table.add_column("Capacidad", justify="right")

    for s in plan.subnets:
        table.add_row(
            s.name,
            str(s.hosts_needed),
            s.cidr,
            s.netmask,
            f"{s.first_usable} — {s.last_usable}",
            s.broadcast_address,
            f"{s.usable_hosts} (-{s.wasted_hosts})",
        )
    console.print(table)
    console.print(
        f"[dim]Asignadas: {plan.allocated_addresses} IPs | Libres: {plan.unused_addresses} IPs[/dim]"
    )


@app.command("overlaps")
def check_overlaps(cidrs: list[str] = typer.Argument(..., help="Lista de redes CIDR a comparar.")) -> None:
    """Detecta si dos o más subredes IPv4 se solapan entre sí."""
    try:
        pairs = detect_overlaps(cidrs)
    except SubnetError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if not pairs:
        console.print("[green]✔ Sin solapamientos:[/green] todas las subredes son disjuntas.")
        return

    for pair in pairs:
        console.print(f"[red]✖ Solapamiento:[/red] {pair.network_a} ↔ {pair.network_b}")
    raise typer.Exit(code=1)


@app.command("audit")
def port_audit(
    host: str = typer.Argument("127.0.0.1", help="Host local o privado autorizado a auditar."),
    ports: str | None = typer.Option(None, "--ports", "-p", help="Puertos o rangos (ej. 22,80,8000-8010)."),
    expected: str | None = typer.Option(None, "--expected", "-e", help="Puertos permitidos en línea base (ej. 22,8000)."),
    timeout: float = typer.Option(0.5, "--timeout", help="Timeout por puerto en segundos."),
    allow_external: bool = typer.Option(False, "--allow-external", help="Permite auditar hosts fuera de redes privadas (solo con autorización)."),
) -> None:
    """Audita puertos TCP abiertos de forma concurrente y compara contra una línea base."""
    target_ports = _parse_ports(ports)
    expected_set = set(_parse_ports(expected)) if expected else set()

    try:
        report = asyncio.run(
            audit_ports(
                host=host,
                ports=target_ports,
                expected_ports=expected_set,
                timeout=timeout,
                allow_external=allow_external,
            )
        )
    except UnauthorizedTargetError as exc:
        console.print(f"[red]Bloqueado:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    console.print(
        f"Objetivo: [bold]{report.host}[/bold] ({report.resolved_ip}) | "
        f"Puertos probados: [bold]{report.scanned_ports}[/bold]"
    )
    if not report.open_ports:
        console.print("[green]No se detectaron puertos TCP abiertos en el rango consultado.[/green]")
        return

    table = Table(title="Puertos TCP abiertos")
    table.add_column("Puerto", style="bold")
    table.add_column("Servicio", style="cyan")
    table.add_column("Estado")
    table.add_column("Severidad")

    has_unexpected = False
    for f in report.open_ports:
        color = "red" if f.severity == "HIGH" else "green"
        if f.severity == "HIGH":
            has_unexpected = True
        table.add_row(str(f.port), f.service, f.status, f"[{color}]{f.severity}[/{color}]")
    console.print(table)

    if report.missing_expected_ports:
        console.print(f"[yellow]Puertos esperados cerrados:[/yellow] {report.missing_expected_ports}")
    if has_unexpected:
        raise typer.Exit(code=1)


@app.command("web")
def run_web(
    host: str = typer.Option("127.0.0.1", "--host", help="Dirección de escucha."),
    port: int = typer.Option(8000, "--port", help="Puerto HTTP."),
) -> None:
    """Levanta la interfaz web interactiva de netkit-guard."""
    console.print(f"[cyan]Iniciando netkit-guard web en http://{host}:{port}[/cyan]")
    uvicorn.run("netkit_guard.web:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
