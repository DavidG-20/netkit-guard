# netkit-guard — Suite de Redes (VLSM) y Auditoría Defensiva de Puertos

Herramienta **CLI + Web** de **Redes TCP/IP y Seguridad Defensiva** en Python para diseñar esquemas de direccionamiento **VLSM/CIDR** sin solapamientos y auditar puertos TCP abiertos en hosts propios/locales usando `asyncio`.

## Características principales

1. **Inspección CIDR (`netkit info`)**: calcula dirección de red, broadcast, máscara, wildcard, rango de hosts utilizables y clasificación privada/pública.
2. **Motor de Subnetting VLSM (`netkit vlsm`)**: ordena requisitos de mayor a menor, asigna subredes óptimas alineadas sin desperdicio ni solapamiento y calcula el porcentaje de utilización de la red base.
3. **Detector de solapamientos (`netkit overlaps`)**: identifica pares de subredes CIDR en conflicto antes de aplicar configuraciones en routers o firewalls.
4. **Auditor defensivo de puertos TCP (`netkit audit`)**: escaneo concurrente con `asyncio` + comparación contra línea base de puertos esperados (`--expected`), bloqueando por defecto cualquier IP externa fuera de redes privadas/loopback para prevenir usos indebidos o SSRF.
5. **Interfaz Web interactiva (`netkit web`)**: panel visual en `http://127.0.0.1:8000` para diseñar planes VLSM, verificar solapamientos y auditar puertos locales.

## Arquitectura

```text
netkit-guard/
├── .agents/skills/redes-seguras/   # Reglas de VLSM y auditoría TCP segura
├── AGENTS.md                       # Reglas del proyecto
├── src/netkit_guard/
│   ├── main.py                     # CLI (Typer + Rich)
│   ├── web.py                      # API FastAPI + cabeceras de seguridad + protección SSRF
│   ├── models.py                   # Dataclasses tipados
│   ├── subnetting.py               # Motor CIDR, VLSM y detección de solapamientos
│   ├── port_auditor.py             # Auditor TCP concurrente con asyncio y guardrails
│   └── static/index.html           # Interfaz web interactiva (XSS-safe)
└── tests/
    └── test_netkit.py              # Pruebas unitarias y de seguridad (pytest)
```

## Instalación

```bash
git clone https://github.com/DavidG-20/netkit-guard.git
cd netkit-guard
uv sync
```

## Uso rápido

```bash
# 1. Desglose de una red CIDR
uv run netkit info 192.168.10.0/24

# 2. Calcular plan VLSM
uv run netkit vlsm 192.168.10.0/24 -r "Ventas:50" -r "TI:20" -r "Enlace:2"

# 3. Detectar solapamientos
uv run netkit overlaps 10.0.0.0/24 10.0.0.128/25 10.0.1.0/24

# 4. Auditar puertos locales contra línea base
uv run netkit audit 127.0.0.1 --ports 22,80,5432,8000 --expected 8000

# 5. Abrir interfaz web interactiva
uv run netkit web
```

## Ejecutar pruebas

```bash
uv run pytest -v
```

## Licencia

MIT
