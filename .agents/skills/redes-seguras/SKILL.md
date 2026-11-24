---
name: redes-seguras
description: Reglas de cálculo VLSM/CIDR, auditoría TCP defensiva y prevención de SSRF para netkit-guard.
---

# Reglas de Redes y Auditoría Defensiva

- Usa `ipaddress.IPv4Network` en modo `strict=False` solo para inspección informativa, y valida direcciones válidas en VLSM y detección de solapamientos.
- En VLSM, ordena siempre los requisitos de mayor a menor número de hosts antes de asignar bloques para evitar fragmentación.
- En el auditor TCP con `asyncio`, limita concurrencia con `asyncio.Semaphore` y usa timeouts cortos (`<= 2s`).
- En la API web, restringe el auditor de puertos exclusivamente a direcciones loopback y privadas RFC1918 (`is_loopback` o `is_private`) para impedir abusos SSRF.
- Escapa todos los datos dinámicos en el frontend web (`escapeHtml`) y agrega cabeceras HTTP de seguridad.
