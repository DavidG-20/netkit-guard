# Reglas del proyecto `netkit-guard`

- Stack: **Python 3.12+**, **`uv`**, **Typer**, **Rich**, **FastAPI**, **Uvicorn** y biblioteca estándar (`ipaddress`, `asyncio`).
- Código interno en **inglés técnico**; CLI, interfaz web y `README.md` en **español**.
- El auditor de puertos es estrictamente defensivo: por defecto solo permite hosts locales/privados (`localhost`, RFC1918) y en la interfaz web bloquea IPs públicas para evitar SSRF.
- Consulta `.agents/skills/redes-seguras/SKILL.md` para reglas de VLSM y escaneo TCP seguro.
