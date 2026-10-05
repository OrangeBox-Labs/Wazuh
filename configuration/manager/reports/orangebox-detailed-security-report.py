#!/usr/bin/env python3
"""Compatibilidad con el nombre antiguo del reporte detallado.

Desde v4 el reporte ejecutivo y el detallado se generan en una sola ejecución:
el resumen queda en el cuerpo del correo y el detallado se adjunta como ZIP.
Este archivo no contiene un segundo motor ni genera un segundo correo.
"""

import runpy

if __name__ == "__main__":
    runpy.run_path(
        "/var/ossec/reports/orangebox-security-report.py",
        run_name="__main__",
    )
