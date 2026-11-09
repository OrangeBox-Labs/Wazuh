#!/usr/bin/env python3
"""Pruebas de contrato para el bloque HTML de Active Response del correo."""
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EMAIL_SCRIPT = (
    REPO_ROOT
    / "configuration"
    / "manager"
    / "integrations"
    / "custom-orangebox-email.py"
)


def active_response_html_source():
    """Extrae el fragmento que construye Active Response sin ejecutar la integración."""
    source = EMAIL_SCRIPT.read_text(encoding="utf-8")
    start_marker = '    blocked_ip_html = f"""'
    end_marker = "\n\n\n# ============================================================\n# PLANTILLA HTML CORPORATIVA ORANGEBOX"
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


class ActiveResponseEmailLayoutTests(unittest.TestCase):
    def test_active_response_keeps_responsive_row_and_wrappable_values(self):
        """El bloque mantiene una fila de tabla y permite envolver valores largos en móvil."""
        fragment = active_response_html_source()
        self.assertIn('class="ob-detail-row"', fragment)
        self.assertIn('colspan="2"', fragment)
        self.assertIn("overflow-wrap:anywhere", fragment)
        self.assertIn("vertical-align:top", fragment)

    def test_active_response_keeps_all_operational_details(self):
        """La corrección visual no debe eliminar información de diagnóstico."""
        fragment = active_response_html_source()
        for expected in (
            "Active Response:",
            "Acción: firewall-drop",
            "Tiempo:",
            "Ejecución en:",
            "Selector:",
            "status_detail",
            "timeout_label",
            "location_detail",
            "selector_detail",
            "source_ip",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, fragment)


if __name__ == "__main__":
    unittest.main(verbosity=2)
