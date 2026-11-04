#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "configuration/manager/bin/update-orangebox-ioc-lists.sh"
DEPLOY = ROOT / "tools/deploy-ioc-active-response.sh"
CONFIRMED_SOURCE_LIST = (
    ROOT / "configuration/manager/etc/lists/malicious-ioc/orangebox-confirmed-source-ip"
)


class IOCUpdaterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Prepara rutas y carga el actualizador una sola vez para ejecutar pruebas aisladas."""
        cls.source = UPDATER.read_text(encoding="utf-8")
        cls.deploy_source = DEPLOY.read_text(encoding="utf-8")

    # Extrae el parser CSV incrustado sin ejecutar descargas externas.
    def embedded_parser(self):
        """Extrae el parser CSV incrustado en el script para probarlo sin descargar feeds."""
        marker = """python3 - "$TMP_DIR/urlhaus-recent.csv" "$TMP_DIR/malware-host-ip" <<'PY'
"""
        self.assertIn(marker, self.source, "No se encontró el parser CSV embebido.")
        start = self.source.index(marker) + len(marker)
        end = self.source.index("\nPY", start)
        return self.source[start:end]

    # Extrae el validador de la CDB curada para probarlo de forma aislada.
    def embedded_confirmed_source_parser(self):
        """Extrae el parser de la CDB curada para validar sus entradas sin modificar el Manager."""
        marker = """python3 - "$CONFIRMED_SOURCE_LIST" "$TMP_DIR/orangebox-confirmed-source-ip" <<'PY'
"""
        self.assertIn(marker, self.source, "No se encontró el validador de IOC confirmados.")
        start = self.source.index(marker) + len(marker)
        end = self.source.index("\nPY", start)
        return self.source[start:end]

    # Evita que reaparezcan wrappers o parsers secundarios obsoletos.
    def test_single_script_contains_real_implementation(self):
        """Comprueba que el actualizador sea el único punto de implementación y no delegue en wrappers legacy."""
        self.assertGreater(len(self.source.splitlines()), 500)
        self.assertIn("urlhaus-api.abuse.ch/v2/files/exports/$URLHAUS_AUTH_KEY/recent.csv", self.source)
        self.assertIn("urlhaus-api.abuse.ch/v2/files/exports/$URLHAUS_AUTH_KEY/hostfile.txt", self.source)
        self.assertNotIn("update-orangebox-ioc-lists-v2.sh", self.source)
        self.assertNotIn("parse_urlhaus_recent.py", self.source)
        self.assertNotIn("downloads/text_recent/", self.source)
        self.assertNotIn("downloads/hostfile/", self.source)

    # Comprueba que los secretos nunca se lean con xtrace activo.
    def test_xtrace_is_disabled_before_secrets_are_loaded(self):
        """Garantiza que la depuración de shell quede desactivada antes de leer secretos."""
        self.assertLess(self.source.index("set +x"), self.source.index('source "$SECRETS_FILE"'))
        self.assertLess(self.source.index("umask 077"), self.source.index('source "$SECRETS_FILE"'))

    # Verifica que la configuración de la Auth-Key pertenezca al mismo actualizador.
    def test_key_setup_is_a_mode_of_the_same_script(self):
        """Verifica que la configuración de la Auth-Key esté integrada en el actualizador principal."""
        self.assertIn("--configure-key", self.source)
        self.assertIn("read -r -s", self.source)
        self.assertIn("root:root", self.source)
        self.assertIn("chmod 0600", self.source)
        self.assertIn("URLHAUS_AUTH_KEY=%s", self.source)
        self.assertIn("MB_AUTH_KEY=%s", self.source)

    # Comprueba que las URLs autenticadas no aparezcan en argv ni en archivos legibles por otros.
    def test_authenticated_curl_config_files_are_private(self):
        """Comprueba que las credenciales de descarga no queden expuestas en argv ni en archivos públicos."""
        self.assertIn('chmod 0600 "$TMP_DIR/urlhaus-recent.curl" "$TMP_DIR/urlhaus-hostfile.curl"', self.source)
        self.assertIn('--config "$TMP_DIR/urlhaus-recent.curl"', self.source)
        self.assertIn('--config "$TMP_DIR/urlhaus-hostfile.curl"', self.source)
        self.assertIn('chmod 0600 "$TMP_DIR/malwarebazaar.curl"', self.source)
        self.assertIn('--config "$TMP_DIR/malwarebazaar.curl"', self.source)
        self.assertNotIn('-H "Auth-Key: $MB_AUTH_KEY"', self.source)

    # Verifica extracción de IPs globales y exclusión de destinos reservados/IPv6.
    def test_inline_csv_parser_extracts_only_global_ipv4_hosts(self):
        """Valida que el parser acepte solo hostnames con IPv4 pública."""
        parser = self.embedded_parser()
        csv_data = (
            '# URLhaus recent CSV\n'
            '"ID","Dateadded","URL","URL status"\n'
            '"1","2026-10-30","http://45.61.49.78/payload.bin","online"\n'
            '"2","2026-10-30","https://malware.example/payload","online"\n'
            '"3","2026-10-30","http://8.8.8.8/bad","online"\n'
            '"4","2026-10-30","http://192.0.2.10/test","online"\n'
            '"5","2026-10-30","https://[2001:4860:4860::8888]/bad","online"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "recent.csv"
            out_path = Path(tmp) / "malware-host-ip"
            csv_path.write_text(csv_data, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-", str(csv_path), str(out_path)],
                input=parser,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                out_path.read_text(encoding="ascii"),
                "8.8.8.8:\n45.61.49.78:\n",
            )

    # Comprueba el encabezado real de exportación URLhaus aunque venga comentado.
    def test_inline_csv_parser_accepts_comment_prefixed_urlhaus_header(self):
        """Comprueba que se reconozca la cabecera URLhaus aunque venga precedida por comentarios."""
        parser = self.embedded_parser()
        csv_data = (
            "# URLhaus recent export\n"
            "# This is descriptive metadata\n"
            "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
            '"1","2026-10-30","http://45.61.49.78/payload.bin","online","","malware_download","","https://urlhaus.abuse.ch/url/1/","analyst"\n'
            '"2","2026-10-30","https://malware.example/payload","online","","malware_download","","https://urlhaus.abuse.ch/url/2/","analyst"\n'
            '"3","2026-10-30","http://8.8.8.8/bad","online","","malware_download","","https://urlhaus.abuse.ch/url/3/","analyst"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "recent.csv"
            out_path = Path(tmp) / "malware-host-ip"
            csv_path.write_text(csv_data, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-", str(csv_path), str(out_path)],
                input=parser,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                out_path.read_text(encoding="ascii"),
                "8.8.8.8:\n45.61.49.78:\n",
            )

    # Evita publicar una CDB si cambia inesperadamente el formato del CSV.
    def test_csv_parser_rejects_unknown_header(self):
        """Evita actualizar IOC si cambia el formato de columnas de una fuente."""
        parser = self.embedded_parser()
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "recent.csv"
            out_path = Path(tmp) / "malware-host-ip"
            csv_path.write_text(
                '"ID","Dateadded","URL address"\n"1","2026-10-30","http://45.61.49.78/a"\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-", str(csv_path), str(out_path)],
                input=parser,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no contiene una cabecera CSV reconocible", result.stderr)

    # Comprueba que la lista curada privada mantenga la IOC documentada.
    def test_confirmed_source_list_contains_the_incident_ip(self):
        """Verifica que la lista curada local corresponda a la política de IOC de este repositorio."""
        # Construye el conjunto de entradas reales de la CDB curada, ignorando comentarios.
        entries = {
            line.strip()
            for line in CONFIRMED_SOURCE_LIST.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertIn("165.154.218.226:", entries)

    # Valida normalización, orden y deduplicación de IPv4 en formato CDB.
    def test_confirmed_source_parser_normalizes_ipv4_cdb_entries(self):
        """Comprueba normalización, orden y deduplicación de IPv4 en formato CDB."""
        parser = self.embedded_confirmed_source_parser()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "confirmed-source-ip"
            output = Path(tmp) / "normalized"
            source.write_text(
                "# locally confirmed sources\n165.154.218.226:\n8.8.8.8:\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-", str(source), str(output)],
                input=parser,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output.read_text(encoding="ascii"),
                "8.8.8.8:\n165.154.218.226:\n",
            )

    # Rechaza entradas sin dos puntos, direcciones inválidas e IPv6.
    # Permite una lista curada vacía en repositorios nuevos; Emerging Threats sigue aportando IOC de origen.
    def test_confirmed_source_parser_accepts_comment_only_list(self):
        """Permite que una distribución pública comience con la lista curada vacía."""
        parser = self.embedded_confirmed_source_parser()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "confirmed-source-ip"
            output = Path(tmp) / "normalized"
            source.write_text("# Add manually verified source IPs here.\\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-", str(source), str(output)],
                input=parser,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(encoding="ascii"), "")

    def test_confirmed_source_parser_rejects_non_cdb_or_non_ipv4_entries(self):
        """Rechaza direcciones inválidas, IPv6 y entradas fuera del formato CDB."""
        parser = self.embedded_confirmed_source_parser()
        # Prueba cada formato inválido para comprobar que el parser lo rechace.
        for invalid in ("165.154.218.226", "not-an-ip:", "2001:4860:4860::8888:"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "confirmed-source-ip"
                output = Path(tmp) / "normalized"
                source.write_text(invalid + "\n", encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-", str(source), str(output)],
                    input=parser,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())

    # Asegura que solo IOC de origen alimenten malicious-ip.
    def test_active_source_cdb_is_union_of_emerging_threats_and_confirmed(self):
        """Comprueba que malicious-ip combine el feed automático y las IOC de origen confirmadas."""
        self.assertIn('CONFIRMED_SOURCE_LIST="$LIST_DIR/orangebox-confirmed-source-ip"', self.source)
        self.assertIn('cat "$TMP_DIR/emerging-threats-source-ip" "$TMP_DIR/orangebox-confirmed-source-ip"', self.source)
        self.assertIn('sort -u > "$TMP_DIR/malicious-ip"', self.source)
        self.assertIn('CONFIRMED_SOURCE_OWNER="$(stat -c \'%u\' "$CONFIRMED_SOURCE_LIST")"', self.source)
        self.assertIn('CONFIRMED_SOURCE_MODE="$(stat -c \'%a\' "$CONFIRMED_SOURCE_LIST")"', self.source)
        self.assertIn("malware-host-ip", self.source)
        self.assertNotIn('cat "$TMP_DIR/urlhaus', self.source)

    # Comprueba que el deploy combine semilla y entradas locales sin borrar estas últimas.
    def test_deployment_merge_preserves_live_confirmed_ips_and_adds_seed(self):
        """Evita que el despliegue borre IOC locales que ya fueron validadas."""
        self.assertIn("CONFIRMED_SOURCE_SEED", self.deploy_source)
        self.assertIn("CONFIRMED_SOURCE_TARGET", self.deploy_source)
        self.assertIn('"${OBSOLETE_TARGETS[@]}" "etc/lists/malicious-ioc/orangebox-confirmed-source-ip"', self.deploy_source)
        marker = """python3 - "$CONFIRMED_SOURCE_SEED" "$CONFIRMED_SOURCE_TARGET" "$MERGE_TMP" <<'PY'
"""
        self.assertIn(marker, self.deploy_source)
        start = self.deploy_source.index(marker) + len(marker)
        end = self.deploy_source.index("\nPY", start)
        merge_parser = self.deploy_source[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            seed = Path(tmp) / "seed"
            live = Path(tmp) / "live"
            output = Path(tmp) / "merged"
            seed.write_text("165.154.218.226:\n", encoding="utf-8")
            live.write_text("# local manual IOC\n203.0.113.10:\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-", str(seed), str(live), str(output)],
                input=merge_parser,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output.read_text(encoding="ascii"),
                "165.154.218.226:\n203.0.113.10:\n",
            )

    # Impide que cron reclasifique fuentes de IOC sin DRY_RUN y aprobación inicial.
    def test_ioc_migration_gate_is_preserved(self):
        """Exige simulación y aprobación explícita para la primera reclasificación de IOC."""
        self.assertIn("SOURCE_IP_MIGRATION_MARKER", self.source)
        self.assertIn("ORANGEBOX_IOC_DRY_RUN", self.source)
        self.assertIn("ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION", self.source)
        self.assertEqual(self.source.count('install_if_changed "malicious-ip"'), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
