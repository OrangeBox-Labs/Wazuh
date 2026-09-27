# Integrations

Integraciones propias utilizadas por Wazuh para transformar o entregar alertas.

## Archivos

- **`custom-orangebox-email.py`** — integración de correo HTML de OrangeBox, con envío inmediato para eventos críticos, agrupación de alertas, deduplicación y conservación de evidencia FIM.
- **`custom-orangebox-email.md`** — documentación técnica y decisiones de diseño de la integración.

## Principio de diseño

Las reglas Wazuh determinan **qué ocurrió**. La integración determina **cómo se entrega la alerta** sin perder evidencia ni inundar el correo.

Los cambios en reglas de detección no deben modificar automáticamente la lógica de esta integración. Primero debe verificarse si el nuevo evento necesita tratamiento especial de entrega.
