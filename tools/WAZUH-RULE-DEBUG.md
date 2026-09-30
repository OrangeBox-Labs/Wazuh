# Wazuh: probar reglas y depurar alertas

Guía corta para cuando una regla "debería disparar" y Wazuh decide hacerse el hueón.

## 1. Primero: ¿el evento llegó?

En el Manager, mirar el log que alimenta la regla:

```bash
tail -f /var/ossec/logs/archives/archives.log
```

Si no aparece ahí, **no partas mirando la regla**. El problema está antes: decoder, logcollector, agente, permisos, conexión o la fuente del evento.

Buscar un evento concreto:

```bash
grep -F 'texto-del-evento' /var/ossec/logs/archives/archives.log | tail -20
```

Para JSON:

```bash
grep -F 'texto-del-evento' /var/ossec/logs/archives/archives.json | tail -5 | jq .
```

## 2. ¿Qué regla lo procesó?

Usa el logtest del Manager:

```bash
/var/ossec/bin/wazuh-logtest
```

Pega **el evento real**, no una versión inventada a mano.

Mira tres cosas:

```text
Phase 1  -> evento recibido
Phase 2  -> decoder
Phase 3  -> regla
```

Si falla en Phase 2, no sigas tuneando la regla: **el decoder no está extrayendo lo que la regla necesita**.

Si llega a Phase 3 pero no coincide, revisa campos, operadores, regla padre y condiciones.

Salir:

```text
Ctrl+D
```

## 3. Buscar la alerta en alerts.json

Las alertas generadas por Wazuh están aquí:

```bash
/var/ossec/logs/alerts/alerts.json
```

Por ID de regla:

```bash
grep -F '"id":"10460"' /var/ossec/logs/alerts/alerts.json | tail -20
```

Con JSON legible:

```bash
grep -F '"id":"10460"' /var/ossec/logs/alerts/alerts.json |
  tail -1 | jq .
```

Ver rápidamente los campos importantes:

```bash
grep -F '"id":"10460"' /var/ossec/logs/alerts/alerts.json |
  tail -1 |
  jq '{timestamp,rule,agent,srcip,dstip,srcport,dstport,location,decoder}'
```

Para todas las alertas recientes de un agente:

```bash
jq -c 'select(.agent.name=="NOMBRE_DEL_AGENT")'   /var/ossec/logs/alerts/alerts.json | tail -20
```

Para un nivel concreto:

```bash
jq -c 'select(.rule.level >= 12)'   /var/ossec/logs/alerts/alerts.json | tail -20
```

### Ojo con esto

Que exista una entrada en `archives.json` **no significa que exista una alerta**.

- `archives.*` = evento recibido.
- `alerts.*` = evento que terminó coincidiendo con una regla que genera alerta.

Ese detalle ahorra horas de puteadas.

## 4. ¿La regla disparó, pero no llegó correo?

Primero confirma que existe la alerta:

```bash
grep -F '"id":"ID_REGLA"' /var/ossec/logs/alerts/alerts.json | tail
```

Después revisa la integración/correo:

```bash
tail -f /var/ossec/logs/ossec.log
```

Y, si corresponde:

```bash
tail -f /var/ossec/logs/integrations.log
```

Si la alerta está en `alerts.json` pero no hay envío, **la regla ya hizo su pega**. El problema está en la cadena posterior: integración, condiciones de correo, script o SMTP.

## 5. ¿Active Response se ejecutó?

Primero confirma la alerta:

```bash
grep -F '"id":"ID_REGLA"' /var/ossec/logs/alerts/alerts.json | tail
```

Después mira:

```bash
tail -f /var/ossec/logs/active-responses.log
```

Y en el Agent:

```bash
grep -i 'orangebox\|active response' /var/ossec/logs/active-responses.log | tail -50
```

También revisa que el comando exista y sea ejecutable:

```bash
ls -l /var/ossec/active-response/bin/
```

Para un Agent instalado en `/opt/ossec`, cambia la ruta:

```bash
ls -l /opt/ossec/active-response/bin/
```

### La pregunta clave

```text
¿La alerta existe?
        |
        +-- NO -> regla / decoder / evento
        |
        +-- SÍ
             |
             +-- ¿Active Response aparece?
             |       |
             |       +-- NO -> command / active-response / nivel / ubicación
             |
             +-- SÍ -> depurar el script
```

## 6. Probar una regla sin esperar a producción

La herramienta principal es:

```bash
/var/ossec/bin/wazuh-logtest
```

Flujo recomendado:

1. captura el evento real;
2. pásalo por `wazuh-logtest`;
3. confirma decoder;
4. confirma regla;
5. revisa campos extraídos;
6. recién después prueba la acción.

No uses primero un `echo` inventado que no se parece al evento real. Eso produce reglas preciosas que nunca disparan.

## 7. Revisar reglas cargadas

Buscar una regla por ID:

```bash
grep -R 'id="10460"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/ 2>/dev/null
```

Buscar una cadena:

```bash
grep -R -n -F 'orangebox' /var/ossec/etc/rules/ /var/ossec/etc/decoders/ 2>/dev/null
```

Validar configuración antes de reiniciar:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Si la versión instalada no acepta esa opción, usa:

```bash
/var/ossec/bin/wazuh-control info
```

y revisa el error concreto en:

```bash
tail -100 /var/ossec/logs/ossec.log
```

**No reinicies a ciegas.** Primero valida; después reinicia si corresponde.

## 8. Cuando una regla dejó de funcionar

No cambies cinco cosas juntas.

Haz esta secuencia:

```text
1. ¿Llegó el evento?
2. ¿Qué decoder lo tomó?
3. ¿Qué campos extrajo?
4. ¿Qué regla coincidió?
5. ¿Apareció en alerts.json?
6. ¿Se ejecutó Active Response?
7. ¿Se envió el correo?
```

El primer punto que falle te dice dónde está el problema.

## 9. Firewall / IOC

Para una alerta relacionada con firewall o IOC, revisar primero la alerta completa:

```bash
grep -F '"id":"ID_REGLA"' /var/ossec/logs/alerts/alerts.json |
  tail -1 | jq .
```

Luego, en el Agent, confirmar que el firewall realmente recibió el tráfico.

Shorewall:

```bash
iptables -L ORANGEBOX-FW -n --line-numbers
```

Buscar el log:

```bash
journalctl -k | grep -F 'ORANGEBOX-FW' | tail -50
```

En EL6:

```bash
grep -F 'ORANGEBOX-FW' /var/log/orangebox-firewall.log | tail -50
```

Si hay un IOC pero no hay bloqueo, recuerda la arquitectura: **la cadena de logging no bloquea por sí sola**. El bloqueo ocurre cuando la regla de Wazuh dispara el Active Response correspondiente.

## 10. YARA

Probar que el binario funciona:

```bash
/var/ossec/active-response/bin/orangebox-yara.sh --help 2>/dev/null || true
```

Comprobar que el runtime existe:

```bash
ls -l /var/ossec/active-response/bin/orangebox-yara.sh
ls -l /var/ossec/active-response/bin/orangebox-quarantine.py
```

Comprobar el ruleset:

```bash
cat /var/ossec/active-response/bin/yara/rules/YARA-RULES-COMMIT
```

Validar directamente los índices:

```bash
yara -w /var/ossec/active-response/bin/yara/rules/yara-rules/webshells_index.yar /dev/null
yara -w /var/ossec/active-response/bin/yara/rules/yara-rules/malware_index.yar /dev/null
```

Para `/opt/ossec`, usa la ruta equivalente.

## 11. Permisos: el clásico "pero si el archivo existe"

Revisar:

```bash
stat -c '%A %a %U:%G %n'   /var/ossec/etc/rules/*.xml   /var/ossec/etc/decoders/*.xml
```

Y:

```bash
sudo -u wazuh cat /var/ossec/etc/rules/NOMBRE.xml >/dev/null
echo $?
```

Si devuelve `0`, el usuario `wazuh` puede leerlo.

Para revisar/corregir todo el árbol:

```bash
sudo ./tools/verify-ossec-permissions.sh
sudo ./tools/verify-ossec-permissions.sh --fix
```

## 12. Mini checklist para no volverse loco

Cuando algo falle:

```bash
# Evento
tail -f /var/ossec/logs/archives/archives.log

# Regla
/var/ossec/bin/wazuh-logtest

# Alertas
tail -f /var/ossec/logs/alerts/alerts.json

# Manager
tail -f /var/ossec/logs/ossec.log

# Active Response
tail -f /var/ossec/logs/active-responses.log

# Reglas
grep -R -n 'ID_REGLA' /var/ossec/etc/rules/

# Decoders
grep -R -n 'texto_clave' /var/ossec/etc/decoders/

# Firewall
iptables -L ORANGEBOX-FW -n --line-numbers
```

**Regla de oro:** no adivines. Sigue el evento desde que entra hasta que termina:

```text
EVENTO
  -> DECODER
  -> RULE
  -> ALERT
  -> INTEGRATION / EMAIL
  -> ACTIVE RESPONSE
  -> ACCION
```

Si encuentras en qué flecha se murió, ya encontraste al culpable. El resto es carpintería.
