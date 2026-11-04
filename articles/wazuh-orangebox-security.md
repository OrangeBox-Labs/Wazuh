---
title: "Wazuh, pero con esteroides: cómo OrangeBox convirtió un SIEM en una capa de detección y respuesta para Linux"
date: 2026-09-27
draft: false
description: "Cómo extendimos Wazuh con FIM quirúrgico, detección de ataques, IOC, YARA, Active Response y cuarentena para proteger servidores Linux reales."
tags:
  - wazuh
  - seguridad
  - linux
  - fim
  - yara
  - ioc
  - active-response
  - threat-intelligence
categories:
  - seguridad
showToc: true
TocOpen: false
---

Wazuh es bastante más que un visor de logs con lucecitas bonitas.

De fábrica ya trae una cantidad importante de capacidades: análisis de logs, reglas de detección, File Integrity Monitoring (FIM), inventario, detección de vulnerabilidades, Security Configuration Assessment, Active Response y varias capas de detección de comportamiento. Wazuh además mantiene un conjunto amplio de reglas para eventos de sistema, autenticación, aplicaciones y ataques conocidos.

Entonces viene la pregunta incómoda:

**¿para qué demonios hicimos otro repositorio encima de Wazuh?**

Porque un servidor Linux real no vive en el laboratorio.

Tiene Zimbra, Carbonio, cPanel, Apache, Nginx, PHP, reverse proxies, backups, cron, systemd, SSH, firewall, usuarios de servicio, binarios propios y una colección de "cosas que nadie recuerda haber instalado pero que llevan cinco años funcionando".

Y cuando aparece un atacante, no basta con saber que "algo pasó".

Queremos saber:

- qué pasó;
- dónde pasó;
- si el comportamiento tiene sentido;
- si la fuente ya es conocida como maliciosa;
- si apareció un archivo donde no debería;
- si ese archivo parece malware;
- si alguien consiguió ejecutar algo;
- si hubo escalamiento de privilegios;
- si la misma IP está atacando varios servidores;
- y, cuando la evidencia es suficientemente fuerte, **hacer algo al respecto**.

Eso es lo que contiene el repositorio público de OrangeBox:

**[OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh)**

El repositorio privado de desarrollo y operación contiene la configuración completa y es la fuente de donde sale lo que finalmente se despliega.

![Arquitectura OrangeBox Wazuh](https://www.orangebox.cl/blog/images/wazuh-repo/fig1.svg)

---

## 1. Primero: ¿qué hace Wazuh sin OrangeBox?

Wazuh funciona como una cadena de recolección, normalización, detección y respuesta.

A grandes rasgos:

~~~text
Servidor Linux
     |
     | logs / FIM / inventario / eventos
     v
 Wazuh Agent
     |
     v
 Wazuh Manager
     |
     +--> decoders
     |
     +--> reglas
     |
     +--> enriquecimiento / IOC
     |
     +--> alertas
     |
     +--> Active Response
     |
     v
 Indexer / Dashboard / correo / integraciones
~~~

El agente recoge información del endpoint y el Manager la procesa mediante decoders y reglas. En el análisis tradicional de logs, el evento pasa por predecodificación, decodificación y evaluación de reglas. Wazuh también dispone de FIM, evaluación de vulnerabilidades, SCA, inventario y Active Response.

### FIM

El File Integrity Monitoring puede detectar creación, modificación y eliminación de archivos, comparando hashes y atributos contra la información almacenada por el agente. También puede trabajar en tiempo real y, mediante Who-Data, identificar usuario y proceso asociados al cambio.

### Vulnerabilidades

Wazuh recoge inventario de software y lo correlaciona con información de vulnerabilidades para identificar paquetes vulnerables. La documentación actual indica que Vulnerability Detection viene habilitado por defecto en el Manager.

### SCA

Security Configuration Assessment revisa configuraciones contra políticas de seguridad. Wazuh distribuye políticas basadas principalmente en benchmarks CIS y permite crear políticas propias.

### Active Response

Wazuh también trae respuestas automáticas. Entre ellas está \`firewall-drop\`, que puede bloquear una IP en el firewall del endpoint. También se pueden crear scripts propios y asociarlos a reglas, niveles o grupos de alertas.

Hasta aquí, todo bien.

El problema empieza cuando intentas aplicar una política de seguridad real y descubres que:

> "vigilar todo" no significa "detectar mejor".

Normalmente significa **más ruido, más almacenamiento y más cosas que nadie revisa**.

---

# 2. La filosofía OrangeBox: no vigilar todo, vigilar lo que importa

La primera decisión fue bastante poco glamorosa:

**no queremos monitorizar el filesystem completo.**

Queremos detectar mecanismos concretos de compromiso.

La política FIM se diseñó alrededor de cinco preguntas:

1. ¿Puede esta ruta contener una puerta de entrada?
2. ¿Puede ser usada para persistencia?
3. ¿Puede contener credenciales o material de autenticación?
4. ¿Puede permitir escalamiento de privilegios?
5. ¿Puede ser usada para ocultar o alterar la evidencia?

Si la respuesta es sí, se monitoriza.

Si la respuesta es "bueno... quizás", probablemente no.

La política se separa en un perfil común y perfiles específicos para plataformas como Zimbra/Carbonio, cPanel y servidores web.

---

# 3. ¿Por qué demonios vigilamos /tmp?

Porque un atacante no necesita modificar \`/usr/bin\` para hacer daño.

Puede descargar o crear:

~~~text
/tmp/payload
/var/tmp/script.sh
/dev/shm/tool
~~~

y ejecutarlo desde ahí.

Son directorios particularmente interesantes porque:

- son escribibles por procesos y usuarios;
- se utilizan legítimamente para trabajo temporal;
- no suelen ser una ubicación permanente para software instalado;
- pueden ser utilizados para payloads, scripts, herramientas de explotación y malware;
- un atacante puede usarlos sin necesidad de modificar un binario del sistema.

Por eso OrangeBox activa FIM en:

~~~text
/tmp
/var/tmp
/dev/shm
~~~

y además habilita \`alert_new_files\`.

No nos interesa solamente que cambie algo.

Nos interesa especialmente:

> **"apareció algo nuevo aquí".**

Y hay una segunda capa.

Si ese archivo nuevo aparece con permisos de ejecución, la regla \`10410\` lo convierte en una alerta de alto nivel.

No preguntamos si se llama \`malware.sh\`.

Eso sería demasiado fácil de esquivar.

Un atacante puede llamarlo:

~~~text
update
backup
systemd-helper
x
~~~

Si aparece como ejecutable en una zona temporal crítica, la propiedad interesante es **ser ejecutable**, no el nombre.

Hay excepciones muy específicas para actividad legítima conocida, como determinados temporales de \`dracut\`, ClamAV, SpamAssassin/cPanel y el socket de MySQL.

La idea es importante:

**no se excluye \`/var/tmp\`. Se excluye solamente el comportamiento legítimo conocido.**

---

# 4. Zimbra y Carbonio: porque /tmp no es el único lugar interesante

Los servidores de correo tienen sus propias zonas temporales:

~~~text
/opt/zimbra/data/tmp
/opt/zextras/data/tmp
~~~

Zimbra y Carbonio no comparten el mismo árbol de instalación, pero operacionalmente pertenecen a la misma familia de servidores.

Esos directorios se agregan al FIM porque pueden contener artefactos generados por componentes del producto y, al mismo tiempo, pueden convertirse en un lugar interesante para código malicioso.

Aquí aparece otra regla de diseño:

**no hacemos una excepción gigantesca para "todo Zimbra".**

En vez de eso protegemos:

- temporales;
- configuración;
- SSL;
- webapps;
- binarios que pueden participar en sudo;
- mecanismos de autenticación y persistencia.

Es mucho más preciso que decir:

> "vigilemos \`/opt/zimbra\` completo y después vemos qué pasa."

Eso último es la receta clásica para construir un bonito problema de rendimiento.

---

# 5. Persistencia: donde realmente queremos enterarnos

Un atacante que consiguió acceso hoy puede querer seguir teniendo acceso mañana.

Por eso el perfil común protege mecanismos clásicos de persistencia:

~~~text
/root/.ssh
/home/*/.ssh

/etc/systemd/system
/etc/systemd/user

/etc/cron.d
/etc/cron.hourly
/etc/cron.daily
/etc/cron.weekly
/etc/cron.monthly
/var/spool/cron

/etc/profile.d
/etc/ld.so.conf.d
/etc/modprobe.d
/etc/modules-load.d
/etc/udev/rules.d
~~~

También se vigilan zonas relacionadas con:

- SSH;
- sudo;
- PAM;
- Polkit;
- identidad;
- firewall;
- DNS;
- auditoría;
- logging.

La pregunta no es:

> "¿este archivo es importante?"

La pregunta es:

> **"si un atacante modifica esto, ¿puede volver después, conseguir más privilegios o esconder lo que hizo?"**

Si la respuesta es sí, queremos una alerta.

---

# 6. Who-Data: no basta con saber que el archivo cambió

FIM puede decir:

~~~text
/etc/ssh/sshd_config
cambió
~~~

Eso está bien.

Pero en una investigación queremos algo más parecido a:

~~~text
archivo: /etc/ssh/sshd_config
usuario: root
proceso: vi
PID: 12345
~~~

Ahí aparece Who-Data.

En las rutas donde la atribución es importante, OrangeBox utiliza \`whodata="yes"\`.

Eso permite pasar de:

**"alguien cambió esto"**

a:

**"este usuario/proceso cambió esto".**

No se utiliza Who-Data indiscriminadamente porque tiene un coste operativo. Para árboles gigantes de binarios y librerías normalmente interesa detectar el cambio, no registrar una película IMAX de cada actualización legítima del sistema.

---

# 7. Los binarios de sudo: una puerta muy bonita si nadie la mira

Otro ejemplo es la política de \`sudo -> root\`.

Wazuh ya sabe detectar muchos eventos de sudo.

OrangeBox agrega una política más estricta:

~~~text
sudo -> root
     |
     +-- comando permitido para ese perfil
     |       |
     |       +--> excepción controlada
     |
     +-- cualquier otra cosa
             |
             +--> alerta
~~~

Para Zimbra/Carbonio no autorizamos:

~~~text
/opt/zimbra/*
/opt/zextras/*
~~~

Eso sería una estupidez.

Se autorizan comandos concretos que históricamente necesitan elevar privilegios, y solamente en servidores que pertenecen al perfil correspondiente.

La idea es que una excepción sea:

**comando + contexto + servidor**

y no:

**"todo lo que esté bajo /opt/zimbra está bien".**

Además, los binarios privilegiados que forman parte de esa allowlist también se vigilan mediante FIM.

Así tenemos dos controles:

1. **la regla de autenticación decide qué comando puede ejecutarse;**
2. **FIM verifica que ese comando no haya sido reemplazado o modificado.**

---

# 8. Detección de ataques: no todo evento merece un bloqueo

Aquí está una de las partes más importantes del diseño.

No usamos solamente niveles de alerta.

Usamos **comportamiento + contexto + correlación**.

Por ejemplo, un intento SSH fallido puede ser:

- un usuario equivocándose;
- un monitoreo;
- un scanner;
- un ataque.

Un solo evento no siempre dice cuál.

Pero:

~~~text
muchos fallos
     +
misma IP
     +
ventana corta
~~~

ya es otra historia.

Wazuh trae reglas nativas para correlacionar ataques de fuerza bruta, y OrangeBox construye detecciones hijas sobre esas señales en vez de reemplazarlas.

---

# 9. SSH: fallar es normal; conseguir entrar después de fallar mucho, no tanto

OrangeBox agrega varias capas.

### Login SSH exitoso

La regla \`10001\` identifica un login SSH exitoso.

Eso permite después construir correlaciones sobre un evento normalizado en lugar de intentar reinventar el parser SSH.

### Fuerza bruta completada

La regla \`10006\` correlaciona:

~~~text
fuerza bruta SSH
       +
login exitoso
       +
misma fuente
~~~

Eso es mucho más interesante que un simple "hubo un login".

### Movimiento lateral

La regla \`10008\` busca la misma IP obteniendo múltiples logins SSH exitosos en diferentes servidores dentro de cinco minutos.

No bloqueamos automáticamente eso.

¿Por qué?

Porque un jump host, una plataforma de administración o un operador pueden hacer exactamente lo mismo.

Aquí queremos **alertar e investigar**, no disparar un cañón contra la IP administrativa de turno.

---

# 10. SUDO y SU: detectar escalamiento sin romper la operación

Para \`su -> root\`, la regla \`10004\` exige que la sesión haya sido abierta para root por un usuario cuyo UID iniciador no sea 0.

Eso evita clasificar como "escalamiento" algo que ya comenzó siendo root.

Parece un detalle menor.

No lo es.

Si un proceso root hace:

~~~text
su root -c ...
~~~

no acaba de escalar privilegios.

Ya era root.

La detección correcta tiene que distinguir eso.

Para sudo, \`10005\` alerta sobre sudo exitoso hacia root cuando no existe una excepción operacional validada.

Las excepciones están separadas y se aplican al final del archivo de reglas.

Esto es importante porque una whitelist mal diseñada es simplemente una vulnerabilidad con nombre elegante.


---

# 11. Ataques web: mirar la conducta, no una URL mágica

La capa web sigue la misma filosofía.

### Fuerza bruta web

\`10025\` requiere:

- 10 respuestas HTTP 401/403;
- desde la misma IP;
- en 15 segundos.

Eso es bastante más útil que alertar por cada 401.

### Reconocimiento de archivos sensibles

\`10023\` identifica intentos sobre rutas como:

~~~text
/.env
/.aws/
/.config/gcloud/
/.oci/
/.openai/
/wp-config.php
~~~

incluyendo variantes que pueden aparecer detrás de determinados prefijos.

Después \`10026\` requiere dos eventos desde la misma IP en 30 segundos.

La idea es detectar **reconocimiento automatizado**, no castigar a alguien que accidentalmente pidió un recurso que no existe.

### Explotación web

Las reglas auxiliares \`10027\` y \`10028\` buscan señales como:

- Shellshock;
- SQL injection;
- XSS;
- traversal/LFI;
- intentos de RCE;
- SSRF;
- ejecución de comandos.

No generan una alerta individual por cada coincidencia.

Se utilizan como señales de correlación.

Cuando la misma IP acumula tres señales de ataque web en 180 segundos, \`10029\` genera una alerta crítica.

Es decir:

~~~text
señal
  +
señal
  +
señal
  +
misma IP
  +
ventana corta
       =
actividad web correlacionada
~~~

Ahí ya no estamos mirando ruido aislado.

---

# 12. Reverse proxy: porque el backend puede estar viendo al proxy

Una detección perfecta con una fuente incorrecta sigue siendo una detección mala.

Si Apache/Nginx está detrás de un reverse proxy, el backend puede registrar la IP del proxy en lugar de la IP real del cliente.

Por eso existen CDB separadas para:

- proxies autorizados para autenticación web;
- proxies autorizados para reconocimiento.

Las excepciones son específicas para cada detección.

No hacemos:

~~~text
"todo lo que venga de un proxy es bueno"
~~~

porque eso convertiría al proxy en una capa de invisibilidad.

---

# 13. Firewall: detectar el comportamiento de red

También incorporamos una capa basada en los eventos del firewall.

La idea es transformar los SYN registrados por el firewall en comportamiento.

### Escaneo TCP

La regla \`10453\` requiere:

- 12 SYN;
- 90 segundos;
- misma IP origen;
- diferentes puertos destino.

Eso intenta distinguir un port scan de alguien golpeando repetidamente un único servicio.

### SYN flood

\`10454\` requiere:

- 60 SYN;
- 10 segundos;
- misma IP origen;
- mismo puerto destino.

Aquí sí tiene sentido responder contra una fuente concreta.

### DoS distribuido

\`10455\` requiere:

- 200 IPs origen diferentes;
- 10 segundos;
- mismo puerto destino.

Pero no ejecuta \`firewall-drop\`.

¿Por qué?

Porque 200 IPs no se pueden resumir honestamente en:

> "bloquea esta IP".

La detección es útil; la respuesta automática incorrecta no.

---

# 14. IOC: pasar de "parece malo" a "esto ya lo conocemos"

Aquí entra Threat Intelligence.

Un IOC puede ser, por ejemplo:

- una IP;
- un dominio;
- un hash.

OrangeBox mantiene tres listas CDB:

~~~text
malicious-ip
malicious-domains
malware-hashes
~~~

El updater obtiene:

- IPs desde URLhaus y Emerging Threats;
- dominios desde URLhaus;
- hashes desde MalwareBazaar.

Antes de reemplazar las listas se realizan validaciones de formato y controles para rechazar actualizaciones que presenten caídas anormales de cantidad de entradas.

La idea es sencilla:

**si la fuente se rompe, no queremos convertir una lista de miles de IOCs en una lista de tres y después creer que estamos protegidos.**

---

# 15. IOC + comportamiento: la combinación que realmente importa

Un IOC aislado puede ser útil.

Un comportamiento sospechoso aislado también.

Pero cuando ambos coinciden, cambia el contexto.

Por ejemplo:

~~~text
SSH brute force
      +
IP pertenece a malicious-ip
      |
      v
10460
      |
      +--> alerta nivel 14
      |
      +--> firewall-drop
~~~

Lo mismo ocurre con:

### Port scan + IP maliciosa

\`10462\`

### SYN flood + IP maliciosa

\`10463\`

En estos casos, la IP es el origen del ataque y podemos responder directamente contra ella.

La respuesta configurada actualmente para estas tres reglas es \`firewall-drop\` durante **30 días**.

No porque "30 días suene fuerte".

Sino porque la condición previa ya exige dos piezas de evidencia:

**comportamiento de ataque + IOC conocido.**

---

# 16. IOC de salida: aquí no bloqueamos a lo bruto

Hay dos detecciones particularmente interesantes.

### HTTP hacia dominio malicioso

\`10464\`

Se basa en la detección nativa de Wazuh y eleva el evento cuando el destino pertenece a un dominio conocido como malicioso.

### DNS hacia dominio malicioso

\`10465\`

Hace lo mismo para consultas DNS.

Pero aquí **no usamos firewall-drop**.

¿Por qué?

Porque el IOC es el **destino**, no la fuente.

Bloquear \`srcip\` en ese contexto podría significar bloquear al propio servidor comprometido en lugar del destino malicioso.

La regla eleva y alerta.

La contención automática queda deliberadamente fuera hasta tener un mecanismo seguro para responder sobre el destino.

Eso es diseño de seguridad.

No todo lo que se puede automatizar se debe automatizar.

---

# 17. YARA: cuando FIM dice "apareció un archivo" hay que mirar qué contiene

FIM responde:

> "cambió un archivo".

Pero FIM no está diseñado para decidir por sí solo:

> "este archivo es un webshell".

Ahí entra YARA.

Wazuh documenta precisamente esta arquitectura: FIM detecta la creación o modificación, Active Response ejecuta YARA sobre el archivo afectado y el resultado vuelve al Manager para ser decodificado y convertido en una alerta.

Nuestra implementación hace lo mismo, pero de forma deliberadamente acotada.

~~~text
FIM 554/550
      |
      v
10420 / 10421
      |
      v
Active Response local
      |
      v
orangebox-yara.sh
      |
      +--> webshells_index.yar
      |
      +--> malware_index.yar
      |
      v
active-responses.log
      |
      v
decoder
      |
      v
10501
~~~

---

# 18. ¿Por qué YARA no escanea todo?

Porque sería una idea espectacularmente mala.

Si un servidor tiene millones de archivos y cada modificación dispara un scan de contenido, tenemos:

~~~text
más CPU
+
más I/O
+
más latencia
+
más ruido
~~~

Y no necesariamente más seguridad.

Por eso OrangeBox hace dos filtros antes de ejecutar YARA.

## Primero: ubicación

Solamente:

~~~text
/tmp
/var/tmp
/dev/shm

/opt/zimbra/data/tmp
/opt/zextras/data/tmp
~~~

## Segundo: tipo de archivo

Actualmente se consideran candidatos extensiones como:

~~~text
jsp
jspx
php
phtml
phar
asp
aspx
cgi
pl
py
rb
sh
bash
zsh
war
class
~~~

No porque la extensión determine si algo es malware.

Sirve para controlar el coste de la inspección.

La capa YARA sigue siendo la que analiza el contenido.

---

![Flujo FIM YARA IOC](https://www.orangebox.cl/blog/images/wazuh-repo/fig2.svg)

# 19. Las firmas YARA también tienen una decisión importante

OrangeBox dejó de mantener una colección paralela de firmas propias como mecanismo principal.

El runtime actual utiliza los índices oficiales de:

**Yara-Rules/rules**

con:

~~~text
webshells_index.yar
malware_index.yar
~~~

El instalador valida los índices antes de reemplazar el ruleset y registra:

~~~text
YARA-RULES-COMMIT
YARA-RULES-REPOSITORY
YARA-RULES-BRANCH
~~~

Eso nos da trazabilidad.

Si mañana aparece una alerta:

> "YARA detectó X"

podemos saber exactamente qué versión del ruleset estaba instalada.

No tenemos una carpeta mágica de firmas que alguien modificó hace ocho meses y que ahora nadie recuerda de dónde salió.

---

# 20. YARA todavía no borra nada

Esto también es intencional.

La coincidencia YARA genera:

~~~text
10501
nivel 14
~~~

y entra al flujo de alerta.

Pero \`10501\` no elimina automáticamente el archivo.

¿Por qué?

Porque **YARA es detección de contenido**.

Antes de destruir algo queremos medir falsos positivos y comportamiento real sobre:

- Linux;
- cPanel;
- Zimbra;
- Carbonio;
- servidores web.

La contención destructiva se separa de la detección.

---

# 21. Pero si tenemos un hash confirmado, ahí sí: cuarentena

Wazuh ya dispone de detección de malware basada en IOC y hashes.

Cuando la regla nativa \`99901\` confirma un hash malicioso, OrangeBox tiene una respuesta específica:

~~~text
99901
  |
  v
orangebox-quarantine.py
  |
  +--> comprueba path
  +--> rechaza symlinks
  +--> calcula SHA-256
  +--> compara contra el hash esperado
  +--> copia a cuarentena
  +--> vuelve a verificar SHA-256
  +--> guarda metadata
  +--> cambia permisos a 0400
  +--> elimina el original
~~~

La cuarentena se organiza por SHA-256.

Si algo falla durante el proceso, se intenta preservar el original.

La respuesta está diseñada para fallar cerrado.

No hacemos:

~~~text
"llegó una alerta de malware, rm -rf y que Dios reparta suerte"
~~~

---

# 22. Ataques en ejecución: FIM no es suficiente

Hay una diferencia importante entre:

**"se creó un archivo ejecutable"**

y:

**"ese archivo se ejecutó".**

Por eso existe una segunda capa con auditd.

La regla \`10600\` detecta ejecución desde:

~~~text
/tmp
/var/tmp
/dev/shm
~~~

Y \`10601\` eleva a nivel 14 cuando la ejecución está asociada a intérpretes como:

~~~text
bash
sh
dash
zsh
ksh
python
perl
php
ruby
node
~~~

El resultado es una defensa en profundidad:

~~~text
archivo aparece
     |
     v
FIM
     |
     +--> ejecutable nuevo
     |
     +--> YARA
     |
     +--> ejecución real mediante auditd
~~~

No dependemos de una sola señal.

---

# 23. ¿Cómo decidimos cuándo bloquear?

Esta fue probablemente la parte más importante del diseño.

No toda alerta crítica significa:

> "bloquea inmediatamente".

Usamos tres niveles conceptuales.

## Nivel 1 — Evidencia

Algo cambió.

Ejemplos:

- archivo nuevo;
- archivo modificado;
- login;
- 401;
- SYN;
- comando ejecutado.

Esto puede producir telemetría o una alerta.

## Nivel 2 — Comportamiento

Varios eventos forman un patrón.

Ejemplos:

- 10 HTTP 401/403 en 15 segundos;
- 12 SYN sobre distintos puertos;
- 60 SYN sobre el mismo puerto;
- tres señales web desde la misma IP;
- tres logins SSH en servidores distintos.

Aquí aparece una detección de ataque.

## Nivel 3 — Confirmación externa

El comportamiento además coincide con información independiente:

~~~text
comportamiento sospechoso
        +
IOC conocido
        =
alta confianza
~~~

Ahí es donde OrangeBox habilita respuestas más agresivas.

Por ejemplo:

~~~text
SSH brute force + malicious IP
port scan + malicious IP
SYN flood + malicious IP
        |
        v
firewall-drop 30 días
~~~

La regla no bloquea porque "la IP se ve fea".

Bloquea porque tenemos **comportamiento + inteligencia de amenaza**.

---

# 24. ¿Y por qué algunas cosas NO tienen Active Response?

Porque un firewall no entiende contexto.

Por ejemplo:

### 200 IPs contra un puerto

Puede ser un ataque distribuido.

Pero bloquear "la IP atacante" no tiene sentido porque son 200.

### DNS hacia dominio malicioso

La fuente es nuestro propio servidor.

Bloquear \`srcip\` sería bloquearnos a nosotros mismos.

### Tres logins SSH exitosos desde una IP

Puede ser movimiento lateral.

Pero también puede ser el administrador haciendo su trabajo.

En esos casos:

**alertar > destruir.**

La automatización se reserva para eventos donde la respuesta es suficientemente precisa.


---

![De la señal al bloqueo](https://www.orangebox.cl/blog/images/wazuh-repo/fig3.svg)

# 25. La protección no está en una regla gigante

Otra decisión importante del proyecto es separar responsabilidades.

Tenemos:

~~~text
agent.conf
    |
    +--> recopila evidencia

rules
    |
    +--> interpreta evidencia

CDB / IOC
    |
    +--> aporta contexto

YARA
    |
    +--> analiza contenido

Active Response
    |
    +--> ejecuta una acción

correo / reportes
    |
    +--> entrega la información
~~~

Esto permite cambiar una capa sin destruir las demás.

Por ejemplo, podemos cambiar la fuente de IOC sin reescribir las reglas de SSH.

Podemos actualizar YARA sin modificar FIM.

Podemos cambiar una whitelist sin tocar el detector universal.

Y podemos apagar una respuesta automática sin perder la detección.

---

# 26. El criterio más importante: no confundir detección con excepción

Una excepción debe ser específica.

Por ejemplo:

~~~text
NO:
  /var/tmp/*

SÍ:
  /var/tmp/dracut.*
~~~

No:

~~~text
todo /opt/zimbra
~~~

Sí:

~~~text
comando concreto
+
perfil zimbra
+
hostname autorizado
~~~

No:

~~~text
todo lo que venga de un reverse proxy
~~~

Sí:

~~~text
IP concreta
+
detección concreta
~~~

Esta filosofía aparece repetidamente en el repositorio.

Una whitelist demasiado amplia no reduce falsos positivos.

**Reduce la seguridad.**

---

# 27. Entonces, ¿qué agregamos realmente a Wazuh?

En resumen:

| Capa | Wazuh | OrangeBox |
|---|---|---|
| Logs | Sí | Reglas y correlaciones específicas |
| SSH | Sí | Login, brute force exitoso, lateral movement |
| SUDO/SU | Sí | Política de escalamiento y whitelists por contexto |
| FIM | Sí | Política quirúrgica por mecanismo de ataque |
| Who-Data | Sí | Priorizado en rutas críticas |
| Temporales | Sí | Detección de ejecutables y candidatos YARA |
| Web | Sí | Brute force, descubrimiento y correlación de explotación |
| Firewall | Sí | Correlación de SYN, scan y DoS |
| IOC | Sí | Listas propias, actualización, correlación y respuesta |
| YARA | Integrable | Pipeline FIM → YARA → alerta |
| Malware hash | Sí | Cuarentena segura para IOC confirmado |
| Active Response | Sí | Asociado solamente a detecciones seleccionadas |
| Auditoría | Sí | Ejecución desde zonas temporales críticas |
| Zimbra/Carbonio | Parcial | Perfil FIM y política de sudo específica |
| cPanel | Parcial | Perfil específico y excepciones operacionales |

---

# 28. La arquitectura completa

Juntando todo:

~~~text
                         ┌──────────────────────┐
                         │     SERVIDOR LINUX   │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              v                     v                     v
            LOGS                   FIM                  AUDITD
              │                     │                     │
              v                     v                     v
        ┌───────────┐        ┌────────────┐        ┌────────────┐
        │   reglas  │        │ FIM rules  │        │ execution  │
        └─────┬─────┘        └──────┬─────┘        └──────┬─────┘
              │                     │                     │
              │             ┌───────┴────────┐            │
              │             │                │            │
              │             v                v            │
              │          archivo          candidato       │
              │          nuevo/mod.        YARA            │
              │                              │             │
              │                              v             │
              │                           YARA              │
              │                              │             │
              └──────────────┬───────────────┴─────────────┘
                             │
                             v
                      ┌──────────────┐
                      │   CORRELACIÓN │
                      │   + IOC       │
                      └──────┬───────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              v              v              v
            ALERTA        CORREO        RESPUESTA
                                         │
                         ┌───────────────┼──────────────┐
                         │               │              │
                         v               v              v
                    firewall-drop    quarantine     sin acción
~~~

La gracia no está en tener muchas reglas.

Está en que cada regla tenga una razón.

---

# 29. El resultado: seguridad operable

El repositorio OrangeBox no pretende reemplazar Wazuh.

Pretende hacer algo bastante más útil:

**convertir las capacidades de Wazuh en una política de seguridad operable para servidores Linux reales.**

La diferencia está en el detalle.

Wazuh puede decir:

> "un archivo cambió".

OrangeBox pregunta:

> "¿en qué ruta?"

> "¿era una ruta de persistencia?"

> "¿era un temporal?"

> "¿apareció como ejecutable?"

> "¿es un script?"

> "¿lo puede reconocer YARA?"

> "¿el hash está en nuestra inteligencia?"

> "¿la IP que provocó esto ya está catalogada?"

> "¿el comportamiento parece un ataque?"

> "¿hay suficiente evidencia para bloquear?"

Y solamente después:

> **"¿hacemos algo automáticamente?"**

Ese último paso es importante.

Porque automatizar seguridad es fácil.

Automatizarla **sin pegarle un tiro en el pie al servidor** es otra cosa.

---

# 30. Todo esto está versionado

La configuración no vive en una caja negra.

Está versionada en Git.

Eso incluye:

- reglas;
- decoders;
- perfiles FIM;
- IOC;
- Active Response;
- scripts;
- integración YARA;
- cuarentena;
- documentación;
- herramientas de actualización.

El repositorio público está aquí:

**https://github.com/OrangeBox-Labs/Wazuh**

La idea es que cualquiera pueda revisar qué estamos haciendo, por qué lo hacemos y, sobre todo, **qué no estamos haciendo**.

Porque en seguridad, muchas veces la decisión importante no es la regla que agregaste.

Es la respuesta automática que decidiste no agregar.

---

## Referencias

- [Wazuh — documentación oficial](https://documentation.wazuh.com/)
- [Wazuh — File Integrity Monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Wazuh — FIM + YARA](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/fim-yara.html)
- [Wazuh — Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [Wazuh — Threat Intelligence / CDB lists](https://documentation.wazuh.com/current/user-manual/capabilities/threat-detection/cdb-lists.html)
- [Yara-Rules](https://github.com/Yara-Rules/rules)
- [OrangeBox-Labs/Wazuh](https://github.com/OrangeBox-Labs/Wazuh)
