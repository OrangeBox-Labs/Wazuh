#!/bin/bash

# OrangeBox - Wazuh Agent unificado / Firewall Logging
# Compatible: CentOS 6/7/8 and AlmaLinux 8/9/10.
#
# Logging backend by Enterprise Linux major version:
#   EL 6    : iptables -> rsyslog -> /var/log/orangebox-firewall.log -> Wazuh
#   EL 7+   : iptables -> journald -> Wazuh
#
# Idempotent: existing correct settings are preserved; missing settings are added;
# unexpected existing settings cause an error instead of guessing.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# ---------------------------------------------------------------------------
# CONFIGURACION - EDITAR SOLO ESTA SECCION
# ---------------------------------------------------------------------------
IS_CPANEL=''
WAZUH_VERSION='4.14.7'
WAZUH_MANAGER='wazuh.orangebox.cl'
WAZUH_AGENT_GROUP='default'
WAZUH_AGENT_NAME=''
WAZUH_REGISTRATION_PASSWORD='tu_pass'
WAZUH_AGENT_RPM=''
WAZUH_OSSEC_SIZE='1G'
WAZUH_OSSEC_LV='wazuh'
WAZUH_OSSEC_VG=''
YARA_RULES_REPO='https://github.com/Yara-Rules/rules.git'
YARA_RULES_BRANCH='master'
YARA_BIN=''
YARA_NO_PACKAGE_INSTALL='no'
ORANGEBOX_PUBLIC_IP=''
ORANGEBOX_PRIVATE_IP=''

WAZUH_HOME='/var/ossec'
FIREWALL_LOG="/var/log/orangebox-firewall.log"
LOGROTATE_FILE="/etc/logrotate.d/orangebox-firewall"
RSYSLOG_FILE="/etc/rsyslog.d/orangebox-firewall.conf"
WAZUH_FIREWALL_HELPER="/var/ossec/bin/orangebox-iptables"
WAZUH_FIREWALL_STOP_HELPER="/var/ossec/bin/orangebox-iptables-stop"
WAZUH_FIREWALL_SERVICE="/etc/systemd/system/orangebox-iptables.service"
EL_MAJOR=""
LOGGING_BACKEND=""

ERROR_COUNT=0

step_error() {
    echo "ERROR: $*" >&2
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

fail() { echo "ERROR: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }
warn() { echo "AVISO: $*" >&2; }
has() { command -v "$1" >/dev/null 2>&1; }

# ... contenido del instalador sin cambios ...
