#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.0-final"

MODE="full"
OUTDIR=""
IOC_FILE=""
INCLUDE_COPY=1
INCLUDE_WEB=1
INCLUDE_CONTAINERS=1
MAX_FIND_DEPTH_TMP=5
JOURNAL_SINCE="14 days ago"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown-host)"
TS_UTC="$(date -u +%Y%m%dT%H%M%SZ)"

usage() {
  cat <<'EOF'
incident_diagnosis.sh - Linux Incident Response / Forensic Triage

Usage:
  sudo ./incident_diagnosis.sh [options]

Options:
  -o, --outdir PATH         Output directory
  -m, --mode MODE           quick | full   (default: full)
  --ioc FILE                File with IOC patterns (one per line)
  --no-copy                 Do not copy priority artifacts
  --no-web                  Skip web application collection
  --no-containers           Skip container collection
  -h, --help                Show help

Examples:
  sudo ./incident_diagnosis.sh
  sudo ./incident_diagnosis.sh --mode quick -o /root/ir_case_01
  sudo ./incident_diagnosis.sh --ioc iocs.txt
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--outdir)
      OUTDIR="${2:-}"; shift 2 ;;
    -m|--mode)
      MODE="${2:-}"; shift 2 ;;
    --ioc)
      IOC_FILE="${2:-}"; shift 2 ;;
    --no-copy)
      INCLUDE_COPY=0; shift ;;
    --no-web)
      INCLUDE_WEB=0; shift ;;
    --no-containers)
      INCLUDE_CONTAINERS=0; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ "$MODE" != "quick" && "$MODE" != "full" ]]; then
  echo "Invalid mode: $MODE" >&2
  exit 1
fi

if [[ -z "$OUTDIR" ]]; then
  OUTDIR="./incident_diagnosis_${HOSTNAME_FQDN}_${TS_UTC}"
fi

RAW_DIR="${OUTDIR}/raw"
TXT_DIR="${OUTDIR}/text"
JSON_DIR="${OUTDIR}/json"
TIMELINE_DIR="${OUTDIR}/timeline"
HASH_DIR="${OUTDIR}/hashes"
ERR_DIR="${OUTDIR}/errors"
META_DIR="${OUTDIR}/meta"
WEB_DIR="${OUTDIR}/web"
IOC_DIR="${OUTDIR}/ioc"
REPORT_DIR="${OUTDIR}/report"

mkdir -p "$RAW_DIR" "$TXT_DIR" "$JSON_DIR" "$TIMELINE_DIR" "$HASH_DIR" "$ERR_DIR" "$META_DIR" "$WEB_DIR" "$IOC_DIR" "$REPORT_DIR"

exec 3>>"${ERR_DIR}/stderr.log"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "${META_DIR}/run.log"
}

warn() {
  printf '[%s] WARN: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "${META_DIR}/run.log"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

run_cmd() {
  local name="$1"; shift
  log "collect: ${name}"
  {
    printf '### COMMAND ###\n'
    printf '%q ' "$@"
    printf '\n\n### OUTPUT ###\n'
    "$@"
  } > "${TXT_DIR}/${name}.txt" 2>>"${ERR_DIR}/stderr.log" || true
}

run_shell() {
  local name="$1"
  local cmd="$2"
  log "collect(shell): ${name}"
  {
    printf '### SHELL ###\n%s\n\n### OUTPUT ###\n' "$cmd"
    bash -lc "$cmd"
  } > "${TXT_DIR}/${name}.txt" 2>>"${ERR_DIR}/stderr.log" || true
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  [[ -e "$src" ]] || return 0
  mkdir -p "$dst"
  cp -a --parents "$src" "$dst" 2>>"${ERR_DIR}/stderr.log" || true
}

append_section() {
  local file="$1"
  local title="$2"
  {
    echo
    echo "================================================================"
    echo "$title"
    echo "================================================================"
  } >> "$file"
}

sha256_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  sha256sum "$f" >> "${HASH_DIR}/sha256.txt" 2>>"${ERR_DIR}/stderr.log" || true
}

sha256_dir() {
  local d="$1"
  [[ -d "$d" ]] || return 0
  find "$d" -type f 2>/dev/null | while read -r f; do
    sha256sum "$f" >> "${HASH_DIR}/sha256.txt" 2>>"${ERR_DIR}/stderr.log" || true
  done
}

json_escape() {
  python3 - <<'PY' "$1"
import json,sys
print(json.dumps(sys.argv[1]))
PY
}

init_metadata() {
  {
    echo "version=${VERSION}"
    echo "mode=${MODE}"
    echo "hostname=${HOSTNAME_FQDN}"
    echo "utc_start=${TS_UTC}"
    echo "uid=$(id -u)"
    echo "euid=${EUID}"
    echo "kernel=$(uname -a 2>/dev/null || true)"
    echo "cwd=$(pwd)"
    echo "outdir=${OUTDIR}"
  } > "${META_DIR}/metadata.txt"

  if [[ $EUID -ne 0 ]]; then
    warn "Ideal executar como root para visibilidade completa."
    echo "warning=run_as_root_recommended" >> "${META_DIR}/metadata.txt"
  fi
}

collect_identity() {
  run_cmd "date_utc" date -u
  run_shell "hostname" 'hostnamectl 2>/dev/null || hostname 2>/dev/null || true'
  run_cmd "uname" uname -a
  run_shell "os_release" 'cat /etc/os-release 2>/dev/null || true'
  run_shell "uptime" 'uptime 2>/dev/null || true'
  run_shell "who" 'who -a 2>/dev/null || true'
  run_shell "w" 'w 2>/dev/null || true'
  run_shell "last" 'last -a 2>/dev/null | head -n 300 || true'
  run_shell "lastlog" 'lastlog 2>/dev/null | sed -n "1,300p" || true'
  run_shell "timedatectl" 'timedatectl 2>/dev/null || true'
}

collect_network() {
  run_shell "ip_addr" 'ip a 2>/dev/null || ifconfig -a 2>/dev/null || true'
  run_shell "ip_route" 'ip route 2>/dev/null || route -n 2>/dev/null || true'
  run_shell "ip_rule" 'ip rule 2>/dev/null || true'
  run_shell "ip_neigh" 'ip neigh 2>/dev/null || arp -an 2>/dev/null || true'
  run_shell "ss_listening" 'ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || true'
  run_shell "ss_established" 'ss -tpn 2>/dev/null || netstat -tpn 2>/dev/null || true'
  run_shell "resolv_conf" 'cat /etc/resolv.conf 2>/dev/null || true'
  run_shell "hosts_file" 'cat /etc/hosts 2>/dev/null || true'
  run_shell "iptables_filter" 'iptables -S 2>/dev/null || true'
  run_shell "iptables_nat" 'iptables -t nat -S 2>/dev/null || true'
  run_shell "nft_ruleset" 'nft list ruleset 2>/dev/null || true'
}

collect_processes() {
  run_shell "ps_auxwf" 'ps auxwf 2>/dev/null || true'
  run_shell "ps_forest" 'ps -ef --forest 2>/dev/null || ps -ef 2>/dev/null || true'
  run_shell "pstree" 'pstree -ap 2>/dev/null || true'
  run_shell "lsof_head" 'lsof -nP 2>/dev/null | sed -n "1,800p" || true'
  run_shell "deleted_binaries_in_use" 'lsof +L1 -nP 2>/dev/null || true'

  {
    echo -e "pid\tppid\tuid\tuser\tstart\texe\tcwd\tcmdline"
    for p in /proc/[0-9]*; do
      [[ -d "$p" ]] || continue
      pid="${p##*/}"
      ppid="$(awk "/^PPid:/{print \$2}" "$p/status" 2>/dev/null || true)"
      uid="$(awk "/^Uid:/{print \$2}" "$p/status" 2>/dev/null || true)"
      user="$(stat -c %U "$p" 2>/dev/null || true)"
      start="$(ps -p "$pid" -o lstart= 2>/dev/null || true)"
      exe="$(readlink -f "$p/exe" 2>/dev/null || true)"
      cwd="$(readlink -f "$p/cwd" 2>/dev/null || true)"
      cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$pid" "$ppid" "$uid" "$user" "$start" "$exe" "$cwd" "$cmd"
    done
  } > "${TXT_DIR}/proc_process_summary.tsv" 2>>"${ERR_DIR}/stderr.log" || true
}

collect_users_auth() {
  run_shell "passwd" 'cat /etc/passwd 2>/dev/null || true'
  run_shell "group" 'cat /etc/group 2>/dev/null || true'
  run_shell "shadow_perm" 'ls -l /etc/shadow 2>/dev/null || true'
  run_shell "sudoers" 'cat /etc/sudoers 2>/dev/null || true'
  run_shell "sudoers_d" 'find /etc/sudoers.d -maxdepth 1 -type f -exec sh -c '"'"'echo "### {}"; cat "{}"; echo'"'"' \; 2>/dev/null || true'
  run_shell "login_defs" 'cat /etc/login.defs 2>/dev/null || true'
  run_shell "pam_d" 'grep -R . /etc/pam.d 2>/dev/null || true'
  run_shell "sshd_config" 'cat /etc/ssh/sshd_config 2>/dev/null || true'
  run_shell "sshd_config_d" 'grep -R . /etc/ssh/sshd_config.d 2>/dev/null || true'

  {
    for d in /root /home/*; do
      [[ -d "$d" ]] || continue
      echo "### USERDIR ${d}"
      ls -la "${d}/.ssh" 2>/dev/null || true
      for f in authorized_keys authorized_keys2 known_hosts config; do
        if [[ -f "${d}/.ssh/${f}" ]]; then
          echo "--- ${d}/.ssh/${f} ---"
          cat "${d}/.ssh/${f}" 2>/dev/null || true
          echo
        fi
      done
    done
  } > "${TXT_DIR}/ssh_user_artifacts.txt" 2>>"${ERR_DIR}/stderr.log" || true
}

collect_persistence() {
  run_shell "systemd_unit_files" 'systemctl list-unit-files --type=service --no-pager 2>/dev/null || true'
  run_shell "systemd_units_all" 'systemctl list-units --type=service --all --no-pager 2>/dev/null || true'
  run_shell "systemd_timers" 'systemctl list-timers --all --no-pager 2>/dev/null || true'
  run_shell "systemd_failed" 'systemctl --failed --no-pager 2>/dev/null || true'

  {
    find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
      -maxdepth 3 \( -type f -o -type l \) 2>/dev/null | sort | while read -r f; do
      echo "### ${f}"
      cat "$f" 2>/dev/null || true
      echo
    done
  } > "${TXT_DIR}/systemd_units_content.txt" 2>>"${ERR_DIR}/stderr.log" || true

  run_shell "crontab_system" 'cat /etc/crontab 2>/dev/null || true'
  run_shell "cron_dirs" 'find /etc/cron* /var/spool/cron /var/spool/cron/crontabs -maxdepth 4 -type f -exec sh -c '"'"'echo "### {}"; cat "{}"; echo'"'"' \; 2>/dev/null || true'

  {
    cut -d: -f1 /etc/passwd 2>/dev/null | while read -r u; do
      echo "### USER ${u}"
      crontab -u "$u" -l 2>/dev/null || true
      echo
    done
  } > "${TXT_DIR}/crontab_per_user.txt" 2>>"${ERR_DIR}/stderr.log" || true

  run_shell "profile_files" 'grep -R . /etc/profile /etc/profile.d /etc/bash.bashrc /etc/zsh* 2>/dev/null || true'
  run_shell "ld_preload" 'cat /etc/ld.so.preload 2>/dev/null || true'
  run_shell "rc_local" 'cat /etc/rc.local 2>/dev/null || true'
  run_shell "init_d" 'find /etc/init.d -maxdepth 1 -type f -exec sh -c '"'"'echo "### {}"; sed -n "1,300p" "{}"; echo'"'"' \; 2>/dev/null || true'
}

collect_logs() {
  if [[ "$MODE" == "full" ]]; then
    copy_if_exists /var/log "$RAW_DIR"
  fi

  run_shell "journal_boot" 'journalctl -b --no-pager 2>/dev/null | sed -n "1,5000p" || true'
  run_shell "journal_since" "journalctl --since \"${JOURNAL_SINCE}\" --no-pager 2>/dev/null | sed -n '1,12000p' || true"
  run_shell "auth_log" 'cat /var/log/auth.log 2>/dev/null || cat /var/log/secure 2>/dev/null || true'
  run_shell "syslog" 'cat /var/log/syslog 2>/dev/null || cat /var/log/messages 2>/dev/null || true'
  run_shell "kern_log" 'cat /var/log/kern.log 2>/dev/null || true'
  run_shell "audit_log" 'sed -n "1,12000p" /var/log/audit/audit.log 2>/dev/null || true'
  run_shell "grep_ssh" 'grep -RinE "sshd|ssh" /var/log 2>/dev/null | sed -n "1,5000p" || true'
  run_shell "grep_sudo" 'grep -Rin "sudo" /var/log 2>/dev/null | sed -n "1,5000p" || true'
  run_shell "grep_authfail" 'grep -RinE "Failed|failure|invalid user|authentication failure|FAILED LOGIN" /var/log 2>/dev/null | sed -n "1,5000p" || true'
}

collect_recent_and_temp() {
  run_shell "tmp_listing" "find /tmp /var/tmp /dev/shm -xdev -maxdepth ${MAX_FIND_DEPTH_TMP} -printf '%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %y %p\n' 2>/dev/null | sort || true"
  run_shell "tmp_exec_candidates" 'find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null | sort || true'
  run_shell "tmp_hidden" 'find /tmp /var/tmp /dev/shm -xdev -name ".*" -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null | sort || true'
  run_shell "recent_etc" 'find /etc -xdev -type f -mtime -30 -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null | sort || true'
  run_shell "recent_home_root" 'find /root /home -xdev -type f -mtime -30 -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null | sort || true'
  run_shell "recent_usr_local" 'find /usr/local/bin /usr/local/sbin -xdev -type f -mtime -45 -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null | sort || true'
}

collect_integrity() {
  run_shell "suid_files" 'find / -xdev -perm -4000 -type f 2>/dev/null | sort || true'
  run_shell "sgid_files" 'find / -xdev -perm -2000 -type f 2>/dev/null | sort || true'
  run_shell "capabilities" 'getcap -r / 2>/dev/null || true'
  run_shell "world_writable_dirs" 'find / -xdev -type d -perm -0002 2>/dev/null | sort || true'
  run_shell "world_writable_files" 'find / -xdev -type f -perm -0002 2>/dev/null | sort || true'
  run_shell "loaded_modules" 'lsmod 2>/dev/null || true'
  run_shell "ldconfig_p" 'ldconfig -p 2>/dev/null | sed -n "1,2000p" || true'

  if have debsums; then
    run_shell "debsums_changed" 'debsums -s 2>/dev/null || true'
  fi

  if have rpm; then
    run_shell "rpm_verify" 'rpm -Va 2>/dev/null || true'
  fi
}

collect_histories() {
  {
    for d in /root /home/*; do
      [[ -d "$d" ]] || continue
      echo "### ${d}"
      for f in .bash_history .zsh_history .ash_history .python_history .mysql_history .psql_history .sqlite_history .wget-hsts; do
        if [[ -f "${d}/${f}" ]]; then
          echo "--- ${d}/${f} ---"
          sed -n '1,8000p' "${d}/${f}" 2>/dev/null || true
          echo
        fi
      done
    done
  } > "${TXT_DIR}/shell_histories.txt" 2>>"${ERR_DIR}/stderr.log" || true
}

collect_packages_services() {
  if have dpkg; then
    run_shell "dpkg_list" 'dpkg -l 2>/dev/null || true'
  fi

  if have rpm; then
    run_shell "rpm_list" 'rpm -qa 2>/dev/null || true'
  fi

  run_shell "service_status_snapshot" 'systemctl status ssh sshd cron crond rsyslog auditd nginx apache2 httpd php-fpm docker containerd 2>/dev/null || true'
}

collect_hunting() {
  run_shell "pattern_hunting" 'grep -RInaE "curl|wget|nc |ncat|socat|base64|python -c|perl -e|php -r|bash -c|/dev/tcp/|nohup|mkfifo|LD_PRELOAD|authorized_keys|systemctl enable|crontab|@reboot|eval\(|assert\(|shell_exec|passthru|exec\(|system\(" /etc /usr/local /tmp /var/tmp /dev/shm /root /home 2>/dev/null | sed -n "1,12000p" || true'
  run_shell "suspicious_process_exec_paths" 'ps aux 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/" | grep -v grep || true'
  run_shell "suspicious_network_tools" 'grep -RInaE "curl|wget|scp|rsync|nc |ncat|socat|ftp|tftp|python -m http.server|busybox" /etc /root /home /usr/local /tmp /var/tmp /dev/shm 2>/dev/null | sed -n "1,6000p" || true'
}

collect_web() {
  [[ "$INCLUDE_WEB" -eq 1 ]] || return 0

  log "collect: web apps"

  run_shell "web_nginx_vhosts" 'find /etc/nginx -maxdepth 4 -type f -exec sh -c '"'"'echo "### {}"; sed -n "1,400p" "{}"; echo'"'"' \; 2>/dev/null || true'
  run_shell "web_apache_vhosts" 'find /etc/apache2 /etc/httpd -maxdepth 4 -type f -exec sh -c '"'"'echo "### {}"; sed -n "1,400p" "{}"; echo'"'"' \; 2>/dev/null || true'
  run_shell "web_php_configs" 'find /etc/php* /etc/php /etc/opt/remi /etc -maxdepth 5 -type f \( -name "php.ini" -o -name "*.conf" \) -exec sh -c '"'"'echo "### {}"; sed -n "1,300p" "{}"; echo'"'"' \; 2>/dev/null || true'

  {
    echo "/var/www"
    echo "/srv/www"
    echo "/usr/share/nginx/html"
    echo "/var/www/html"
    echo "/opt"
    echo "/srv"
  } > "${WEB_DIR}/candidate_webroots.txt"

  {
    for base in /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv; do
      [[ -d "$base" ]] || continue
      find "$base" -xdev -maxdepth 6 -type f \
        \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" -o -name "*.jsp" -o -name "*.jspx" -o -name "*.asp" -o -name "*.aspx" -o -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name ".env" -o -name "config.php" -o -name "wp-config.php" -o -name "settings.py" -o -name "application.properties" -o -name "Dockerfile" -o -name "docker-compose.yml" -o -name "docker-compose.yaml" \) \
        -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null
    done | sort
  } > "${WEB_DIR}/web_files_inventory.txt" 2>>"${ERR_DIR}/stderr.log" || true

  run_shell "web_recent_files" 'find /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv -xdev -type f -mtime -30 -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null | sort || true'
  run_shell "web_world_writable" 'find /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv -xdev \( -type d -o -type f \) -perm -0002 2>/dev/null | sort || true'
  run_shell "web_upload_dirs" 'find /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv -xdev -type d \( -iname "*upload*" -o -iname "*uploads*" -o -iname "*files*" -o -iname "*media*" -o -iname "*tmp*" -o -iname "*cache*" \) 2>/dev/null | sort || true'

  run_shell "web_shell_patterns" 'grep -RInaE "eval\(|base64_decode\(|gzinflate\(|assert\(|shell_exec\(|passthru\(|system\(|exec\(|preg_replace.*/e|proc_open\(|popen\(|cmd\.exe|powershell|Runtime\.getRuntime\(\)|ProcessBuilder|child_process|subprocess|os\.system|pty\.spawn|create_function\(" /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv 2>/dev/null | sed -n "1,12000p" || true'

  run_shell "web_env_and_secrets" 'find /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv -xdev -type f \( -name ".env" -o -name "*.env" -o -name "wp-config.php" -o -name "config.php" -o -name "database.yml" -o -name "settings.py" -o -name "application.properties" -o -name "secrets.yml" -o -name "*.pem" -o -name "*.key" -o -name "*.crt" \) -printf "%TY-%Tm-%Td %TH:%TM:%TS %u %g %m %s %p\n" 2>/dev/null | sort || true'

  run_shell "web_access_logs" 'find /var/log/nginx /var/log/apache2 /var/log/httpd -maxdepth 3 -type f 2>/dev/null | while read -r f; do echo "### $f"; sed -n "1,3000p" "$f"; echo; done || true'
  run_shell "web_error_logs" 'find /var/log/nginx /var/log/apache2 /var/log/httpd -maxdepth 3 -type f \( -iname "*error*" -o -iname "*php*" \) 2>/dev/null | while read -r f; do echo "### $f"; sed -n "1,3000p" "$f"; echo; done || true'

  if [[ "$INCLUDE_COPY" -eq 1 && "$MODE" == "full" ]]; then
    mkdir -p "${RAW_DIR}/web_priority"
    for d in /etc/nginx /etc/apache2 /etc/httpd /var/www /srv/www /usr/share/nginx/html /var/www/html; do
      [[ -e "$d" ]] || continue
      copy_if_exists "$d" "${RAW_DIR}/web_priority"
    done
  fi
}

collect_containers() {
  [[ "$INCLUDE_CONTAINERS" -eq 1 ]] || return 0

  log "collect: containers"

  if have docker; then
    run_shell "docker_info" 'docker info 2>/dev/null || true'
    run_shell "docker_ps" 'docker ps -a --no-trunc 2>/dev/null || true'
    run_shell "docker_images" 'docker images 2>/dev/null || true'
    run_shell "docker_networks" 'docker network ls 2>/dev/null || true'
    run_shell "docker_volumes" 'docker volume ls 2>/dev/null || true'

    {
      docker ps -aq 2>/dev/null | while read -r cid; do
        [[ -n "$cid" ]] || continue
        echo "### CONTAINER $cid"
        docker inspect "$cid" 2>/dev/null || true
        echo
      done
    } > "${TXT_DIR}/docker_inspect.txt" 2>>"${ERR_DIR}/stderr.log" || true
  fi

  if have crictl; then
    run_shell "crictl_ps" 'crictl ps -a 2>/dev/null || true'
    run_shell "crictl_images" 'crictl images 2>/dev/null || true'
  fi

  copy_if_exists /var/lib/docker "$RAW_DIR"
  copy_if_exists /etc/docker "$RAW_DIR"
  copy_if_exists /var/lib/containerd "$RAW_DIR"
  copy_if_exists /etc/containerd "$RAW_DIR"
  copy_if_exists /etc/kubernetes "$RAW_DIR"
}

collect_copy_priority() {
  [[ "$INCLUDE_COPY" -eq 1 ]] || return 0

  log "copy: priority artifacts"
  mkdir -p "${RAW_DIR}/priority"

  copy_if_exists /etc/passwd "${RAW_DIR}/priority"
  copy_if_exists /etc/group "${RAW_DIR}/priority"
  copy_if_exists /etc/sudoers "${RAW_DIR}/priority"
  copy_if_exists /etc/ssh "${RAW_DIR}/priority"
  copy_if_exists /etc/ld.so.preload "${RAW_DIR}/priority"
  copy_if_exists /etc/crontab "${RAW_DIR}/priority"
  copy_if_exists /etc/cron.d "${RAW_DIR}/priority"
  copy_if_exists /etc/cron.daily "${RAW_DIR}/priority"
  copy_if_exists /etc/systemd/system "${RAW_DIR}/priority"
  copy_if_exists /etc/profile "${RAW_DIR}/priority"
  copy_if_exists /etc/profile.d "${RAW_DIR}/priority"
  copy_if_exists /etc/bash.bashrc "${RAW_DIR}/priority"
  copy_if_exists /etc/hosts "${RAW_DIR}/priority"
  copy_if_exists /etc/resolv.conf "${RAW_DIR}/priority"

  for d in /root /home/*; do
    [[ -d "$d" ]] || continue
    copy_if_exists "${d}/.ssh" "${RAW_DIR}/priority"
    for f in .bash_history .zsh_history .profile .bashrc .zshrc; do
      copy_if_exists "${d}/${f}" "${RAW_DIR}/priority"
    done
  done

  for t in /tmp /var/tmp /dev/shm; do
    [[ -d "$t" ]] || continue
    find "$t" -xdev -maxdepth 3 \( -type f -o -type l \) 2>/dev/null | while read -r f; do
      cp -a --parents "$f" "${RAW_DIR}/priority" 2>>"${ERR_DIR}/stderr.log" || true
    done
  done
}

build_timelines() {
  log "timeline: generating"

  {
    find /tmp /var/tmp /dev/shm -xdev \( -type f -o -type d -o -type l \) \
      -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%A@\t%C@\t%T@\t%u\t%g\t%m\t%s\t%y\t%p\n' 2>/dev/null | sort
  } > "${TIMELINE_DIR}/tmp.tsv" || true

  {
    find /etc -xdev \( -type f -o -type d -o -type l \) \
      -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%A@\t%C@\t%T@\t%u\t%g\t%m\t%s\t%y\t%p\n' 2>/dev/null | sort
  } > "${TIMELINE_DIR}/etc.tsv" || true

  {
    find /root /home -xdev \( -type f -o -type d -o -type l \) \
      -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%A@\t%C@\t%T@\t%u\t%g\t%m\t%s\t%y\t%p\n' 2>/dev/null | sort
  } > "${TIMELINE_DIR}/home_root.tsv" || true

  {
    find /usr/local/bin /usr/local/sbin -xdev \( -type f -o -type d -o -type l \) \
      -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%A@\t%C@\t%T@\t%u\t%g\t%m\t%s\t%y\t%p\n' 2>/dev/null | sort
  } > "${TIMELINE_DIR}/usr_local.tsv" || true

  if [[ "$INCLUDE_WEB" -eq 1 ]]; then
    {
      find /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv -xdev \( -type f -o -type d -o -type l \) \
        -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%A@\t%C@\t%T@\t%u\t%g\t%m\t%s\t%y\t%p\n' 2>/dev/null | sort
    } > "${TIMELINE_DIR}/web.tsv" || true
  fi
}

run_ioc_scan() {
  [[ -n "$IOC_FILE" ]] || return 0
  [[ -f "$IOC_FILE" ]] || { warn "IOC file not found: $IOC_FILE"; return 0; }

  log "ioc: scanning using ${IOC_FILE}"

  cp -a "$IOC_FILE" "${IOC_DIR}/ioc_input.txt" 2>/dev/null || true

  while read -r pattern; do
    [[ -n "$pattern" ]] || continue
    [[ "$pattern" =~ ^# ]] && continue

    safe_name="$(echo "$pattern" | tr '/ :*?[](){}|&;'"'"'"'"'"' '"' '_' | tr -cd '[:alnum:]_.-')"
    out="${IOC_DIR}/${safe_name}.txt"

    {
      echo "### IOC PATTERN: $pattern"
      echo
      grep -RInaF -- "$pattern" /etc /root /home /usr/local /tmp /var/tmp /dev/shm /var/log /var/www /srv/www /usr/share/nginx/html /var/www/html /opt /srv 2>/dev/null || true
    } > "$out" 2>>"${ERR_DIR}/stderr.log" || true
  done < "$IOC_FILE"
}

generate_report() {
  local report="${REPORT_DIR}/SUMMARY.txt"
  : > "$report"

  append_section "$report" "IR TRIAGE SUMMARY"
  cat >> "$report" <<EOF
Host: ${HOSTNAME_FQDN}
UTC Start: ${TS_UTC}
Version: ${VERSION}
Mode: ${MODE}
Run As Root: $( [[ $EUID -eq 0 ]] && echo yes || echo no )

Primary paths:
- text/: command outputs
- raw/: copied evidence
- timeline/: file timelines
- hashes/: sha256 hashes
- web/: web inventory
- ioc/: IOC matches
EOF

  append_section "$report" "PRIORITY FILES TO REVIEW FIRST"
  cat >> "$report" <<'EOF'
1. text/ss_established.txt
2. text/ps_auxwf.txt
3. text/deleted_binaries_in_use.txt
4. text/tmp_exec_candidates.txt
5. text/ssh_user_artifacts.txt
6. text/crontab_per_user.txt
7. text/systemd_units_content.txt
8. text/auth_log.txt
9. text/pattern_hunting.txt
10. timeline/etc.tsv
11. timeline/home_root.tsv
12. timeline/tmp.tsv
13. text/web_shell_patterns.txt
14. text/web_recent_files.txt
15. text/docker_inspect.txt
EOF

  append_section "$report" "HIGH SIGNAL INDICATORS"
  cat >> "$report" <<'EOF'
- Executable files or running processes from /tmp, /var/tmp, /dev/shm
- Deleted binaries still running
- New or unexpected authorized_keys
- Unexpected cron entries or systemd services/timers
- Recent changes in /etc or /root or /home
- Unusual outbound connections
- PHP/JSP/Python/Node files with eval/base64/system/shell_exec/proc_open
- Writable web directories combined with recent app file changes
- SUID/SGID or capabilities outside expected baseline
- Web access/error log activity near times of changed application files
EOF

  append_section "$report" "NOTES"
  cat >> "$report" <<'EOF'
This collection is intended for triage and evidence preservation support.
It does not remediate, delete, kill, or harden the host.
EOF
}

generate_json_manifest() {
  local manifest="${JSON_DIR}/manifest.json"
  {
    echo "{"
    echo "  \"version\": \"${VERSION}\","
    echo "  \"hostname\": \"${HOSTNAME_FQDN}\","
    echo "  \"utc_start\": \"${TS_UTC}\","
    echo "  \"mode\": \"${MODE}\","
    echo "  \"paths\": {"
    echo "    \"text\": \"${TXT_DIR}\","
    echo "    \"raw\": \"${RAW_DIR}\","
    echo "    \"timeline\": \"${TIMELINE_DIR}\","
    echo "    \"hashes\": \"${HASH_DIR}\","
    echo "    \"web\": \"${WEB_DIR}\","
    echo "    \"ioc\": \"${IOC_DIR}\","
    echo "    \"report\": \"${REPORT_DIR}\""
    echo "  }"
    echo "}"
  } > "$manifest"
}

hash_outputs() {
  : > "${HASH_DIR}/sha256.txt"
  sha256_dir "$TXT_DIR"
  sha256_dir "$TIMELINE_DIR"
  sha256_dir "$META_DIR"
  sha256_dir "$REPORT_DIR"
  sha256_dir "$IOC_DIR"
  sha256_dir "$WEB_DIR"
  if [[ "$INCLUDE_COPY" -eq 1 ]]; then
    sha256_dir "$RAW_DIR"
  fi
}

main() {
  init_metadata
  collect_identity
  collect_network
  collect_processes
  collect_users_auth
  collect_persistence
  collect_logs
  collect_recent_and_temp
  collect_integrity
  collect_histories
  collect_packages_services
  collect_hunting
  collect_web
  collect_containers
  collect_copy_priority
  build_timelines
  run_ioc_scan
  generate_report
  generate_json_manifest
  hash_outputs
  log "done: ${OUTDIR}"
}

main "$@"
