#!/usr/bin/env bash
# SideComputer bootstrap (Debian/Ubuntu first). Run as root on the target host. Idempotent.
# Usage: bootstrap.sh --profile NAME[,NAME] --bot-pubkey "ssh-ed25519 AAAA..."|FILE --mode strict|open [--lock] [--admin-user USER]
set -euo pipefail
PROFILES=""; PUBKEY=""; MODE="strict"; LOCK=0; ADMIN_USER="${SUDO_USER:-root}"
SRC="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${SC_PREFIX:-}"                 # for chroot/test installs
DRY="${SC_DRY_RUN:-0}"                  # 1 = skip useradd/systemctl/sshd reload/apt
die(){ echo "{\"ok\":false,\"error\":\"$*\"}"; exit 1; }
while [ $# -gt 0 ]; do case "$1" in
  --profile) PROFILES="$2"; shift 2;;
  --bot-pubkey) PUBKEY="$2"; shift 2;;
  --mode) MODE="$2"; shift 2;;
  --lock) LOCK=1; shift;;
  --admin-user) ADMIN_USER="$2"; shift 2;;
  -h|--help) sed -n 2,4p "$0"; exit 0;;
  *) die "unknown arg $1";; esac; done
[ -n "$PROFILES" ] || die "--profile required"
[ -n "$PUBKEY" ] || die "--bot-pubkey required"
[ -f "$PUBKEY" ] && PUBKEY="$(head -n1 "$PUBKEY")"
case "$MODE" in strict|open) ;; *) die "--mode must be strict or open";; esac
echo "$PUBKEY" | grep -Eq '^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/=]+( .*)?$' || die "bad pubkey"
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "must run as root"
KEYTYPE_B64="$(echo "$PUBKEY" | awk '{print $1" "$2}')"
run(){ if [ "$DRY" = 1 ]; then :; else "$@"; fi; }

LIB="$PREFIX/usr/local/lib/sidecomputer"; BIN="$PREFIX/usr/local/bin"; ETC="$PREFIX/etc/sidecomputer"
SPOOL="$PREFIX/var/lib/sidecomputer"; UNIT="$PREFIX/etc/systemd/system/sidecomputer-worker.service"
SSHD_D="$PREFIX/etc/ssh/sshd_config.d"; HOMEDIR="$PREFIX/home/sidecomputer"

# 1. users and group
if [ "$DRY" != 1 ]; then
  getent group sidecomputer >/dev/null || groupadd --system sidecomputer
  id sidecomputer >/dev/null 2>&1 || useradd --create-home --home-dir /home/sidecomputer --shell /bin/bash -g sidecomputer sidecomputer
  id sc-worker >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/sidecomputer --shell /usr/sbin/nologin -G sidecomputer sc-worker
  passwd -l sidecomputer >/dev/null 2>&1 || true
fi

# 2. files
mkdir -p "$LIB" "$BIN" "$ETC/profiles" "$SPOOL"/{queue,running,done,artifacts} "$(dirname "$UNIT")" "$SSHD_D" "$HOMEDIR/.ssh"
install -m 0644 "$SRC/gate/sclib.py" "$LIB/sclib.py"
install -m 0755 "$SRC/gate/gate.py" "$LIB/gate.py"
install -m 0755 "$SRC/gate/worker.py" "$LIB/worker.py"
ln -sf /usr/local/lib/sidecomputer/gate.py "$BIN/sidecomputer-gate"
ln -sf /usr/local/lib/sidecomputer/worker.py "$BIN/sidecomputer-worker"

# 3. profiles (admin step: only declared profiles, validated before install)
INSTALLED=()
IFS=',' read -ra PL <<< "$PROFILES"
for p in "${PL[@]}"; do
  f="$SRC/profiles/$p.json"; [ -f "$f" ] || die "no such profile $p"
  python3 -c "import sys,json;sys.path.insert(0,'$SRC/gate');import sclib;sclib.validate_profile(json.load(open('$f')))" || die "invalid profile $p"
  install -m 0644 "$f" "$ETC/profiles/$p.json"
  pk="$(python3 -c "import json;print(' '.join(json.load(open('$f')).get('packages',[])))")"
  if [ -n "$pk" ] && [ "$DRY" != 1 ] && command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pk >/dev/null || die "apt install failed for $p"
  fi
  mc="$(python3 -c "import json;print(' '.join(json.load(open('$f')).get('mcps',[])))")"
  if [ -n "$mc" ] && [ "$DRY" != 1 ] && command -v npm >/dev/null; then npm install -g $mc >/dev/null || die "mcp install failed for $p"; fi
  INSTALLED+=("\"$p\"")
done

# 4. spool permissions: shared group, setgid, no world access
if [ "$DRY" != 1 ]; then
  chown -R root:sidecomputer "$SPOOL"; chmod 2770 "$SPOOL" "$SPOOL"/{queue,running,done,artifacts}
  chown sc-worker:sidecomputer "$SPOOL/artifacts"
fi

# 5. systemd worker
cat > "$UNIT" <<UNITEOF
[Unit]
Description=SideComputer task worker
After=network-online.target
[Service]
User=sc-worker
Group=sidecomputer
UMask=0007
ExecStart=/usr/bin/python3 /usr/local/lib/sidecomputer/worker.py
Environment=SC_SYSTEMD_RUN=0
Restart=always
RestartSec=3
MemoryMax=8G
CPUQuota=400%
TasksMax=512
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/sidecomputer
[Install]
WantedBy=multi-user.target
UNITEOF
run systemctl daemon-reload; run systemctl enable --now sidecomputer-worker.service >/dev/null 2>&1 || true

# 6. authorized_keys (replace any prior line for the same key -> idempotent)
AK="$HOMEDIR/.ssh/authorized_keys"; touch "$AK"
{ grep -vF "$KEYTYPE_B64" "$AK" | grep -v '^# OPEN MODE' || true; } > "$AK.new"
if [ "$MODE" = strict ]; then
  echo "command=\"/usr/local/bin/sidecomputer-gate\",restrict $KEYTYPE_B64 sidecomputer-bot" >> "$AK.new"
else
  echo "# OPEN MODE (less safe): full shell for this key" >> "$AK.new"
  echo "restrict,pty $KEYTYPE_B64 sidecomputer-bot-open" >> "$AK.new"
fi
mv "$AK.new" "$AK"
chmod 700 "$HOMEDIR/.ssh"; chmod 600 "$AK"; run chown -R sidecomputer:sidecomputer "$HOMEDIR/.ssh"

# 7. sshd hardening
cat > "$SSHD_D/60-sidecomputer.conf" <<SSHEOF
# managed by sidecomputer bootstrap (mode=$MODE)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin $( [ "$LOCK" = 1 ] && echo no || echo prohibit-password )
Match User sidecomputer
  AllowTcpForwarding no
  X11Forwarding no
  AllowAgentForwarding no
  PermitTunnel no
  $( [ "$MODE" = strict ] && echo "ForceCommand /usr/local/bin/sidecomputer-gate" )
SSHEOF
LOCKED=false
if [ "$LOCK" = 1 ] && [ "$MODE" = strict ]; then
  ADMIN_HOME="$(getent passwd "$ADMIN_USER" 2>/dev/null | cut -d: -f6 || true)"
  if [ -n "$ADMIN_HOME" ] && [ -f "$PREFIX$ADMIN_HOME/.ssh/authorized_keys" ]; then
    cp "$PREFIX$ADMIN_HOME/.ssh/authorized_keys" "$PREFIX$ADMIN_HOME/.ssh/authorized_keys.sc-locked.bak"
    : > "$PREFIX$ADMIN_HOME/.ssh/authorized_keys"
  fi
  LOCKED=true
fi
if [ "$DRY" != 1 ]; then sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true); fi

WARN=""; [ "$MODE" = open ] && WARN="open mode grants a normal shell to the bot key; less safe"
[ "$LOCKED" = true ] && WARN="admin SSH key removed; recovery needs console/provider access"
printf '{"ok":true,"mode":"%s","locked":%s,"profiles":[%s],"spool":"/var/lib/sidecomputer","gate":"/usr/local/bin/sidecomputer-gate","worker_unit":"sidecomputer-worker.service","login_user":"sidecomputer","warning":"%s"}\n' \
  "$MODE" "$LOCKED" "$(IFS=,; echo "${INSTALLED[*]}")" "$WARN"
