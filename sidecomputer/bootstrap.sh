#!/usr/bin/env bash
# SideComputer bootstrap (Debian/Ubuntu first). Run as root on the target host. Idempotent.
# Usage: bootstrap.sh --profile NAME[,NAME] --bot-pubkey "ssh-ed25519 AAAA..."|FILE --mode strict|open [--lock] [--rotate] [--admin-user USER]
set -euo pipefail
PROFILES=""; PUBKEY=""; MODE="strict"; LOCK=0; ROTATE=0; ADMIN_USER="${SUDO_USER:-root}"
SRC="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${SC_PREFIX:-}"
DRY="${SC_DRY_RUN:-0}"
die(){ python3 -c 'import json,sys; print(json.dumps({"ok": False, "error": sys.argv[1]}))' "$*"; exit 1; }
while [ $# -gt 0 ]; do case "$1" in
  --profile) PROFILES="$2"; shift 2;;
  --bot-pubkey) PUBKEY="$2"; shift 2;;
  --mode) MODE="$2"; shift 2;;
  --lock) LOCK=1; shift;;
  --rotate) ROTATE=1; shift;;
  --admin-user) ADMIN_USER="$2"; shift 2;;
  -h|--help) sed -n '2,4p' "$0"; exit 0;;
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
SUDOERS_D="$PREFIX/etc/sudoers.d"
export SC_SRC_GATE="$SRC/gate"

# 1. users and groups. The login user is in none of the spool groups.
if [ "$DRY" != 1 ]; then
  for g in sidecomputer sc-gate sc-worker sc-task sc-audit sc-ipc; do
    getent group "$g" >/dev/null || groupadd --system "$g"
  done
  id sidecomputer >/dev/null 2>&1 || useradd --create-home --home-dir /home/sidecomputer --shell /bin/bash -g sidecomputer sidecomputer
  id sc-gate >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin -g sc-gate -G sc-audit,sc-ipc sc-gate
  id sc-worker >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/sidecomputer --shell /usr/sbin/nologin -g sc-worker -G sc-audit,sc-ipc sc-worker
  id sc-task >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin -g sc-task sc-task
  usermod -a -G sc-audit,sc-ipc sc-gate
  usermod -a -G sc-audit,sc-ipc sc-worker
  gpasswd -d sc-worker sidecomputer >/dev/null 2>&1 || true
  passwd -l sidecomputer >/dev/null 2>&1 || true
fi

# 2. files
mkdir -p "$LIB" "$BIN" "$ETC/profiles" "$SPOOL" "$(dirname "$UNIT")" "$SSHD_D" "$SUDOERS_D" "$HOMEDIR/.ssh"
install -m 0644 "$SRC/gate/sclib.py" "$LIB/sclib.py"
install -m 0755 "$SRC/gate/gate.py" "$LIB/gate.py"
install -m 0755 "$SRC/gate/worker.py" "$LIB/worker.py"
install -m 0755 "$SRC/gate/approve.py" "$LIB/approve.py"
install -m 0755 "$SRC/gate/chown_artifact.py" "$LIB/chown_artifact.py"
install -m 0755 "$SRC/scripts/sidecomputer-gate.sh" "$BIN/sidecomputer-gate"
ln -sfn /usr/local/lib/sidecomputer/worker.py "$BIN/sidecomputer-worker"
ln -sfn /usr/local/lib/sidecomputer/approve.py "$BIN/sidecomputer-approve"

# 3. profiles (admin step: only declared profiles, validated before install)
INSTALLED=()
IFS=',' read -ra PL <<< "$PROFILES"
for p in "${PL[@]}"; do
  f="$SRC/profiles/$p.json"; [ -f "$f" ] || die "no such profile $p"
  python3 -c "import os,sys,json; sys.path.insert(0, os.environ['SC_SRC_GATE']); import sclib; sclib.validate_profile(json.load(open(sys.argv[1])))" "$f" || die "invalid profile $p"
  install -m 0644 "$f" "$ETC/profiles/$p.json"
  pk="$(python3 -c "import json,sys; print(' '.join(json.load(open(sys.argv[1])).get('packages',[])))" "$f")"
  if [ -n "$pk" ] && [ "$DRY" != 1 ] && command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pk >/dev/null || die "apt install failed for $p"
  fi
  mc="$(python3 -c "import json,sys; print(' '.join(json.load(open(sys.argv[1])).get('mcps',[])))" "$f")"
  if [ -n "$mc" ] && [ "$DRY" != 1 ] && command -v npm >/dev/null; then npm install -g $mc >/dev/null || die "mcp install failed for $p"; fi
  INSTALLED+=("\"$p\"")
done

# 4. spool DAC: gate writes queue, worker writes results, neither rewrites the audit log.
#    Task uid is sc-task (via sudo). The login user is not in these groups.
SC_SPOOL_ROOT="$SPOOL" SC_APPLY_CHOWN="$([ "$DRY" = 1 ] && echo 0 || echo 1)" \
  python3 -c 'import os,sys; sys.path.insert(0, os.environ["SC_SRC_GATE"]); import sclib; sclib.apply_spool_policy(os.environ["SC_SPOOL_ROOT"], chown=os.environ.get("SC_APPLY_CHOWN")=="1")'

# 5. audit key and per-key profile grants. The key is unreadable by the login user and by sc-task.
if [ ! -s "$ETC/audit.key" ]; then
  (umask 077; head -c 32 /dev/urandom > "$ETC/audit.key")
fi
run chown root:sc-audit "$ETC/audit.key"
chmod 0640 "$ETC/audit.key"
FP="$(SC_PUB="$PUBKEY" python3 -c 'import os,sys; sys.path.insert(0, os.environ["SC_SRC_GATE"]); import sclib; print(sclib.fingerprint_pubkey(os.environ["SC_PUB"]))')"
SC_ROTATE="$ROTATE" SC_FP="$FP" SC_PROFILES_CSV="$PROFILES" SC_GRANTS_PATH="$ETC/grants.json" \
  python3 -c 'import os,sys; sys.path.insert(0, os.environ["SC_SRC_GATE"]); import sclib; sclib.write_grant(os.environ["SC_GRANTS_PATH"], os.environ["SC_FP"], [p for p in os.environ["SC_PROFILES_CSV"].split(",") if p]); sclib.prune_grants(os.environ["SC_GRANTS_PATH"], os.environ["SC_FP"]) if os.environ["SC_ROTATE"] == "1" else None'
chmod 0644 "$ETC/grants.json" || true

# 6. systemd worker. Egress is denied unless a profile is given a privileged scope.
cat > "$UNIT" <<UNITEOF
[Unit]
Description=SideComputer task worker
After=network-online.target
[Service]
User=sc-worker
Group=sc-worker
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/lib/sidecomputer/worker.py
Environment=SC_SYSTEMD_RUN=0
Environment=SC_TASK_SEPARATION=auto
Environment=SC_AUDIT_KEY=/etc/sidecomputer/audit.key
Environment=SC_GRANTS=/etc/sidecomputer/grants.json
Environment=SC_PROFILES=/etc/sidecomputer/profiles
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
IPAddressDeny=any
IPAddressAllow=localhost
[Install]
WantedBy=multi-user.target
UNITEOF
run systemctl daemon-reload; run systemctl enable --now sidecomputer-worker.service >/dev/null 2>&1 || true

# 7. sudoers: gate uid, task uid, and the artifact chown helper. No root shell for the login user.
cat > "$SUDOERS_D/sidecomputer.new" <<'SUDOEOF'
Defaults:sidecomputer !requiretty
Defaults:sidecomputer env_keep += "SC_KEY_ID SSH_CONNECTION SSH_CLIENT"
Defaults:sc-worker !requiretty
sidecomputer ALL=(sc-gate) NOPASSWD: /usr/bin/python3 /usr/local/lib/sidecomputer/gate.py
sc-worker ALL=(root) NOPASSWD: /usr/local/lib/sidecomputer/chown_artifact.py
sc-worker ALL=(sc-task) NOPASSWD: ALL
SUDOEOF
mv "$SUDOERS_D/sidecomputer.new" "$SUDOERS_D/sidecomputer"
chmod 0440 "$SUDOERS_D/sidecomputer" || true

# 8. authorized_keys. environment= names the key so the gate can apply grants.
AK="$HOMEDIR/.ssh/authorized_keys"; touch "$AK"
{ grep -vF "$KEYTYPE_B64" "$AK" | grep -v '^# OPEN MODE' || true; } > "$AK.new"
if [ "$ROTATE" = 1 ]; then
  { grep -vE 'command="[^"]*sidecomputer-gate|[[:space:]]sidecomputer-bot(-open)?([[:space:]]|$)' "$AK.new" || true; } > "$AK.rotate"
  mv "$AK.rotate" "$AK.new"
fi
# Key rotation is admin-only (this script). Every entry keeps command= and restrict;
# there is no gate tool that can rewrite authorized_keys.
if [ "$MODE" = strict ]; then
  echo "command=\"/usr/local/bin/sidecomputer-gate\",restrict,environment=\"SC_KEY_ID=$FP\" $KEYTYPE_B64 sidecomputer-bot" >> "$AK.new"
else
  echo "# OPEN MODE (less safe): ForceCommand is not set for the user; this key still cannot get a shell" >> "$AK.new"
  echo "command=\"/usr/local/bin/sidecomputer-gate\",restrict,environment=\"SC_KEY_ID=$FP\" $KEYTYPE_B64 sidecomputer-bot-open" >> "$AK.new"
fi
mv "$AK.new" "$AK"
chmod 700 "$HOMEDIR/.ssh"; chmod 600 "$AK"; run chown -R sidecomputer:sidecomputer "$HOMEDIR/.ssh"

# 9. sshd hardening. PermitUserEnvironment is limited to the grant id.
cat > "$SSHD_D/60-sidecomputer.conf" <<SSHEOF
# managed by sidecomputer bootstrap (mode=$MODE)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitUserEnvironment SC_KEY_ID
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

WARN=""
[ "$MODE" = open ] && WARN="open mode is less safe because ForceCommand is not set for the user; the bot key still has command= and restrict"
[ "$LOCKED" = true ] && WARN="admin SSH key removed; recovery needs console/provider access"
HOST_KEY_FINGERPRINT=""
if [ -f "$PREFIX/etc/ssh/ssh_host_ed25519_key.pub" ]; then
  HOST_KEY_FINGERPRINT="$(ssh-keygen -lf "$PREFIX/etc/ssh/ssh_host_ed25519_key.pub")"
fi
PROFILES_JSON="[$(IFS=,; echo "${INSTALLED[*]}")]"
python3 -c 'import json,sys; print(json.dumps({"ok": True, "mode": sys.argv[1], "locked": sys.argv[2]=="true", "profiles": json.loads(sys.argv[3]), "spool": "/var/lib/sidecomputer", "gate": "/usr/local/bin/sidecomputer-gate", "worker_unit": "sidecomputer-worker.service", "login_user": "sidecomputer", "warning": sys.argv[4], "host_key_fingerprint": sys.argv[5]}))' \
  "$MODE" "$LOCKED" "$PROFILES_JSON" "$WARN" "$HOST_KEY_FINGERPRINT"
