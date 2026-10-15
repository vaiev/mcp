#!/bin/sh
# SSH forced command. The login user cannot write the spool; the gate runs as sc-gate.
exec /usr/bin/sudo -n -u sc-gate -- /usr/bin/python3 /usr/local/lib/sidecomputer/gate.py
