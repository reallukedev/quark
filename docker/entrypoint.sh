#!/bin/sh
# Folders mounted from the host often belong to root; give them to the quark user, then drop
# root before starting. `quark ctl` (docker exec) runs as root and can still reach the socket.
set -eu
if [ "$(id -u)" = "0" ] && [ "${1:-run}" = "run" ]; then
    mkdir -p /etc/quark/certs /var/lib/quark
    chown -R quark:quark /etc/quark /var/lib/quark
    exec setpriv --reuid=quark --regid=quark --init-groups --inh-caps=-all quark "$@"
fi
exec quark "$@"
