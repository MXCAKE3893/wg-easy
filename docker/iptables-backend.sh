#!/bin/sh
# Select the iptables backend, then run the given command.
# Prefer legacy only if every required address family and table is usable.
# Some Docker Desktop kernels support legacy IPv4 but not legacy IPv6 NAT.
backend_works() {
  "iptables-$1" -w 2 -S >/dev/null 2>&1 &&
    "iptables-$1" -w 2 -t nat -S >/dev/null 2>&1 || return 1
  if [ "${DISABLE_IPV6:-false}" != "true" ]; then
    "ip6tables-$1" -w 2 -S >/dev/null 2>&1 &&
      "ip6tables-$1" -w 2 -t nat -S >/dev/null 2>&1 || return 1
  fi
}

if backend_works legacy; then
  backend=legacy
elif backend_works nft; then
  backend=nft
fi

if [ -n "$backend" ] && [ "$(readlink /etc/alternatives/iptables)" != "/usr/sbin/iptables-$backend" ]; then
  update-alternatives --set iptables "/usr/sbin/iptables-$backend"
  update-alternatives --set ip6tables "/usr/sbin/ip6tables-$backend"
fi

exec "$@"
