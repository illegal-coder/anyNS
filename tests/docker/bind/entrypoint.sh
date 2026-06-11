#!/bin/sh
set -eu

resolver_ip=""
attempt=0
while [ -z "$resolver_ip" ] && [ "$attempt" -lt 30 ]; do
  resolver_ip="$(getent ahostsv4 pdns-recursor | awk 'NR == 1 { print $1; exit }')"
  attempt=$((attempt + 1))
  if [ -z "$resolver_ip" ]; then
    sleep 1
  fi
done

if [ -z "$resolver_ip" ]; then
  echo "unable to resolve pdns-recursor container address" >&2
  exit 1
fi

sed "s/__PDNS_RECURSOR_IP__/$resolver_ip/g" \
  /etc/bind/named.conf.template \
  > /tmp/named.conf

named-checkconf /tmp/named.conf
echo "BIND forwarding to pdns-recursor at $resolver_ip" >&2
exec /usr/sbin/named -u bind "$@" -c /tmp/named.conf
