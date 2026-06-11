ARG PDNS_RECURSOR_IMAGE=powerdns/pdns-recursor-54:5.4.2
FROM ${PDNS_RECURSOR_IMAGE}

USER root

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      lua-cjson \
      lua-socket \
 && rm -rf /var/lib/apt/lists/*

USER pdns
