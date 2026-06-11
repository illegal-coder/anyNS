#!/bin/sh
set -eu

find /certs -mindepth 1 -maxdepth 1 -type f -delete

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -sha256 \
  -days 2 \
  -subj "/CN=anyNS Docker Test CA" \
  -keyout /certs/ca.key \
  -out /certs/ca.crt

openssl req \
  -new \
  -newkey rsa:2048 \
  -nodes \
  -sha256 \
  -subj "/CN=bind-latest" \
  -addext "subjectAltName=DNS:bind-latest" \
  -keyout /certs/server.key \
  -out /certs/server.csr

openssl x509 \
  -req \
  -sha256 \
  -days 2 \
  -in /certs/server.csr \
  -CA /certs/ca.crt \
  -CAkey /certs/ca.key \
  -CAcreateserial \
  -copy_extensions copy \
  -out /certs/server.crt

chmod 0644 /certs/ca.crt /certs/server.crt /certs/server.key
openssl verify -CAfile /certs/ca.crt /certs/server.crt
