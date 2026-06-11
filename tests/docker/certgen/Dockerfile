FROM alpine:3.22

RUN apk add --no-cache openssl

COPY generate.sh /usr/local/bin/generate-bind-test-certs
RUN chmod +x /usr/local/bin/generate-bind-test-certs

ENTRYPOINT ["/usr/local/bin/generate-bind-test-certs"]
