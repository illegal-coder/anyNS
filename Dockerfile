FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -buildvcs=false -trimpath -o /out/anyns-admin-api ./cmd/anyns-admin-api \
 && go build -buildvcs=false -trimpath -o /out/anyns-plugin-runtime ./cmd/anyns-plugin-runtime \
 && go build -buildvcs=false -trimpath -o /out/anyns-log-forwarder ./cmd/anyns-log-forwarder

FROM alpine:3.20
RUN adduser -D -u 10001 anyns
COPY --from=build /out/ /usr/local/bin/
USER anyns
ENTRYPOINT ["/usr/local/bin/anyns-plugin-runtime"]
