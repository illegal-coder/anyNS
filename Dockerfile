FROM node:22-alpine AS web-build
WORKDIR /src/web/admin
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci
COPY web/admin ./
RUN npm run build

FROM golang:1.22-alpine AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -buildvcs=false -trimpath -o /out/anyns-admin-api ./cmd/anyns-admin-api \
 && go build -buildvcs=false -trimpath -o /out/anyns-plugin-runtime ./cmd/anyns-plugin-runtime \
 && go build -buildvcs=false -trimpath -o /out/anyns-log-forwarder ./cmd/anyns-log-forwarder

FROM alpine:3.20
RUN adduser -D -u 10001 anyns
RUN mkdir -p /var/lib/anyns /usr/share/anyns-admin \
 && chown -R anyns:anyns /var/lib/anyns /usr/share/anyns-admin
COPY --from=go-build /out/ /usr/local/bin/
COPY --from=web-build /src/internal/adminui/dist/ /usr/share/anyns-admin/
COPY configs/anyns/config.example.json /usr/share/anyns/config.default.json
ENV ANYNS_ADMIN_UI_DIR=/usr/share/anyns-admin
USER anyns
ENTRYPOINT ["/usr/local/bin/anyns-plugin-runtime"]
