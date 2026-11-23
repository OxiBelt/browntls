# Go crypto/tls as an Encrypted Client Hello (RFC 9849) peer: a client and a
# shared-mode server (Go implements no split mode), built from go/ with the
# standard library only. The runtime stage is Ubuntu 24.04 for gen-pki.sh,
# which needs the OpenSSL command-line tool.
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go/go.mod go/main.go ./
RUN CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=mod go build -trimpath -o /out/go-peer . \
 && go version > /out/go-version

FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/go-peer /usr/local/bin/go-peer
COPY --from=build /out/go-version /usr/local/share/browntls-e2e/go-version
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
