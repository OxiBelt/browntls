FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
ENV GOTOOLCHAIN=local CGO_ENABLED=0
COPY pion/go.mod pion/go.sum ./
RUN go mod download && go mod verify
COPY pion/main.go ./
ENV GOPROXY=off GOFLAGS=-mod=readonly
# Carry the licenses of the Go runtime and every linked third-party module.
RUN go build -trimpath -o /out/pion-dtls . \
 && mkdir /out/licenses \
 && cp /usr/local/go/LICENSE /out/licenses/Go \
 && go list -deps -f '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}} {{.Module.Dir}}{{end}}{{end}}' . > /tmp/packages \
 && sort -u /tmp/packages > /tmp/deps \
 && while read -r module dir; do \
      if [ -n "$dir" ]; then mkdir -p "/out/licenses/$module" && cp "$dir/LICENSE" "/out/licenses/$module/"; fi; \
    done < /tmp/deps

FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/pion-dtls /usr/local/bin/pion-dtls
COPY --from=build /out/licenses /usr/local/share/browntls-e2e/pion-licenses/
COPY gen-pki.sh /usr/local/share/browntls-e2e/
