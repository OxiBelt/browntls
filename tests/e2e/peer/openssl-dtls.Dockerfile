# Independent DTLS 1.2 test peer; same pinned Alpine base as alpine.Dockerfile.
# Packages come only from that distribution; no external source downloads.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
RUN apk add --no-cache build-base openssl-dev
WORKDIR /build
COPY openssl-dtls.c .
RUN cc -std=c11 -O2 -Wall -Wextra -Werror openssl-dtls.c -lssl -lcrypto -o openssl-dtls

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache openssl \
    && openssl version | grep -E '^OpenSSL 3\.5\.'
COPY --from=build /build/openssl-dtls /usr/local/bin/openssl-dtls
COPY gen-pki.sh /usr/local/share/browntls-e2e/
