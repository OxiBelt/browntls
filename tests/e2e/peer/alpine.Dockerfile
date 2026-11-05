# Interoperability peers from a current distribution: OpenSSL 3.5 or later
# (with the X25519MLKEM768 hybrid group) and GnuTLS 3.8.
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache openssl gnutls-utils
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
