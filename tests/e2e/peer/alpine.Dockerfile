# Interoperability peers from a current distribution: OpenSSL 3.5 or later
# (with the X25519MLKEM768 hybrid group) and GnuTLS 3.8.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache openssl gnutls-utils
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
