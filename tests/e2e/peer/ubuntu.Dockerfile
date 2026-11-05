# Interoperability peers as widely deployed on long-term-support systems:
# OpenSSL 3.0 (no post-quantum groups) and GnuTLS 3.8.3 from Ubuntu 24.04.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl gnutls-bin \
 && rm -rf /var/lib/apt/lists/*
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
