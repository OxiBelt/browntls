# Interoperability peers as widely deployed on long-term-support systems:
# OpenSSL 3.0 (no post-quantum groups) and GnuTLS 3.8.3 from Ubuntu 24.04.
FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl gnutls-bin \
 && rm -rf /var/lib/apt/lists/*
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
