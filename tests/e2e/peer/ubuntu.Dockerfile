# Interoperability peers as widely deployed on long-term-support systems:
# OpenSSL 3.0 (no post-quantum groups) and GnuTLS 3.8.3 from Ubuntu 24.04.
FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl gnutls-bin \
 && rm -rf /var/lib/apt/lists/*
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
