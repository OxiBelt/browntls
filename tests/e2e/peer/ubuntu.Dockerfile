# Interoperability peers as widely deployed on long-term-support systems:
# OpenSSL 3.0 (no post-quantum groups) and GnuTLS 3.8.3 from Ubuntu 24.04.
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl gnutls-bin \
 && rm -rf /var/lib/apt/lists/*
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
