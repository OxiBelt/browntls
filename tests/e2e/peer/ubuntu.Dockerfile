# Interoperability peers as widely deployed on long-term-support systems:
# OpenSSL 3.0 (no post-quantum groups) and GnuTLS 3.8.3 from Ubuntu 24.04.
FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl gnutls-bin \
 && rm -rf /var/lib/apt/lists/*
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
