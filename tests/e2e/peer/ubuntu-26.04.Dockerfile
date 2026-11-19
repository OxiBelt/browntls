# Interoperability peer from the current Ubuntu LTS release, 26.04: OpenSSL
# 3.5 (with X25519MLKEM768). Its riscv64 image requires RVA23, which the
# native riscv64 runner lacks, so the suite skips that architecture.
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY gen-pki.sh no-etm.cnf /usr/local/share/browntls-e2e/
