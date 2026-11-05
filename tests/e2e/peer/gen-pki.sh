#!/bin/sh
# Generate a throwaway CA with server and client certificates for each key
# type into the directory given as the only argument (a per-run Docker
# volume). The server certificate names the network alias `tls-server`.
# Keys are world-readable because the browntls image runs as an unprivileged
# user; they live only as long as the test run's volume.
set -eu

out="${1:?usage: gen-pki.sh <directory>}"

gen_key() {
  case "$1" in
    ecdsa-p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" ;;
    rsa-2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$2" ;;
    ed25519) openssl genpkey -algorithm ED25519 -out "$2" ;;
    *) echo "unknown key type $1" >&2; exit 2 ;;
  esac
}

for kt in ecdsa-p256 rsa-2048 ed25519; do
  d="${out}/${kt}"
  mkdir -p "${d}"
  gen_key "${kt}" "${d}/ca.key"
  openssl req -x509 -new -key "${d}/ca.key" -subj "/CN=browntls e2e ${kt} CA" -days 2 \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    -out "${d}/ca.pem"
  serial=2
  for who in server client; do
    case "${who}" in
      server) eku=serverAuth; san="subjectAltName=DNS:tls-server" ;;
      client) eku=clientAuth; san="subjectAltName=DNS:tls-client" ;;
    esac
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n%s\n' \
      "${eku}" "${san}" > "${d}/${who}.ext"
    gen_key "${kt}" "${d}/${who}.key"
    openssl req -new -key "${d}/${who}.key" -subj "/CN=tls-${who}" -out "${d}/${who}.csr"
    openssl x509 -req -in "${d}/${who}.csr" -CA "${d}/ca.pem" -CAkey "${d}/ca.key" \
      -set_serial "${serial}" -days 2 -extfile "${d}/${who}.ext" -out "${d}/${who}.pem"
    serial=$((serial + 1))
    rm -f "${d}/${who}.csr" "${d}/${who}.ext"
  done
  rm -f "${d}/ca.key"
  chmod 0755 "${d}"
  chmod 0644 "${d}"/*
done
chmod 0755 "${out}"
