#!/bin/sh
# Generate a throwaway CA with server and client certificates for each key
# type into the directory given as the first argument (a per-run Docker
# volume). ML-DSA key types (FIPS 204: mldsa44, mldsa65, mldsa87) are added
# only when the OpenSSL tool lists them as TLS signature schemes (OpenSSL 3.5
# or later); older peers get the classical key types alone. The optional
# second argument names the server (`tls-server`); the `public` certificate
# names `ech-public.test`, the public name of the Encrypted Client Hello
# scenarios, which a server rejecting ECH presents.
# Keys are world-readable because the browntls image runs as an unprivileged
# user; they live only as long as the test run's volume.
set -eu

out="${1:?usage: gen-pki.sh <directory> [server-name]}"
server_name="${2:-tls-server}"
delegated_credentials="${3:-}"
if [ -n "${delegated_credentials}" ] && [ "${delegated_credentials}" != "--delegated-credentials" ]; then
  echo "unknown option: ${delegated_credentials}" >&2
  exit 2
fi

gen_key() {
  case "$1" in
    ecdsa-p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" ;;
    rsa-2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$2" ;;
    ed25519) openssl genpkey -algorithm ED25519 -out "$2" ;;
    mldsa44) openssl genpkey -algorithm ML-DSA-44 -out "$2" ;;
    mldsa65) openssl genpkey -algorithm ML-DSA-65 -out "$2" ;;
    mldsa87) openssl genpkey -algorithm ML-DSA-87 -out "$2" ;;
    *) echo "unknown key type $1" >&2; exit 2 ;;
  esac
}

key_types="ecdsa-p256 rsa-2048 ed25519"
# OpenSSL 3.0 has no -tls-signature-algorithms option: the probe fails there.
tls_sigalgs="$(openssl list -tls-signature-algorithms 2>/dev/null || true)"
for kt in mldsa44 mldsa65 mldsa87; do
  case ":${tls_sigalgs}:" in
    *":${kt}:"*) key_types="${key_types} ${kt}" ;;
  esac
done

for kt in ${key_types}; do
  d="${out}/${kt}"
  mkdir -p "${d}"
  gen_key "${kt}" "${d}/ca.key"
  openssl req -x509 -new -key "${d}/ca.key" -subj "/CN=browntls e2e ${kt} CA" -days 2 \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    -out "${d}/ca.pem"
  serial=2
  for who in server client public; do
    case "${who}" in
      server) eku=serverAuth; san="subjectAltName=DNS:${server_name}" ;;
      client) eku=clientAuth; san="subjectAltName=DNS:tls-client" ;;
      public) eku=serverAuth; san="subjectAltName=DNS:ech-public.test" ;;
    esac
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n%s\n' \
      "${eku}" "${san}" > "${d}/${who}.ext"
    if [ "${delegated_credentials}" = "--delegated-credentials" ] && [ "${who}" != "public" ]; then
      printf '%s\n' '1.3.6.1.4.1.44363.44=DER:05:00' >> "${d}/${who}.ext"
    fi
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
