#!/usr/bin/env bash
# Seal fuzz findings for the maintainers, and open sealed findings.
#
#   scripts/fuzz/findings-envelope.sh keygen KEY CERT
#   scripts/fuzz/findings-envelope.sh seal CERT DIR OUT
#   scripts/fuzz/findings-envelope.sh open KEY CERT IN DIR
#
# keygen  creates a P-384 private key (KEY, mode 600; maintainers keep it
#         privately, never in this repository) and a self-signed recipient
#         certificate for it (CERT, public).
# seal    packs DIR (tar + gzip) and encrypts it to CERT as CMS
#         AuthEnvelopedData (ECDH key agreement, AES-256-GCM), written to OUT
#         in DER. The archive is streamed into the encryption, never written
#         out in plaintext. Prints OUT's size and SHA-256 only.
# open    decrypts IN with KEY and unpacks it into DIR, which must not exist
#         yet. The archive is unpacked only after decryption succeeded, which
#         includes the GCM tag check.
#
# The Fuzz workflow seals a failing job's findings (inputs, libFuzzer logs,
# quarantined corpora) to .github/fuzz-findings-recipient.pem and uploads only
# the sealed file, because CI logs and artifacts of this repository are public
# (fuzz/README.md, Continuous fuzzing). Anyone can encrypt to the public
# certificate, so treat what `open` unpacks as untrusted data.
#
# Needs OpenSSL 3.0 or later (AES-GCM in CMS) and GNU tar.
set -euo pipefail

usage() {
  sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
command="$1"
shift

case "${command}" in
  keygen)
    [[ $# -eq 2 ]] || usage
    key="$1" cert="$2"
    if [[ -e "${key}" ]]; then
      echo "refusing to overwrite ${key}" >&2
      exit 1
    fi
    (
      umask 077
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "${key}"
    )
    openssl req -x509 -new -key "${key}" -sha384 -days 3650 \
      -subj "/CN=browntls fuzz findings recipient" -out "${cert}"
    echo "private key: ${key} (never commit it to the public repository)"
    echo "recipient certificate: ${cert}"
    openssl x509 -in "${cert}" -noout -fingerprint -sha256
    ;;

  seal)
    [[ $# -eq 3 ]] || usage
    cert="$1" dir="$2" out="$3"
    openssl x509 -in "${cert}" -noout
    [[ -d "${dir}" ]] || { echo "no such directory: ${dir}" >&2; exit 1; }
    mkdir -p "$(dirname "${out}")"
    umask 077
    if ! tar -C "${dir}" -czf - . \
      | openssl cms -encrypt -binary -aes-256-gcm -recip "${cert}" -outform DER -out "${out}"; then
      rm -f "${out}"
      echo "sealing failed" >&2
      exit 1
    fi
    echo "sealed $(stat -c %s "${out}") bytes, SHA-256 $(sha256sum "${out}" | cut -d' ' -f1)"
    ;;

  open)
    [[ $# -eq 4 ]] || usage
    key="$1" cert="$2" in="$3" dir="$4"
    if [[ -e "${dir}" ]]; then
      echo "refusing to unpack into existing ${dir}" >&2
      exit 1
    fi
    mkdir -p "${dir}"
    chmod 700 "${dir}"
    archive="${dir}/.findings.tar.gz"
    if ! (umask 077 && openssl cms -decrypt -binary -inform DER -in "${in}" \
      -inkey "${key}" -recip "${cert}" -out "${archive}"); then
      rm -rf "${dir}"
      echo "decryption failed (wrong key, or the file was modified)" >&2
      exit 1
    fi
    tar -C "${dir}" -xzf "${archive}" --no-same-owner --no-same-permissions
    rm -f "${archive}"
    echo "unpacked into ${dir}"
    ;;

  *)
    usage
    ;;
esac
