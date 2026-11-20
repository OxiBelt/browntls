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
#         AuthEnvelopedData (ECDH key agreement with a SHA-384 KDF,
#         AES-256-GCM), written to OUT
#         in DER. The archive is streamed into the encryption, never written
#         out in plaintext. Prints OUT's size and SHA-256 only.
# open    decrypts IN with KEY and unpacks it into DIR, which must not exist
#         yet. The archive is unpacked only after decryption succeeded, which
#         includes the GCM tag check. DIR, any parent directories it creates,
#         and everything unpacked get owner-only modes (umask 077 throughout,
#         whatever modes the archive records), since the findings are private.
#         A default ACL on an existing parent directory overrides the umask:
#         the parents `open` creates keep what it grants. DIR gets mode 700,
#         which also clears its ACL mask, before anything is decrypted into
#         it, so its contents are unreachable through the ACL; DIR and its
#         subdirectories keep the default ACL, which files created there
#         later inherit.
#
# The Fuzz workflow seals a failing job's findings (inputs, libFuzzer logs,
# quarantined corpora) to the certificate in the Actions variable
# FUZZ_FINDINGS_RECIPIENT and uploads only the sealed file, because CI logs and artifacts of this repository are public
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
      | openssl cms -encrypt -binary -aes-256-gcm -recip "${cert}" \
        -keyopt ecdh_kdf_md:sha384 -outform DER -out "${out}"; then
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
    # The findings are private: nothing created from here on may be
    # accessible to other users, whatever the caller's umask. `seal` archives
    # DIR's own entry (`.`) and the modes of the files under it, and
    # --no-same-permissions only applies the umask to those modes, so the
    # umask must cover the extraction as well as the decryption.
    umask 077
    mkdir -p -- "$(dirname -- "${dir}")"
    # A plain mkdir fails on an existing directory, which the check above
    # misses for names such as `existing/new/..`.
    if ! mkdir -- "${dir}"; then
      echo "cannot create ${dir}, which must not exist yet" >&2
      exit 1
    fi
    # Not redundant with the umask: under a default ACL the umask is ignored,
    # and mode 700 also clears the ACL mask.
    chmod 700 -- "${dir}"
    # Removes DIR even when the archive made parts of it unreadable or
    # unwritable for its owner (chmod changes a directory before reading it).
    discard() {
      chmod -R u+rwX -- "${dir}" 2>/dev/null || true
      rm -rf -- "${dir}"
    }
    archive="${dir}/.findings.tar.gz"
    if ! openssl cms -decrypt -binary -inform DER -in "${in}" \
      -inkey "${key}" -recip "${cert}" -out "${archive}"; then
      discard
      echo "decryption failed (wrong key, or the file was modified)" >&2
      exit 1
    fi
    # The archive cannot replace the decrypted file it is read from.
    if ! tar -C "${dir}" -xzf "${archive}" --no-same-owner --no-same-permissions \
      --exclude=.findings.tar.gz; then
      discard
      echo "unpacking failed (unsafe or malformed archive); nothing was kept" >&2
      exit 1
    fi
    # Give the owner access to everything (an archive can record mode 000
    # entries, DIR's own included) and drop any group or other access that
    # survived. GNU chmod does not follow symbolic links met while
    # recursing.
    if ! chmod -R u+rwX,go-rwx -- "${dir}"; then
      discard
      echo "restricting permissions failed; nothing was kept" >&2
      exit 1
    fi
    rm -f -- "${archive}"
    echo "unpacked into ${dir}"
    ;;

  *)
    usage
    ;;
esac
