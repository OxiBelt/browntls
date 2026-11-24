#!/bin/sh
# Generate distinct leaves for the authenticated inner and public ECH names.
set -eu
umask 077
cd "${1:?missing fixture directory}"
inner="${2:?missing inner name}"
public="${3:?missing public name}"

trap 'rm -f ca.key leaf.csr leaf.ext' EXIT
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl req -new -x509 -key ca.key -out ca.pem -days 1 \
    -subj '/CN=browntls ECH fixture CA' \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign

for role in inner public; do
    case "$role" in
        inner) name="$inner"; serial=2 ;;
        public) name="$public"; serial=3 ;;
    esac
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$role.key"
    openssl req -new -key "$role.key" -out leaf.csr -subj "/CN=$name"
    printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature \
        extendedKeyUsage=serverAuth "subjectAltName=DNS:$name" > leaf.ext
    openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial "$serial" \
        -days 1 -extfile leaf.ext -out "$role.pem"
done
