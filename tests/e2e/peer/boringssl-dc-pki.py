#!/usr/bin/env python3
"""Create isolated test PKI and an RFC 9345 server delegated credential."""

import pathlib
import struct
import subprocess
import sys


SERVER_NAME = "tls-server.test"
SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256 = 0x0403
DELEGATED_CREDENTIAL_VALIDITY = 24 * 60 * 60


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def generate(server_dir, client_dir):
    server_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    client_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca_key = server_dir / "ca.key"
    ca_cert = server_dir / "ca.pem"
    leaf_key = server_dir / "server.key"
    leaf_csr = server_dir / "server.csr"
    leaf_ext = server_dir / "server.ext"
    leaf_cert = server_dir / "server.pem"
    dc_key = server_dir / "dc.key"

    command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-out", str(ca_key))
    command("openssl", "req", "-new", "-x509", "-key", str(ca_key), "-out",
            str(ca_cert), "-days", "2", "-subj", "/CN=browntls delegated credential test CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
            "keyUsage=critical,keyCertSign,cRLSign")

    command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-out", str(leaf_key))
    command("openssl", "req", "-new", "-key", str(leaf_key), "-out", str(leaf_csr),
            "-subj", f"/CN={SERVER_NAME}")
    leaf_ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{SERVER_NAME}\n"
        "1.3.6.1.4.1.44363.44=DER:05:00\n",
        encoding="ascii",
    )
    command("openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-set_serial", "2", "-days", "2", "-extfile",
            str(leaf_ext), "-out", str(leaf_cert))
    cert_der = server_dir / "server.der"
    command("openssl", "x509", "-in", str(leaf_cert), "-outform", "DER", "-out",
            str(cert_der))

    command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-out", str(dc_key))
    spki = subprocess.run(
        ["openssl", "pkey", "-in", str(dc_key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    credential = (
        struct.pack("!IH", DELEGATED_CREDENTIAL_VALIDITY,
                    SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256)
        + len(spki).to_bytes(3, "big")
        + spki
    )
    signature_input = (
        b" " * 64
        + b"TLS, server delegated credentials\x00"
        + cert_der.read_bytes()
        + credential
        + struct.pack("!H", SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256)
    )
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(leaf_key)],
        input=signature_input,
        check=True,
        capture_output=True,
    ).stdout
    delegated_credential = (
        credential
        + struct.pack("!H", SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256)
        + struct.pack("!H", len(signature))
        + signature
    )
    (server_dir / "dc.der").write_bytes(delegated_credential)

    # Only the public trust anchor enters the separate client volume.
    (client_dir / "ca.pem").write_bytes(ca_cert.read_bytes())
    leaf_key.unlink()
    for path in server_dir.iterdir():
        path.chmod(0o644)
    server_dir.chmod(0o755)
    client_dir.chmod(0o755)
    ca_key.unlink()
    leaf_csr.unlink()
    leaf_ext.unlink()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: boringssl-dc-pki.py SERVER_DIRECTORY CLIENT_DIRECTORY")
    generate(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))


if __name__ == "__main__":
    main()
