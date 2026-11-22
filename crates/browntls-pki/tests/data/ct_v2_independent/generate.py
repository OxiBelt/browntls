#!/usr/bin/env python3
"""Produce the public RFC 9162 fixtures with Python and OpenSSL."""

import argparse
import hashlib
import subprocess
import tempfile
from pathlib import Path


BASE_MS = 1_717_200_000_000  # 2024-06-01 00:00:00 UTC
PRECERT_MS = BASE_MS
X509_MS = BASE_MS + 2_000
OLD_HEAD_MS = BASE_MS + 3_000
NEW_HEAD_MS = BASE_MS + 4_000
VALIDITY = ("-not_before", "20240101000000Z", "-not_after", "20250101000000Z")
# DER OID contents for the RFC 5612 documentation PEN, with two suffixes.
P256_ID = bytes.fromhex("2b0601040181fd5901")
ED25519_ID = bytes.fromhex("2b0601040181fd5902")


def openssl(work, *args, input_bytes=None):
    return subprocess.run(
        ["openssl", *args], cwd=work, input=input_bytes, stdout=subprocess.PIPE,
        check=True,
    ).stdout


def sha256(data):
    return hashlib.sha256(data).digest()


def u64(value):
    return value.to_bytes(8, "big")


def vector(data, length_bytes):
    return len(data).to_bytes(length_bytes, "big") + data


def trans_item(kind, payload):
    return kind.to_bytes(2, "big") + payload


def trans_item_list(*items):
    return vector(b"".join(vector(item, 2) for item in items), 2)


def der_element_end(data, offset, tag):
    """Locate one DER element emitted by OpenSSL."""
    if data[offset] != tag:
        raise ValueError(f"expected DER tag {tag:#x} at {offset}")
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    return start, start + length


def tbs_certificate(certificate):
    """Read the first child of a DER Certificate sequence, including its tag."""
    start, _ = der_element_end(certificate, 0, 0x30)
    _, end = der_element_end(certificate, start, 0x30)
    return certificate[start:end]


def octet_string(value):
    length = len(value)
    if length < 128:
        return b"\x04" + bytes([length]) + value
    encoded_length = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return b"\x04" + bytes([0x80 | len(encoded_length)]) + encoded_length + value


def issue_leaf(work, serial, embedded=None):
    extensions = (
        "[leaf]\n"
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = DNS:ct-fixture.example\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid\n"
    )
    if embedded is not None:
        extensions += f"1.3.101.75 = DER:{octet_string(embedded).hex()}\n"
    (work / "leaf.cnf").write_text(extensions, encoding="ascii")
    return openssl(
        work, "x509", "-req", "-in", "leaf.csr", "-CA", "issuer.pem",
        "-CAkey", "issuer.key", "-set_serial", str(serial), *VALIDITY,
        "-extfile", "leaf.cnf", "-extensions", "leaf", "-outform", "DER",
    )


def entry(kind, timestamp, issuer_hash, tbs):
    return trans_item(
        kind, u64(timestamp) + vector(issuer_hash, 1) + vector(tbs, 3)
        + vector(b"", 2),
    )


def sign(work, log, message):
    key = f"{log}.key"
    public_key = f"{log}-spki.der"
    if log == "p256":
        signature = openssl(work, "dgst", "-sha256", "-sign", key, input_bytes=message)
    else:
        (work / "message").write_bytes(message)
        signature = openssl(work, "pkeyutl", "-sign", "-inkey", key, "-rawin",
                            "-in", "message")
    (work / "signature").write_bytes(signature)
    if log == "p256":
        openssl(work, "dgst", "-sha256", "-keyform", "DER", "-verify", public_key,
                "-signature", "signature", input_bytes=message)
    else:
        openssl(work, "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                "-inkey", public_key, "-rawin", "-in", "message",
                "-sigfile", "signature")
    return signature


def sct(work, log, log_id, kind, timestamp, signed_entry):
    return trans_item(
        kind, vector(log_id, 1) + u64(timestamp) + vector(b"", 2)
        + vector(sign(work, log, signed_entry), 2),
    )


def tree_head(work, log, log_id, timestamp, size, root):
    body = u64(timestamp) + u64(size) + vector(root, 1) + vector(b"", 2)
    return trans_item(0x0104, vector(log_id, 1) + body + vector(sign(work, log, body), 2))


def proof(kind, log_id, first, second, nodes):
    path = vector(b"".join(vector(node, 1) for node in nodes), 2)
    return trans_item(kind, vector(log_id, 1) + u64(first) + u64(second) + path)


def node(left, right):
    return sha256(b"\x01" + left + right)


def generate(work):
    # Every private key is generated inside the temporary directory.
    for name, algorithm, options in (
        ("issuer", "ED25519", ()),
        ("leaf", "ED25519", ()),
        ("p256", "EC", ("-pkeyopt", "ec_paramgen_curve:P-256")),
        ("ed25519", "ED25519", ()),
    ):
        openssl(work, "genpkey", "-algorithm", algorithm, *options, "-out", f"{name}.key")

    openssl(
        work, "req", "-new", "-x509", "-key", "issuer.key", "-out", "issuer.pem",
        "-subj", "/CN=CT fixture issuer", "-set_serial", "1", *VALIDITY,
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign",
        "-addext", "subjectKeyIdentifier=hash",
    )
    openssl(work, "req", "-new", "-key", "leaf.key", "-subj", "/CN=ct-fixture.example",
            "-out", "leaf.csr")

    public = {
        "issuer.der": openssl(work, "x509", "-in", "issuer.pem", "-outform", "DER"),
    }
    for name in ("issuer", "p256", "ed25519"):
        filename = f"{name}-spki.der"
        openssl(work, "pkey", "-in", f"{name}.key", "-pubout", "-outform", "DER",
                "-out", filename)
        public[filename] = (work / filename).read_bytes()

    issuer_hash = sha256(public["issuer-spki.der"])
    # Capture the OpenSSL TBS without the CT extension before issuing the
    # final certificate. The serial, key, dates and other extensions match.
    precert_entry = entry(0x0101, PRECERT_MS, issuer_hash,
                          tbs_certificate(issue_leaf(work, serial=2)))
    precert_sct = sct(work, "ed25519", ED25519_ID, 0x0103, PRECERT_MS, precert_entry)
    leaf = issue_leaf(work, serial=2, embedded=trans_item_list(precert_sct))
    (work / "leaf.der").write_bytes(leaf)
    openssl(work, "x509", "-inform", "DER", "-in", "leaf.der", "-out", "leaf.pem")
    openssl(work, "verify", "-attime", str(BASE_MS // 1000), "-purpose", "sslserver",
            "-verify_hostname", "ct-fixture.example", "-CAfile", "issuer.pem", "leaf.pem")

    x509_entry = entry(0x0100, X509_MS, issuer_hash, tbs_certificate(leaf))
    p256_sct = sct(work, "p256", P256_ID, 0x0102, X509_MS, x509_entry)
    ed25519_sct = sct(work, "ed25519", ED25519_ID, 0x0102, X509_MS, x509_entry)
    fillers = [
        entry(0x0100, BASE_MS + 1_000, issuer_hash,
              tbs_certificate(issue_leaf(work, serial=serial)))
        for serial in (10, 11, 12)
    ]
    # Spell out the topology for [A, B, C, D, E] and its [A, B, C] prefix.
    entries = (fillers[0], fillers[1], x509_entry, fillers[2], precert_entry)
    a, b, c, d, e = (sha256(b"\x00" + item) for item in entries)
    ab = node(a, b)
    abcd = node(ab, node(c, d))
    root3 = node(ab, c)
    root5 = node(abcd, e)

    public.update({
        "leaf.der": leaf,
        "x509-entry.bin": x509_entry,
        "precert-entry.bin": precert_entry,
        "root-3.bin": root3,
        "root-5.bin": root5,
        "x509-leaf-hash.bin": c,
        "precert-leaf-hash.bin": e,
        "tls-list.bin": trans_item_list(
            proof(0x0106, P256_ID, 5, 2, (d, ab, e)), p256_sct,
            tree_head(work, "p256", P256_ID, NEW_HEAD_MS, 5, root5),
        ),
        "ocsp-list.bin": trans_item_list(
            precert_sct, ed25519_sct, proof(0x0106, ED25519_ID, 5, 4, (abcd,)),
            tree_head(work, "ed25519", ED25519_ID, NEW_HEAD_MS, 5, root5),
        ),
        "ed25519-stale-head.bin": tree_head(
            work, "ed25519", ED25519_ID, PRECERT_MS - 1, 5, root5,
        ),
    })
    for log, log_id in (("p256", P256_ID), ("ed25519", ED25519_ID)):
        public[f"{log}-old-head.bin"] = tree_head(work, log, log_id, OLD_HEAD_MS, 3, root3)
        public[f"{log}-consistency.bin"] = proof(0x0105, log_id, 3, 5, (c, d, ab, e))
    return public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="directory for public fixtures only")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="browntls-ct-v2-") as directory:
        public = generate(Path(directory))

    args.output.mkdir(parents=True, exist_ok=True)
    for name, data in public.items():
        (args.output / name).write_bytes(data)
    checksums = "".join(f"{sha256(data).hex()}  {name}\n" for name, data in sorted(public.items()))
    (args.output / "SHA256SUMS").write_text(checksums, encoding="ascii")


if __name__ == "__main__":
    main()
