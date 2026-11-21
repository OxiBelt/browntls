# Revocation in minikube

The suite serves an ephemeral certificate using Tokio and a private OpenSSL
OCSP responder. It checks live lookup, egress denial while TLS remains
reachable, and live rotation of the server's staple. The client exercising
the staple has responder access blocked for both handshakes.

On x86-64 Linux, install Docker, OpenSSL, minikube v1.39.0, and
`musl-gcc`. Run from the repository root.

```sh
scripts/ci/install-rust.sh x86_64-unknown-linux-musl
python3 -B tests/kubernetes/revocation.py
```

The runner starts Kubernetes v1.37.0 with Calico and removes its temporary
profile on exit. To reuse a running Calico-enabled minikube profile, pass
`--profile NAME`. This mode creates and cleans up its own test namespace.
`--binary PATH` accepts an existing static build of the Tokio example.

The responder and TLS server mount separate test keys. The clients mount
public trust material and use the same image. The runner prints pod status
and limited server and responder logs on failure.

## Certificate with external PSK (RFC 9973)

For a running minikube profile, build a browntls e2e image and run the
strict TLS/DTLS service checks:

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag browntls-e2e:psk-amd64
python3 -B tests/kubernetes/extern_psk.py --image browntls-e2e:psk-amd64 \
  --profile PROFILE
python3 -B -m unittest discover -s tests/kubernetes -p 'test_extern_psk.py'
```

The runner requires an already running profile. It does not start, stop, or
delete that profile. In its own namespace it exercises strict async Tokio TLS
over a TCP Service and DTLS 1.3 over a UDP Service. Both require an external
PSK, certificate-with-external-PSK negotiation and a verified server
certificate, then check the request and reply. A generated 32-byte PSK and
test certificates are mounted from a temporary Kubernetes Secret; the
namespace and uniquely tagged image are removed after the run. The
[wolfSSL Docker suite](../e2e/README.md#certificate-with-external-psk-rfc-9973)
qualifies the feature with a second TLS implementation.
