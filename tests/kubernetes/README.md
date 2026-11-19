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
