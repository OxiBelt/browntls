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

## RFC 9525 service identity references

On an already running minikube profile, build the browntls image and run URI
identity validation over a TCP Service and SRV-ID validation over a UDP
Service, each with a positive and CA-trusted mismatched-reference case:

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag browntls-e2e:identity-amd64
python3 -B tests/kubernetes/service_identity.py --image browntls-e2e:identity-amd64 \
  --profile PROFILE
```

The runner reuses the profile, creates a per-run namespace and uniquely tagged
image, and deletes only those resources. Test keys and certificates are
generated in a temporary directory and mounted from per-case Secrets.


## RFC 10024 hybrid key agreement

On an already running minikube profile, build the browntls image and run
the six Service exchanges:

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag browntls-e2e:hybrid-amd64
python3 -B tests/kubernetes/rfc10024.py --image browntls-e2e:hybrid-amd64 \
  --profile PROFILE
```

Each group runs over a TCP TLS 1.3 Service and a UDP DTLS 1.3 Service. Both
endpoints use the Tokio adapters. The client verifies the Service DNS
identity, and the runner checks negotiated group, retry behavior and data
in both directions. Only the server pod mounts the private key. The run
uses its own namespace and image tag.

## ECH PEM over TCP Services

Run the ECH harness against an existing running minikube profile. Use an
image built for the profile's node architecture.

```sh
python3 -B tests/e2e/e2e.py build --arch amd64
python3 -B tests/kubernetes/ech_service.py --image browntls-e2e:amd64 \
  --profile PROFILE
```

The first TLS 1.3 exchange uses Tokio and the current public configuration.
The second starts with a stale configuration. The blocking client must
authenticate the public-name certificate, receive usable retry configs, and
reconnect with ECH accepted. The server must observe `ech_required` before
the accepted connection. Both cases verify the inner-name certificate and
the application request and reply through a Kubernetes TCP Service.

The server Secret holds the current private key and the retry configuration.
Each client mounts only the CA and its starting public configuration. The run
removes its temporary namespace, uniquely labelled image, and fixture files.
The caller manages the minikube profile lifecycle.

## External-PSK early data over TCP

Run the Phase 1 scenarios with a local `browntls-e2e` image and a running
minikube profile:

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --tag browntls-e2e:early-amd64
python3 -B tests/kubernetes/early_data.py --profile PROFILE \
  --image browntls-e2e:early-amd64
```

The runner uses fresh PSKs and one TCP Service per case. It checks acceptance
and policy refusal for both buffered and unbuffered Tokio, with exact
early-byte and unresent-byte counts. Each pair completes the authenticated
handshake and exchanges ordinary application data. Refusal uses a policy that
reports unavailable and an explicit client acknowledgement. The runner
verifies cleanup of its namespace and run-owned images. Both TLS peers use
browntls.

## Phase 2 record size limits and delegated credentials

With a built `browntls-e2e` image and a running minikube profile, run:

```sh
python3 -B tests/kubernetes/record_limits.py --profile PROFILE \
  --image browntls-e2e:amd64
```

The TCP cases use TLS 1.3 mutual delegated credentials and distinct local
record size limits through both the buffered Tokio connector/acceptor and the
unbuffered Tokio connector/acceptor. The UDP cases use DTLS 1.2 and 1.3 with
different limits at each endpoint and a 480-byte application payload that
fits both limits. Every case checks the negotiated protocol, certificate
authentication, delegated credential use where applicable, configured
limits, application data, and closure. The runner uses an isolated namespace
and image and verifies ownership-scoped cleanup.

## Zstandard certificate compression over Kubernetes Services

Build the peer with Zstandard enabled, then run against a running minikube
profile:

```sh
python3 -B tests/e2e/e2e.py build --arch amd64 --zstd --tag browntls-e2e:zstd-amd64
python3 -B tests/kubernetes/zstd_compression.py --image browntls-e2e:zstd-amd64 \
  --profile PROFILE
```

The harness runs TLS 1.3 over a TCP Service with buffered Tokio and unbuffered
Tokio, then DTLS 1.3 over a UDP Service with Tokio. The clients connect
through the Service ClusterIP and verify its DNS identity in the
certificate. The servers require and verify client certificates. The test
tool configs permit only Zstandard.
Connection JSON reports the per-connection count of successfully decoded
Zstandard certificates alongside the authenticated peer-certificate count
and request/reply data. DTLS records must report `DTLSv1_3`. The OpenSSL Docker
harness provides direct wire-level evidence for the compressed-certificate
algorithm. The runner reuses the ECH Service environment helper to create an
ownership-labelled image and namespace and verify their removal. The supplied
minikube profile remains running.
