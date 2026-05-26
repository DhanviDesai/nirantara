# KMS-backed enrollment API

`nirantara-enrollment` is the server-side certificate enrollment API. It accepts
client CSRs at `POST /enroll`, reads the client-provided device id from the
`X-Device-Id` header, and returns a PEM-encoded client certificate whose subject
is:

```text
CN=<device_id>, O=Nirantara
```

The service never loads a CA private key. It constructs the X.509 certificate
locally, hashes the TBSCertificate DER with SHA-256, and calls AWS KMS `Sign`
with `ECDSA_SHA_256`. The configured CA certificate must contain the public key
for the asymmetric KMS key configured in `NR_ENROLL_KMS_KEY_ID`.

## Required KMS key

Create an asymmetric AWS KMS signing key compatible with ECDSA P-256:

- Key spec: `ECC_NIST_P256`
- Key usage: `SIGN_VERIFY`
- Signing algorithm: `ECDSA_SHA_256`

The CA certificate distributed to clients and Mosquitto must be generated from
that KMS key's public key. `tools/ca/gen_ca.sh` remains a local development CA
only; it does not represent the production KMS CA.

## Configuration

| Variable | Required | Default | Description |
|---|---:|---|---|
| `NR_ENROLL_CA_CERT` | yes | - | Path to the CA certificate PEM whose public key matches the KMS key |
| `NR_ENROLL_KMS_KEY_ID` | yes | - | KMS key id, alias, or ARN used for certificate signatures |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | yes | - | AWS region for the KMS endpoint |
| `AWS_ACCESS_KEY_ID` | yes | - | IAM access key with `kms:Sign` permission |
| `AWS_SECRET_ACCESS_KEY` | yes | - | IAM secret key |
| `AWS_SESSION_TOKEN` | no | - | Session token for temporary credentials |
| `NR_ENROLL_DEVICE_ALLOWLIST` | production | - | Newline-separated list of device ids allowed to enroll |
| `NR_ENROLL_ALLOW_ANY_DEVICE` | dev only | `0` | Set to `1` to bypass the allowlist locally |
| `NR_ENROLL_LISTEN_HOST` | no | `127.0.0.1` | IPv4 address to bind |
| `NR_ENROLL_PORT` | no | `8080` | HTTP listen port, intended to sit behind TLS termination |
| `NR_ENROLL_CERT_TTL_DAYS` | no | `365` | Issued certificate validity |

## Request

```http
POST /enroll HTTP/1.1
Content-Type: application/x-pem-file
X-Device-Id: device-123
Content-Length: <csr length>

-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
```

The handler verifies the CSR signature to prove possession of the private key,
but the issued certificate subject is derived from `X-Device-Id`, not from the
CSR subject. That keeps the enrollment API authoritative for MQTT identity.

## Response

```http
HTTP/1.1 201 Created
Content-Type: application/x-pem-file

-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

Run the service behind HTTPS termination that presents a certificate chaining to
the CA pinned by clients. The client library already sends `X-Device-Id` during
`nr_enroll()`.
