# CyberBoar protocol v1

Wire formats, authentication and validation rules for compatible consoles and static
bundle hosts. Endpoint commands are `enroll`, `pull` and `ship`. The endpoint release
does not include a console service. Use this reference to implement a compatible service
independently.

The [golden fixtures](../../testdata/protocol/) provide interoperability cases. For
deployment procedures, see [Operations](../operations.md).

> **License.** This document and the files in `testdata/protocol/` are part of CyberBoar and
> licensed under `AGPL-3.0-only`, with this additional permission under section 7 of that
> license: **you may implement this protocol in software under any license, and copy the
> golden files and the examples in this document into that software and its tests, without
> that software becoming subject to the AGPL.**

## Conventions

- Paths are relative to the console's base URL, e.g. `https://console.example`.
- **TLS 1.3 only.** Endpoints refuse plain `http` everywhere, loopback included, and any TLS
  version below 1.3; a server must offer TLS 1.3. The server certificate is verified against the
  system roots, or only against the CAs an operator pins (`--ca`); the one exception is
  `--insecure-skip-verify` for self-signed setups, which still encrypts but doesn't authenticate
  the server.
- **Every request to a console is authenticated, and every answer an endpoint acts on is signed**
  ([Endpoint authentication](#endpoint-authentication)). A static host that only serves bundles
  is not a console: it needs no authentication, because the bundle's own signature is what makes
  it trustworthy.
- URLs with credentials are refused.
- Endpoints never follow redirects: a redirect could send audit events to another host or
  downgrade to `http`. Serve the paths below directly.
- The API is versioned in the path (`/api/v1/`). Existing v1 message formats are frozen;
  new endpoints may be added. Incompatible messages require a new API version.

## Endpoint authentication

An endpoint **enrolls** once with a one-time enrollment token: it creates an ECDSA P-256
key pair, sends the public half with the token, and gets back a short-lived client
certificate for that key, the policy the console assigned it and the console's own
public key, which it pins. From then on:

- every request travels over **mutual TLS** with that client certificate, **and** carries an
  **HTTP Message Signature** (RFC 9421) made with the endpoint key, over the method, path, query
  and a digest of the body (RFC 9530 `Content-Digest`), with a timestamp and a nonce;
- every answer the endpoint acts on is **signed with the console key** and bound to the request it
  answers, so a forged or replayed `202` can't make `ship` discard events.

Mutual TLS ends at the first TLS terminator (a load balancer, an ingress); the signature
reaches the application and binds the body, so authentication holds wherever TLS ends.
Any failure keeps the endpoint's state: events stay in the audit log and are sent again,
the installed policy stays installed. Authentication failures do not trigger a weaker
authentication mode.

### Keys and encodings

Endpoint JSON decoding requires exact field spelling, rejects unknown fields,
duplicate keys and case aliases at every object depth, and allows one JSON value
only. Nesting beyond 32 levels is refused. These rules also apply to enrollment
records and Windows CNG key references.

| Item | Form |
|---|---|
| Signatures | ECDSA P-256 with SHA-256 only (RFC 9421 `ecdsa-p256-sha256`): `r` and `s` as 32-byte big-endian integers, concatenated, standard base64 with padding |
| Public keys in JSON | standard base64 of the key's DER `SubjectPublicKeyInfo`, canonical (`MFkw…`) |
| Endpoint ID | a lowercase version 4 UUID the endpoint creates once (`endpoint-id` in its state directory); the `keyid` of its signatures |
| Console key ID | lowercase hex SHA-256 of the console key's DER `SubjectPublicKeyInfo`; the `keyid` of its signatures |
| Enrollment token | `cyberboar_enroll_` and 43 base64url characters (256 random bits). The console keeps only its SHA-256 and shows the token once |

Endpoint identity keys use P-256 to support hardware-backed storage. Policy signing uses
a separate Ed25519 key. Current key-store availability is listed in [System
requirements](../system-requirements.md#endpoint-key-storage).

### Request signatures

Every request to a console, enrollment included, carries exactly these three header
fields, in this form byte for byte:

```
Content-Digest: sha-256=:<base64 SHA-256 of the body; of no bytes when there is none>:
Signature-Input: cyberboar=("@method" "@path" "@query" "content-digest");created=<Unix seconds>;keyid="<endpoint ID>";nonce="<22 base64url characters: 128 random bits>";alg="ecdsa-p256-sha256";tag="cyberboar.dev/endpoint/v1"
Signature: cyberboar=:<signature>:
```

The signature is over the signature base of RFC 9421 §2.5: one line per component,
`@path` the path as sent (percent-encoding unchanged, `/` if empty), `@query` a `?`
followed by the query as sent (`?` alone without one), the lines joined by `\n`, no `\n`
after the last. For the golden `requests/accept-bundle.http`:

```
"@method": GET
"@path": /api/v1/bundles/baseline
"@query": ?
"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
"@signature-params": ("@method" "@path" "@query" "content-digest");created=1790855990;keyid="3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24";nonce="_eWIhkP5LpohviooZCdlag";alg="ecdsa-p256-sha256";tag="cyberboar.dev/endpoint/v1"
```

Every request gets a new nonce, retries included. The scheme, the authority and other
header fields are not covered, because proxies rewrite them; the body is covered through
its digest. A proxy in front of a console must pass the path and query unchanged.

A console checks a request in this order; the first failure is its answer:

1. Exactly one `Signature-Input`, `Signature` and `Content-Digest`, each matching the profile
   above byte for byte: these components and parameters in this order and no others, `created`
   without leading zeros, the endpoint ID in lowercase. Anything else, including other valid
   RFC 9421 forms, is `401 unauthenticated`: the profile requires one canonical representation.
2. `created` within 300 seconds of the console's clock, either way: else `401 stale`.
3. `Content-Digest` matches the body: else `401 unauthenticated`.
4. The key: the endpoint's enrolled key, or for an enrollment the `publicKey` in the body (whose
   `endpoint.id` must equal `keyid`). No such endpoint: `401 unauthenticated`.
5. The signature verifies with that key: else `401 unauthenticated`.
6. Except for an enrollment, the TLS client certificate (below) chains to the console's endpoint
   CA, is valid now, names this endpoint and holds its enrolled key: else `401 certificate`. Where
   a proxy terminates TLS it verifies the chain and forwards the certificate, and the console
   checks the rest.
7. The endpoint isn't revoked: else `403 revoked`.
8. The pair (`keyid`, `nonce`) hasn't been accepted before: else `401 replayed`. The console
   records it only now, so an unauthenticated client can't use up nonces, and may forget it once
   `created` is more than 300 seconds old, since step 2 refuses the request from then on.

Messages for steps 1–5 don't say whether an endpoint exists.

### Answer signatures

Every answer below 400 to a signed request carries:

```
Content-Digest: sha-256=:<base64 SHA-256 of the answer's body>:
Signature-Input: cyberboar=("@status" "content-digest" "signature";req;key="cyberboar");created=<Unix seconds>;keyid="<console key ID>";alg="ecdsa-p256-sha256";tag="cyberboar.dev/console/v1"
Signature: cyberboar=:<signature>:
```

`"signature";req;key="cyberboar"` is the request's own signature (RFC 9421 §2.4), so an
answer verifies only for the request it answers. For the golden
`responses/accept-events.http`:

```
"@status": 202
"content-digest": sha-256=:Z4vsbpYJPKqfFMt/1mUgW/Dyq6WLfFU9TLBokSiC8o8=:
"signature";req;key="cyberboar": :LklrD0M1IbzvqSOq+w7pGDG4GgfKgPO981NQJf1H4ve7QjcumtdITIzyjR4IPJQQG0d0ALvnwLpjtV6w6wO25A==:
"@signature-params": ("@status" "content-digest" "signature";req;key="cyberboar");created=1790856000;keyid="61870fc6173d2425b03442ec6f9708c85d750d10e7ff42747861acb93c0fa07c";alg="ecdsa-p256-sha256";tag="cyberboar.dev/console/v1"
```

An endpoint accepts an answer below 400 only when the three fields match this profile
byte for byte, `keyid` is its pinned console key's ID, `created` is within 300 seconds
of its own clock, the digest matches the body and the signature verifies with the pinned
key. Anything else is a failed request. Error answers (400 and above) may be unsigned: a
proxy can produce them too, and an endpoint acts on none of them beyond reporting,
except the bounded wait of a `Retry-After` on `POST /api/v1/events`.

### Errors

Errors should have `Content-Type: application/json` and the body
`{"error":"<code>","message":"<what to fix>"}`. Endpoints show both (or the raw text of
a body that isn't this) and keep their state, whatever the code.

| Status | `error` | Meaning |
|---|---|---|
| 401 | `unauthenticated` | no valid signature by a known endpoint |
| 401 | `stale` | `created` is more than 300 seconds from the console's clock: check the endpoint's clock |
| 401 | `replayed` | the nonce was used before |
| 401 | `certificate` | no client certificate, or not this endpoint's; an expired one means enrolling again |
| 403 | `revoked` | the endpoint was revoked; the machine must be reset and enrolled as a new endpoint |
| 403 | `forbidden` | authenticated, but not allowed: a batch for another endpoint, a policy not assigned to it |
| 403 | `token` | the enrollment token is unknown, expired, revoked or used up |
| 409 | `conflict` | the endpoint ID is enrolled with another key, or was revoked |

### `POST /api/v1/enroll`

Signed with the key being enrolled, which proves the endpoint holds it; no client
certificate (there is none yet). `Content-Type: application/json`; anything else is
`415`. Body, at most 4 KiB:

```json
{"token":"cyberboar_enroll_…","endpoint":{"id":"3f1c6a52-…","hostname":"dev-laptop-17","version":"v1.0.0-rc.1"},
 "publicKey":"MFkw…"}
```

`endpoint` follows the rules of an audit batch's `endpoint` (below) and its `id` is the
request's `keyid`; `publicKey` is a P-256 key. Unknown fields are `400`. After steps 1–5
and 8 of the request check, with `publicKey` as the key, the token must be known,
unexpired and not revoked (else `403 token`). Each token names the policy its endpoints
get, how many it may enroll and until when.

- **A new endpoint ID:** the token must have a use left (else `403 token`); one is spent, the
  answer is `201`.
- **The ID already enrolled with this key, not revoked:** no use is spent, a new certificate is
  issued, the answer is `200` with the policy the console assigns the endpoint now, which need
  not be the token's. An endpoint whose answer was lost, or whose certificate expired, completes
  or repeats its enrollment this way, and one the console assigned another policy picks it up.
- **The ID enrolled with another key, or revoked:** `409 conflict`.

The answer is signed (above) with the key it carries:

```json
{"endpointId":"3f1c6a52-…","policy":"baseline","certificate":"-----BEGIN CERTIFICATE-----\n…","consoleKey":"MFkw…"}
```

The endpoint decodes it strictly and checks that the answer's signature verifies with
`consoleKey`, that `endpointId` is its own, that `policy` is a DNS label and that
`certificate` is a client certificate for its key (below). An operator can pin the
console key ahead of enrollment (`cyberboar enroll --console-key`); `consoleKey` must
then be that key. **With `--insecure-skip-verify` the pin is required**, since nothing
else would authenticate its enrollment response. A pin does not keep the enrollment
token confidential from an impersonated TLS server when certificate verification is
disabled; use `--ca` for a private CA or self-signed setup.
The endpoint then records the console's URL, its
endpoint ID, the policy, the console key and the certificate, and from then on talks
only to that console and trusts only that key.

### Client certificates

`certificate` is PEM: the client certificate, then at most three intermediates; at most
16 KiB. The client certificate holds the endpoint key, has exactly one URI subject
alternative name, `urn:uuid:<endpoint ID>`, has the `clientAuth` extended key usage and
is not a CA. The console issues it from an endpoint CA it uses for nothing else and
chooses its lifetime; 30 days is recommended. The endpoint presents it on every request
but enrollment, and renews it once half its lifetime has passed. Consoles ask for a
client certificate in every TLS handshake and enforce it per request (step 6), since
enrollment comes without one.

### `POST /api/v1/endpoint/certificate`

Renews the client certificate for the same key. Authenticated like every request (with
the current certificate), body `{}` as `application/json`. The answer is `200`, signed,
with `{"certificate":"…"}` in the form above. An expired certificate can't renew (`401
certificate`): the endpoint enrolls again with a token, keeping its key and ID. A
revoked endpoint gets `403 revoked`.

## Policy bundles

### `GET /api/v1/bundles/{name}`

`name` is the policy's `metadata.name` (a DNS label). The answer is `200` with
`Content-Type: application/json` and this body, a single line ending in `\n`:

```json
{"apiVersion":"cyberboar.dev/v1","kind":"PolicyBundle","name":"baseline",
 "policySha256":"…","policy":"…the policy file, byte for byte…","signature":"…"}
```

| Field | Meaning |
|---|---|
| `apiVersion` | the policy API version the endpoint understands; anything else is refused |
| `kind` | `PolicyBundle` |
| `name` | must equal `{name}` and the policy's `metadata.name` |
| `policySha256` | lowercase hex SHA-256 of `policy`'s bytes; endpoints report it in audit events (drift) |
| `policy` | the policy file as a JSON string, unchanged |
| `signature` | contents of the policy's `.sig` file: the signature with its serial and expiry ([Signature](#signature)); a bundle without one is refused |

An endpoint decodes the body strictly (unknown fields are an error), checks every row
above, the signature, its expiry and its serial ([Rollback and
expiry](#rollback-and-expiry)), and installs the policy only if everything holds.
**Anything else keeps the installed policy**; with no policy installed the hook denies
every call. Bundle bodies are bounded to 6 MiB plus 4 KiB: JSON can expand each byte
of a 1 MiB policy to a six-byte escape, with space left for the envelope and signature.

From a console the request is authenticated and the answer signed (above), and a console
serves an endpoint only the policy it assigned it (`403 forbidden` for any other name).
Other answers: `404` for an unknown name, and any non-`200` status is an error the
endpoint reports without changing anything.

**Caching.** A server should send a strong `ETag`; the reference console uses
`"sha256-<hex SHA-256 of the body>"` and `Cache-Control: no-cache`, and answers
`If-None-Match` with `304`. Because a bundle is a static document, any static host can
serve it (S3, nginx, GitHub Pages), as long as it is at this path and doesn't redirect;
`cyberboar bundle` writes such a site from a directory of signed policies.

### Signature

A signature is Ed25519 over this message (UTF-8, `\n` line ends, trailing `\n`):

```
cyberboar.dev/policy-signature/v2
<policy name>
<lowercase hex SHA-256 of the policy file>
<serial>
<expiry>
```

The **serial** is a decimal integer from 1 to 2^63 − 1, without sign or leading zeros.
The
**expiry** is an RFC 3339 time in UTC with whole seconds, `YYYY-MM-DDTHH:MM:SSZ`, after 1970, or
`never` for a policy that doesn't expire. The signature file (`POLICY.sig`, and a
bundle's `signature`) is exactly these four lines, with `\n` line ends and a trailing
`\n`, at most 256 bytes:

```
cyberboar.dev/policy-signature/v2
serial <serial>
expires <expiry>
signature <standard base64 (with padding) of the 64-byte signature>
```

Nothing else is accepted: no other spelling of the same values, no CRLF line ends, no
extra lines. For the golden `bundle-baseline.json` it is:

```
cyberboar.dev/policy-signature/v2
serial 1790856000
expires 2026-12-30T12:00:00Z
signature DMsHvBEPmeRWuC9XBiCEQhjBOmROlIbRMF2GFt/Vmmk0JqGwLWqpfHkNZ7MlDofMvZT9jw0UUXVnH2ckDaMiAQ==
```

Keys are PEM: PKCS#8 `PRIVATE KEY` and PKIX `PUBLIC KEY`, stored in regular files of at
most 4 KiB. Endpoints pin the public key; the console never needs the private key.
`cyberboar keygen`, `sign` and `verify` implement this. Private keys created by `keygen`
are owner-only (`0600`) on POSIX. On Windows they are created with a protected DACL for
the current user and SYSTEM, verified before writing key bytes; a filesystem that cannot
enforce it is refused.

### Rollback and expiry

The signature covers a serial and an expiry so that whoever controls a console, or the
network when the server isn't authenticated, can't serve an older signed policy (a
rollback) or keep serving one nobody renews (a freeze):

- **An endpoint never installs a lower serial than the installed policy's.** The installed serial
  is that of the signature file next to the installed policy, or 0 when none is installed.
  An invalid installed signature blocks updates. An equal serial is accepted only with
  the installed signature byte for byte, which changes nothing (or completes an install
  that was interrupted between writing the signature and the policy); the same serial
  with another signature is refused.
- **An endpoint refuses an expired bundle**, and from the expiry on the hook denies every tool
  call (`error.policyExpired`) until a newer signed policy is installed. The expiry instant
  itself is expired. Endpoints check it against their own clock; one that can't reach its
  console by then stays denied until it can. A policy signed with the expiry `never` doesn't
  expire: serials still stop rollbacks, but nothing stops a freeze.
- Serials are compared whatever the policy's name, so a deployment uses **one rising counter for
  every policy it signs**, such as the Unix time at signing (`cyberboar sign --serial $(date +%s)`).
  Going back to an older policy on purpose means signing it again with a new serial.
- Servers pass the signature file on unchanged. They need not parse it, but one that does should
  not serve an expired policy: `cyberboar bundle` writes nothing then, and the endpoint would
  refuse it.

`cyberboar sign` requires `--serial` and `--expires`, refuses an expiry more than 366 days
ahead (`--expires 0` or `never` signs without one, with a warning), and won't replace a
policy's signature with one whose serial is lower, or equal with other contents, since
endpoints that installed the old one would refuse it.

Only `cyberboar.dev/v1` policies and bundles using the signature format defined above
are accepted. Other API versions and incomplete signatures are rejected.

## Audit events

### `POST /api/v1/events`

Authenticated (above); `endpoint.id` must be the signing endpoint's ID, else `403
forbidden`. `Content-Type: application/json` (a `charset=utf-8` parameter is allowed,
nothing else). Any other type is `415`: a browser can't send JSON cross-origin without a
CORS preflight, which a console must never answer, so a web page can't post events
through a developer's browser.

Body, at most 4 MiB:

```json
{"endpoint":{"id":"3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24","hostname":"dev-laptop-17","version":"v1.0.0-rc.1"},
 "events":[ …audit lines, as written… ]}
```

| Field | Rule |
|---|---|
| `endpoint.id` | lowercase UUID; the endpoint's identity, created once and kept in `$XDG_STATE_HOME/cyberboar/endpoint-id` |
| `endpoint.hostname` | optional; at most 255 bytes of valid UTF-8 without control characters |
| `endpoint.version` | required; the same rule |
| `events` | a list (empty is a heartbeat), at most 1000 entries |

Unknown top-level or `endpoint` fields are an error. **Keys are exact and unique:** no
object in the body, at any depth, has the same key twice, also counting keys that differ
only in case, and a key naming a field of the batch, the endpoint, an event or an action
is spelled exactly as here. Many JSON parsers keep the first of two equal keys and some
the last, and `encoding/json` matches keys without regard to case, so either would let
one event read as `deny` to one consumer and `allow` to another. Objects and arrays nest
at most 32 levels in an event, and in the batch around its events. `audit.CheckKeys`
implements these rules. Each event is one audit line as the hook wrote it, at most 64
KiB, and must have `decision` `allow`, `ask` or `deny` and an RFC 3339 `time`. **Unknown
fields inside an event are kept, not rejected**: newer endpoints add fields. The event
fields are those of `audit.Event` (package `audit`); names never change. JSON Schemas
(draft 2020-12) describe the batch and each event: `pkg/audit/schema/batch.v1.json` and
`pkg/audit/schema/event.v1.json`, published under their `$id`. Tests hold them to
`audit.Event` and to the golden files below; the limits they can't express (bytes rather
than characters) are in their descriptions.

An event never exceeds 64 KiB: when the actions of one tool call don't fit (an
`apply_patch` that names thousands of files), the hook drops actions from the end and
counts them in `actionsOmitted`. The event's `decision`, `rule` and `reason` are still
the whole call's; a console should show that the list of actions is incomplete.

The batch is **all or nothing**: if any part is invalid the answer is `400` and nothing
is stored. Success is `202` with `{"accepted":N}`, signed; endpoints treat any other
status, a `202` whose signature doesn't verify, or an acknowledgment that does not
accept exactly N events, as failure and send the same batch again later. The
acknowledgment must be at most 512 bytes and contain only the exact `accepted` key
with an integer value; missing/null values, duplicate keys, case aliases and trailing
JSON are errors. Delivery is at least once, so a console may see a batch twice. `413` means
the body is too large. `503` means the console can't take the batch now: it couldn't
store it, or it is handling as many batches as it allows at once. A console should send
`Retry-After` (seconds or an HTTP date) with a `503`, or with a `429`; endpoints then
wait at least that long, at most an hour, before sending again. Without it they retry at
their next interval (`cyberboar ship --every`, or whatever runs `ship`). These answers
may be unsigned like any error answer, so the wait is the only thing an endpoint takes
from them: whoever could forge one could as well refuse every batch, and the events stay
in the endpoint's audit log.

## Golden files

`testdata/protocol/`:

- `bundle-baseline.json` and its `.etag`: the bundle for `examples/baseline.yaml`,
  signed with `insecure-test.key` (public half `insecure-test.pub`) with serial `1790856000`,
  expiring 2026-12-30T12:00:00Z. A server must be able to serve exactly this body for that
  policy and signature; an endpoint must accept it with that key at the clock
  **2026-10-01T12:00:00Z**, and refuse it from its expiry on. The key is public and for tests
  only.
- `bundle-reject-*.json`, the same policy signed otherwise, at the same clock: `expired` expires
  at that clock exactly and is refused; `api-version` has an unsupported bundle API
  version, and `signature` lacks the required signature headers; both are refused;
  `rollback` (serial `1790855999`) and `same-serial` (serial `1790856000`, a day's later expiry)
  are valid on their own, so an endpoint with nothing installed accepts them, but one that
  installed `bundle-baseline.json` refuses them and keeps it.
- `bundle-never-expires.json`: the same policy, serial `1790856002`, expiry `never`; accepted at
  any time.
- `events/accept-*.json` must be accepted (`202`), `events/reject-*.json` rejected with `400`
  and nothing stored. `accept-actions-omitted.json` has an event whose actions were cut short.
- `auth/`: the authentication layer, made for the clock **2026-10-01T12:00:00Z** (Unix
  1790856000) and endpoint `3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24`. The test keys are
  `insecure-endpoint` (the endpoint), `insecure-console` (the console's answers), `insecure-ca`
  (an endpoint CA, `insecure-ca.pem`) and `insecure-other` (a wrong signer); all are public and
  for tests only. The `.http` files are HTTP/1.1 messages with CRLF line ends.
  - `auth/requests/`: a console that knows `insecure-endpoint.pub` as that endpoint's key checks
    `accept-*.http` in name order and accepts each, then refuses each `reject-<code>-*.http` with
    that error code, all with one nonce memory (so `reject-replayed-*` repeats the nonce of
    `accept-events`). They cover steps 1–5 and 8; certificates can't be carried in a file.
  - `auth/responses/`: an endpoint that pinned `insecure-console.pub` accepts each `accept-X.http`
    as the answer to `requests/accept-X.http`, and refuses each `reject-*.http` as the answer to
    `requests/accept-events.http`. The certificates in `accept-enroll.http` and
    `accept-certificate.http` are for `insecure-endpoint` and chain to `insecure-ca.pem`.

Implementations should run these fixtures against their bundle, authentication and
event-validation paths. The endpoint repository tests use them as contracts; all fixture
keys are public test material and must never be used in deployments.
