# luk - protocol

What a client of lukd must do on the wire: the channel to the endpoints
(uploads, link requests, the endpoint listing) and the signed downloads.
It is written for the authors of other clients; `luk` is the reference
client. The document is derived from the code (`internal/channel`,
`internal/wire`, `internal/sshsig`, `internal/client`,
`internal/server`, `internal/expose`): where this document and `luk`
disagree, one of them has a bug.

`doc/SPEC.md` is the specification of the system: the configuration and
behavior of lukd, the commands of luk. This document repeats from it only
what a client needs, and adds what SPEC leaves to the code: byte layouts,
encodings, the exact signed texts, the order of checks a client can
observe and test vectors (section 8).

Conventions: "MUST" and "MUST NOT" are requirements on a client; a client
that breaks one is refused by lukd, or is insecure. `||` is
concatenation, `BE` big-endian, `LE` little-endian. Hex values are
lowercase. "base64" is the standard alphabet with padding (RFC 4648
section 4), "base64url" the URL alphabet without padding (section 5).
Texts are UTF-8. A canonical text is lines joined by a single `\n`
(0x0a) without a trailing newline.

## 1. Versioning

Every part of the protocol that both sides must read the same way carries
a label. An incompatible change gets a new label; nothing is negotiated.

| what | label |
|---|---|
| channel (prologue of the handshake) | `luk-channel@1` |
| media type of channel requests and answers | `application/vnd.luk.channel` |
| first byte of a channel body | `0x01` handshake, `0x02` transport |
| signature of an upload (in the channel) | SSHSIG namespace `luk-upload@v2` |
| signature of a link request (in the channel) | SSHSIG namespace `luk-link@v2` |
| signature of the endpoint listing (in the channel) | SSHSIG namespace `luk-list@v2` |
| signature of a download (plain HTTPS) | SSHSIG namespace `luk-get@v1` |

- The namespace is also the first line of its canonical text, so a
  signature of one kind never verifies as another (domain separation,
  section 7).
- The `v2` namespaces are signed only inside the channel and their texts
  end with the handshake hash `h`; lukd refuses any other namespace
  there (401). `luk-get@v1` is never accepted inside the channel and the
  channel namespaces never on a download.
- lukd is strict about what a client sends: the client meta (`Luk-Meta`)
  and the link meta are JSON objects decoded with unknown fields refused
  and nothing allowed after the object; the JSON head of an inner
  request (section 4) too. A field this version does not know is a
  refusal, never ignored, so a meta is never read two ways.
- A client is strict about the frame of an answer (the inner response
  head refuses unknown fields and trailing data, as `luk` does) and
  lenient about the JSON bodies of answers: it MUST ignore fields it does
  not know there. lukd may add fields to answer bodies within a version;
  it adds none to the heads.
- A new message kind, a changed byte layout, a changed canonical text or a
  changed meaning of a meta field is an incompatible change: a new
  prologue label or a new namespace, never a reinterpretation of the old
  one.

## 2. Trust

A client trusts two things, kept apart:

- **The endpoint pin**: the static X25519 public key of lukd, its
  identity key. The channel authenticates lukd by it (section 4). TLS
  carries the channel but is not part of the trust for endpoints: a
  client MUST NOT require or check certificates for endpoint URLs (`luk`
  sets no CA and no pin there, and `http://` and `https://` endpoint
  URLs work the same). A proxy that ends TLS sees neither the content
  nor the answers.
- **The download pin**: downloads (section 6) are plain HTTPS. The
  server is authenticated by TLS: the system CAs, or the SPKI pin of the
  certificate.

### Endpoint pin forms

| form | written as |
|---|---|
| full key | exactly 43 characters of base64url without padding, decoding to the 32 bytes of the public key; the strict decoding refuses non-zero trailing bits, so a key has exactly one string |
| words | 6 proquint groups of the first 12 bytes of SHA-256 of the 32-byte public key, lowercase, joined by `-`: `pabom-nobib-basov-ribil-fitav-vozah` |
| list | pins of either form separated by `,` (the fragment of an endpoint URL, `https://lukd.example:8443/drop#<pin>,<pin>`) |

- The two forms are told apart by the length: 43 characters is a key,
  anything else is parsed as words.
- Proquint of a 16-bit group `w` (big-endian from two bytes): consonant
  `w>>12`, vowel `(w>>10)&3`, consonant `(w>>6)&15`, vowel `(w>>4)&3`,
  consonant `w&15`, with consonants `bdfghjklmnprstvz` and vowels `aiou`.
- A key matches a pin of the key form when the 32 bytes are equal, one of
  the words form when the first 12 bytes of its SHA-256 are equal. All 96
  bits are compared. Compare in constant time.
- A list accepts lukd when its key matches any pin of it (rotation: the
  operator gives clients the new pin next to the old one before the key
  changes).
- An endpoint pin is never a TLS pin: `sha256//...` given as an endpoint
  pin is an error (`luk`: `an endpoint pin is the lukd key: run luk scan
  URL`).
- A client MUST check the key lukd presents in the handshake against the
  pins before it sends anything else (section 4.3). A client MUST NOT
  contact an endpoint it has no pin for, except to show the key to a
  person who then decides (`luk scan`: a handshake on the endpoint
  listing path, with no OP).

### Download pin

`sha256//` followed by the base64 (with padding, 44 characters) of the
SHA-256 of the `SubjectPublicKeyInfo` of the leaf certificate. With a pin
the client skips the chain and checks only that the leaf matches the pin
(`luk`); without one it verifies the chain against the system CAs and
the host name. lukd appends the pin as the fragment of the URLs of
listeners with a self-signed or file certificate
(`luk://host/name#sha256//...`; `luk` also accepts `#pin=sha256//...`).
`luk://` always means HTTPS.

## 3. Identities

A client is identified by an SSH key: the public key inside the signature
blob of each signed request. lukd maps it to an identity; the client
sends no name.

- **Plain key**: any key type `golang.org/x/crypto/ssh` verifies:
  `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, the FIDO types
  `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`,
  and RSA of at least 2048 bits signing `rsa-sha2-256` or
  `rsa-sha2-512`.
- **OpenSSH certificate** (host or user): the SSHSIG blob carries the
  certificate as its public key and the signature of the certified key
  (as `ssh-keygen -Y sign` does with a `-cert.pub` beside the key). lukd
  checks the CA, the type, the validity window and revocations.
- **Refused**: DSA keys (`ssh-dss`); RSA keys under 2048 bits; the SHA-1
  signature formats `ssh-rsa` and `ssh-dss` (an RSA key MUST sign
  `rsa-sha2-256` or `rsa-sha2-512`; `luk` signs `rsa-sha2-512`); the
  same inside a certificate, and a certificate whose CA signed it in a
  SHA-1 format. Each is 401.

### SSHSIG

Signatures are SSHSIG (OpenSSH `PROTOCOL.sshsig`), the output of
`ssh-keygen -Y sign`, sent as the raw blob (not the armored form) in
base64 on one line. `string` is a uint32 BE length and the bytes.

```
signed data = "SSHSIG" || string(namespace) || string("") ||
              string("sha512") || string(SHA-512(canonical text))
blob        = "SSHSIG" || uint32 BE 1 || string(public key blob) ||
              string(namespace) || string("") || string("sha512") ||
              string(signature)
signature   = the SSH signature of signed data: string(format) || string(bytes)
              (|| the flags and counter of the sk- types)
```

- The hash algorithm MUST be `sha512`; lukd refuses any other (401).
- The namespace in the blob MUST be the namespace of the request.
- Ed25519 signatures are deterministic, so the vectors of section 8 can
  be reproduced exactly.

## 4. The channel

### 4.1 Carrier

Every channel request is an HTTP `POST` to the endpoint URL (or to the
endpoint listing, `/.well-known/luk/endpoints`) with
`Content-Type: application/vnd.luk.channel` and a body that is one
handshake or one transport request. lukd tells a channel request by the
method and the media type before the path.

- The answer of the channel is `200` with `Content-Type:
  application/vnd.luk.channel`. Anything else (another status, another
  type) is an answer from outside the channel: a proxy, or lukd refusing
  a request in the clear (4.8). A client MUST NOT follow redirects.
- A request to an endpoint path or the listing outside the channel is
  `400 {"error": "protocol mismatch"}`.
- Every request of a session MUST reach the lukd process that holds the
  session (sessions live in the memory of one lukd). `luk` resolves the
  host once per session and sends every request of the session to that
  one address, each on a connection of its own or a kept-alive one;
  proxy environment variables are not used. A client may use several
  connections at once (parallel parts).
- The `Host` header and the path MUST reach lukd unchanged: both are
  bound into the handshake (4.2) and every signature. A request body may
  be streamed (chunked) or sent with a length.
- HTTP version, TLS and connection reuse are the client's choice. The
  `Date` header of an answer is not authenticated; `luk` uses it only to
  report its clock offset after a 401 `timestamp outside the allowed
  window`.

### 4.2 Handshake

Noise protocol `Noise_NX_25519_ChaChaPoly_SHA256` (revision 34 of the
Noise specification). The client is the initiator and is anonymous in
Noise; lukd sends its static key encrypted in message 2. Neither message
carries a payload.

```
prologue = "luk-channel@1\n" || host || "\n" || path

handshake request body:  0x01 || e                      (33 bytes)
handshake response body: 0x01 || e || enc(s) || enc("")  (97 bytes:
                         32 + 32 + 16 + 16)
```

- `host`: the value of the `Host` header the client sends, lowercase,
  with `:port` when it has one (`lukd.example:8443`; a URL with an
  explicit default port keeps it: `host:443`). lukd takes the `Host` of
  the request, lowercase.
- `path`: the path of the request URL exactly as lukd decodes it (the
  unescaped path; `/drop`, `/.well-known/luk/endpoints`). `luk` posts to
  the path of the endpoint URL, `/` when it is empty.
- A rewrite of the `Host` or the path on the way makes the two sides mix
  different prologues: message 2 does not decrypt and the handshake
  fails (`luk`: `the handshake failed: was the Host or path changed on
  the way (a proxy)?`).
- lukd answers a handshake only on an endpoint path of the listener (a
  trailing slash ignored for the lookup) or the listing path: any other
  path is 404 `no endpoint <path>`; a lukd without an identity key
  answers 404 `no channel`. A body over 64 bytes or not a valid message 1
  is 400 `bad handshake`.
- The client reads the response body whole (`luk`: at most 64 KiB),
  checks the first byte (`0x01`), reads Noise message 2 and takes the
  remote static key `rs`.
- `luk` bounds the handshake with 10s.

### 4.3 Pin check, session keys and channel id

Right after message 2 the client MUST compare `rs` with the pins of the
endpoint (section 2) and stop when none matches (`luk`: `the lukd key
<words> matches no pin of this endpoint`). In NX this check is a step of
the client, not a property of the handshake: without it the channel
authenticates nothing.

The handshake ends with Noise `Split()`:

- `k1` (first output): the client to lukd key, for every request frame;
- `k2` (second output): the lukd to client key, for every answer frame;
- `h`: the handshake hash after message 2 (Noise `GetHandshakeHash()`,
  32 bytes). It ends every signed text inside the channel.

```
channel id = first 16 bytes of SHA-256("luk channel id" || h)
```

lukd never assigns or sends the id: both sides derive it.

The transport ciphers are used with explicit nonces only (the Noise
`CipherState` counters are not used): `ENCRYPT(k, n, ad, plaintext)` of
the Noise ChaChaPoly cipher, that is ChaCha20-Poly1305 (RFC 8439) with
the 96-bit nonce `0x00000000 || LE64(n)` and a 16-byte tag appended. Note
that `n` is little-endian inside the AEAD nonce but big-endian in the
clear headers below.

### 4.4 Transport requests and answers

```
transport request body:  0x02 || channel id (16) || nonce (8, BE) || frames
transport answer body:   0x02 || counter (8, BE) || frames
```

The first 25 bytes of a request are its clear header. The nonce there is
the nonce of the message as a whole: its frame and last bits are 0 (lukd
answers anything else 400 `bad channel request`).

#### Request nonce

```
bits 63..60  kind     1 OP, 2 PART, 3 COMPLETE, 4 ABORT, 6 KEEPALIVE
                      (5 reserved; 0 and 7..15 unknown: 400 in the clear)
bits 59..28  number   PART: the part number; COMPLETE: the round (0 first);
                      KEEPALIVE: a sequence from 0; OP and ABORT: 0
bits 27..16  attempt  0..4095, the client's resend counter (4.7)
bits 15..1   frame    the index of the frame in the message (0..32767)
bit  0       last     1 on the final frame of the message
```

`nonce = kind<<60 | number<<28 | attempt<<16 | frame<<1 | last`.

The OP of a session is kind 1, number 0: lukd answers an OP with another
number 400 `bad channel request` in the clear and leaves the session
alone. The attempt is free; `luk` sends attempt 0.

#### Frames

The plaintext of a message is cut into frames of 65536 bytes. Every frame
but the final one carries exactly 65536 bytes; the final frame carries 0
to 65535 bytes. A message whose plaintext is a multiple of 65536 bytes
(the empty plaintext included) ends with an empty final frame. The reader
tells the final frame by its length: a sealed frame shorter than
65536 + 16 bytes is the final one.

```
request frame i:  ENCRYPT(k1, nonce with frame=i and last=(final), AD, chunk i)
                  AD = the 25-byte clear header of the request
answer frame i:   ENCRYPT(k2, counter<<32 | i<<1 | last, AD, chunk i)
                  AD = 0x02 || channel id (16) ||
                       request nonce (8, BE, frame and last 0) || counter (8, BE)
```

- A request has at most 32768 frames (the frame field), so a message
  carries less than 2 GiB; hence the bound of `parts.size` (5.2).
- The answer counter is lukd's, per session: it starts at 1 and grows by
  one per answer, never reused; a client refuses 0 and values of 2^32 or
  more. The AD binds an answer to its session and to the one request it
  answers.
- A stream that ends after a full frame (last = 0) is truncated: an
  error, never a short message. A frame that does not open is an error.
  A client MUST NOT act on an answer before its final frame opened
  (`luk` reads the whole answer, at most 64 MiB, before it looks at it).

#### Inner messages

```
OP:                         uint32 BE n || JSON request head (n bytes) || body (empty)
every answer:               uint32 BE n || JSON answer head (n bytes)  || body
PART:                       the raw bytes of the part
COMPLETE, ABORT, KEEPALIVE: empty
```

- Request head: `{"method": "...", "target": "...", "header": {...}}`.
  `method` is required. `target` is the path of the session as it goes
  on a request line (`luk`: the escaped path, without a query); its
  decoded path MUST equal the session path (else 404 `not found`,
  inside). `header` is a map of header names to lists of strings (the
  HTTP header form, `{"Luk-Nonce": ["..."]}`); names are
  case-insensitive.
- Answer head: `{"status": <int>, "header": {...}}`; the header carries
  `Content-Type: application/json` and, when they apply, `Retry-After`
  (seconds) and `Allow`. The body is JSON (lukd indents it with two
  spaces and ends it with a newline; a client parses it, it never
  compares bytes). An error answer is `{"error": "<text>"}`.
- A head is at most 65536 bytes of JSON; unknown fields and data after the
  JSON value are refused. The plaintext of an OP is at most 1 MiB (413
  in the clear).
- The OP of every operation has an empty body: the content of an upload
  goes in PART messages. An upload OP with a body is 400 `an upload
  inside the channel sends its content in parts`.
- COMPLETE, ABORT and KEEPALIVE carry an empty plaintext (one empty final
  frame); anything else is 400 `a control message carries nothing`.

### 4.5 One operation per session

- A session carries exactly one OP, signed (section 5). A second OP is
  409 `the session has had its operation`, in the clear, and changes
  nothing.
- The answer to the OP ends the session, unless the OP opened an upload
  in parts (an upload or a link replace that got the parts offer): that
  session then carries the PART, COMPLETE, ABORT and KEEPALIVE messages
  of its one upload, and nothing else. The messages carry no upload id:
  the session is the upload.
- A PART, COMPLETE or ABORT in a session without an upload is 404 `no
  upload in the session`, in the clear; a KEEPALIVE in a session without
  its OP is 409 `the session has no operation`.
- A new operation is a new handshake. A client never sends two OPs, and
  never sends the OP again in the same session (its answer lost: the
  operation's result is unknown to the client; `luk` does not retry an
  OP, except as below).

### 4.6 Session lifetime

Defaults of lukd (the operator may change them):

- From the handshake to the OP: 60s (`limits.channel.auth`). The OP must
  also arrive within it once its clear header came. The window covers a
  hardware key touch or an agent unlock, which happen here because the
  signature covers `h`. `luk` does not send an OP whose signature took
  over 55s.
- Sessions without their OP: at most 1024 (`limits.channel.pending`) over
  all listeners. A new handshake beyond that evicts the oldest pending
  session. An evicted session answers its OP 404 `unknown session` in the
  clear; `luk` then runs one new handshake and signs again (a new
  timestamp and nonce), once.
- A session with its OP and an upload lives as long as its upload: an
  open upload without activity (a message that opened, bytes of a part)
  for `limits.body.idle` (default 2m, the `idle` of the offer) expires;
  after the upload ended the session keeps its final answer for 3 x
  `idle`.
- Sessions live in the memory of one lukd process: a restart drops them
  all (404 `unknown session`); lukd checks expiry about once a minute,
  so a limit may act up to a minute late.

### 4.7 Nonces and retries

- Every message of a session is taken once by its base nonce (kind,
  number, attempt; frame and last 0). A message under a base nonce lukd
  took before is 409 `repeated nonce`, in the clear.
- A client MUST NOT encrypt twice under one base nonce, not even the same
  plaintext: every resend of a PART, COMPLETE or ABORT uses the next
  attempt of its kind and number (`luk` keeps a counter per base nonce
  and refuses to send a nonce twice). A KEEPALIVE takes the next number
  instead. The attempt is 0..4095; a part out of attempts fails.
- A resend is always allowed: lukd answers a part it verified 200 at
  once, and a COMPLETE after the end of the upload with the answer it
  kept (5.3).
- Never resend in another session: a session cannot be resumed. A
  failed session is a new handshake, a new signature and, for an upload,
  the content from the start.

### 4.8 Errors in the clear and inner statuses

Two kinds of answers, never mixed up:

- **In the clear**: any answer that is not `200` with the channel media
  type. lukd sends such answers (with `{"error": "<text>"}` and
  `Connection: close`) only when a request reached no session or did not
  open; a proxy may send anything. Nothing authenticates them: a client
  treats them as transport errors, hints, never as the result of an
  operation.
- **Inner**: the status in the head of a sealed answer, authenticated by
  the channel. Every refusal of an operation (401, 403, 422, ...)
  travels inside a `200`.

The answers lukd sends in the clear:

| status | error | when |
|---|---|---|
| 400 | `empty channel request`, `unknown channel request` | an empty body, an unknown first byte |
| 400 | `bad handshake` | handshake body over 64 bytes or not a message 1 |
| 400 | `bad channel request` | a clear header that does not parse (unknown kind, frame bits set, an OP number other than 0) |
| 400 | `bad channel message` | a frame of the message does not open, or the stream is truncated |
| 404 | `no endpoint <path>`, `no channel` | handshake on a path without an endpoint; lukd without identity key |
| 404 | `unknown session` | no session of that id on that Host, path and listener (expired, evicted, lost in a restart, another lukd) |
| 404 | `no upload in the session` | PART, COMPLETE or ABORT without an upload |
| 408 | (as above) | the body did not arrive in time |
| 409 | `the session has had its operation` | a second OP |
| 409 | `repeated nonce` | a base nonce taken before |
| 409 | `the session has no operation` | a KEEPALIVE before the OP |
| 413 | `operation over 1048576 bytes` | an OP plaintext over 1 MiB |
| 421 | `no listener for host <host>` | a Host no listener serves |

`luk` reads only one of them as a statement of lukd: 404 with exactly the
error `unknown session`, to a PART or a COMPLETE, means lukd lost the
session (5.3). Any other answer in the clear, a 404 of a proxy among
them, is a transfer error. A 413 in the clear to a PART is a proxy
limit: the same part would get it again.

## 5. Operations

### 5.1 Signed OP

The OP of an upload, a link request and the endpoint listing is signed
with SSHSIG (section 3) and carries these headers:

```
Luk-Meta:       <base64url of the meta JSON, no padding>   (not for the listing)
Luk-Timestamp:  <RFC 3339 in UTC, to the second: 2026-10-06T12:00:00Z>
Luk-Nonce:      <base64url of 16 random bytes, no padding: 22 characters>
Luk-Signature:  <base64 of the SSHSIG blob, one line>
```

- `Luk-Meta` is signed as sent (the base64url string), so there is no
  JSON canonicalization; it is at most 16384 characters.
- The timestamp must be within the clock skew of lukd (default 1m) of
  its clock, and not before its start; `luk` sends the current UTC time
  without fractional seconds. A refusal names no allowed skew: 401
  `timestamp outside the allowed window`.
- The nonce must be new: lukd keeps every nonce it accepted for twice the
  skew (also across restarts of the process). The nonce cache is shared
  by all signed requests (uploads, links, listings, downloads), so a
  client MUST draw a fresh random nonce for every signature.
- `host` and `path` in every canonical text are those of the prologue
  (4.2). `h` is written in base64url without padding (43 characters).
- Order of checks at the OP, each a sealed answer: the signature headers
  present and the meta valid (401), the timestamp (401), the signature
  (401), the identity (401), the nonce (401 `replayed nonce`), the
  `allow` of the endpoint (403), then what each operation adds.

### 5.2 Upload

OP: method `PUT`, target the endpoint path, headers of 5.1.

Canonical text, namespace `luk-upload@v2`:

```
luk-upload@v2
PUT
<host>
<path>
<Luk-Timestamp>
<Luk-Nonce>
<Luk-Meta>
<h>
```

#### Meta

A JSON object. Fields omitted when empty or false, except `source` and
`portal`, which are always sent (`luk` writes them in this order):

| field | type | meaning |
|---|---|---|
| `file` | string | the file name, a name for the content; no `/`, no control character (C0, DEL, C1), at most 255 bytes; empty for a stream |
| `source` | string | `file` (a regular file), `pipe` (a file that is not regular), `stdin`, `terminal` (a prompted secret) |
| `type` | string | media type for downloads (a valid media type, no control character, at most 255 bytes) |
| `size` | integer | the size in bytes, not negative |
| `sha256` | string | 64 lowercase hex characters |
| `tags` | array of strings | each `[a-z0-9._-]+`, lowercase, unique, sorted (byte order) |
| `ttl` | string | a positive duration (Go form with `d` for whole days: `90m`, `12h`, `7d`) or `max` |
| `once` | bool | removed after the first download |
| `portal` | string | `direct`, `reveal` or `download`; required |
| `pretty_url` | bool | a proquint name |
| `no_owner` | bool | no "Sent by" on the landing page |
| `mutable` | bool | the content may be replaced through the link |
| `access` | string | `private` or `any`; absent for a public upload; only with `portal: direct` |
| `backup` | object | `{"hostname", "path", "mtime"}` (`path` and `mtime` optional; a stream has no `path`); `hostname` one path element, no control character, not starting with `.`, at most 255 bytes |
| `dry_run` | bool | check everything up to the content, store nothing |
| `permanent` | string | a permanent name (relative, clean, at most 1024 bytes, no element `current` or `current.*`); excludes `once`, a portal other than `direct`, `access`, `mutable`, `pretty_url` |

- `file` and `terminal` MUST carry `size` and `sha256`; `pipe` and
  `stdin` carry both or neither (both when the client knows them from an
  earlier answer).
- lukd does not normalize: a meta with unsorted or uppercase tags is 401
  `bad meta`. Normalize before encoding (`luk`: lowercase, trim,
  deduplicate, sort).
- An invalid meta, an unknown field or data after the object is 401
  `bad meta: ...`.

#### Answer to the OP

| status | body | meaning |
|---|---|---|
| 200 | parts offer | send the content in parts (below) |
| 200 | dry run answer | only for `dry_run: true`: every check passed, nothing stored, the session ends |
| 201 | created | stored without the content (`"deduplicated": true`), `respond: url` |
| 202 | receipt | stored without the content (`"deduplicated": true`), `respond: accept` |
| 400 | error | an inner request without a method, an OP with a body |
| 401 | error | signature, timestamp, nonce, identity, meta |
| 403 | error | not in `allow`; a `backup.hostname` or a permanent name not granted |
| 404 | error | the target is not the session path |
| 405 | error | another method (`Allow: PUT`) |
| 409 | error | a permanent name refused by its entry |
| 413 | error | `size` over the limit of the endpoint; `upload exceeds the quota of this endpoint` |
| 422 | error | no pipeline, a capability not granted (`pretty_url`, `mutable`, `access`, `permanent`, `secret`), over the reveal limit (64 KiB), a name that cannot be stored |
| 429 | error | `too many open uploads` (`Retry-After: 1`), `quota exceeded` (`Retry-After`), too many names of that content |
| 500 | error | `internal error` |
| 507 | error | `not enough space` |

A client tells the two 200 answers by its own `dry_run`. A 201 or 202 to
the OP is a deduplicated upload: lukd held the content for the signer and
took it by the signed size and sha256 (scoped to the signer: never the
content of another sender). The client checks that the answered `size`
and `sha256` are the signed ones.

Dry run answer: `{"id", "identity": {"name", "type", "ca", "key_id",
"principals", "serial", "fingerprint"}, "endpoint", "client": <the meta>,
"server": {"received"}, "pipelines": [...], "schedule": [{"pipeline",
"group", "order"}], "claimed": {"pipeline", "skipped"}, "respond":
{"mode", "url"}}`.

#### Parts offer

```json
{"parts": {"size": 8388608, "parallel": 4, "idle": 120, "rate": 65536}}
```

- `size`: the size of every part but the last; a multiple of 65536 from
  65536 to 2 GiB - 64 KiB.
- `parallel`: the most parts in flight at once; 1 to 64.
- `idle`: seconds an upload stays open without activity; at least 1.
- `rate`: the least rate in bytes per second each part must arrive at; 0
  for none.

A client MUST refuse an offer outside these bounds (`luk`: `bad parts
offer`, after an ABORT). A client that cannot send the content (it does
not have it any more) sends an ABORT.

#### Parts

PART (kind 2, number n) carries the bytes of the content from
`n x size` on.

- A file of signed size S has `ceil(S / size)` parts (none when S is 0);
  every part is exactly `size` bytes but the last, which is the rest
  (exactly `size` when S is a multiple of it).
- A stream (no signed size) ends with its first part shorter than `size`,
  possibly empty: a stream whose length is a multiple of `size` MUST end
  with an empty part. lukd learns the end from it.
- Parts may go in any order and in parallel, at most `parallel` at once
  as offered. lukd refuses a part `2 x parallel` or more ahead of the
  contiguous prefix of verified parts with 429 `part <n> ahead of the
  window` and `Retry-After: 1`: wait and send it again, under a new
  attempt; it is no failure.
- Each part must arrive at `rate` or faster (its time limit is `size /
  rate`, 128s for 8 MiB at 64 KiB/s) and never stall for `idle`: else 408.
  A client that limits its own bandwidth sends at most `bandwidth / rate`
  parts at once (`luk` fails before any part when its limit is below
  `rate`).
- One writer per part: a newer attempt replaces an older one still being
  written (the older one ends 409); an older attempt that arrives while a
  newer one is written is 409 `older attempt` and changes nothing: send
  it again under a newer attempt, no failure.

Answers to a PART:

| status | meaning | client |
|---|---|---|
| 200 `{}` | the part is verified (also: it was verified before) | done |
| 400 | beyond the parts of the upload, a wrong length, a short part of a stream that is not the last, a frame that did not open after the first | fail the upload |
| 408 | the part stalled for `idle` or missed `size / rate` | retry; send fewer parts at once |
| 409 | `older attempt`; a newer attempt took over; the upload is finalizing or committed (checked from the clear nonce, before the body) | `older attempt`: retry, no failure; else stop |
| 410 | `upload aborted`, `upload expired` (from the clear nonce); once the body is being read, any state but open: `upload ended` (while bytes are written), `upload <state>` (`finalizing`, `committed`, `aborted`, `expired`; when the message opened) | stop |
| 413, 422 | a stream over the limit of the endpoint (422: over the reveal limit); `upload exceeds the quota of this endpoint` | fail |
| 429 | `part <n> ahead of the window` (`Retry-After`) | wait, retry, no failure |
| 429 | `quota exceeded` (a stream over its quota): the upload ended | fail |
| 500, 507 | `internal error`, `not enough space` | fail |

#### COMPLETE

COMPLETE (kind 3, number: the round, 0 for the first, empty plaintext)
asks lukd to commit the upload.

- 409 `{"missing": [3, 7]}`: parts still missing, at most 1024 numbers in
  ascending order; for a stream whose final part has not come, the list
  ends with the number after the highest part lukd has. Send the listed
  parts and COMPLETE again with the next round number. A client checks
  that every number is a part of the upload (`luk`: within the file, or
  a part of the stream it sent). A stream client that no longer holds a
  listed part fails.
- Else the upload is committed: the size and sha256 of a file MUST equal
  the signed meta (422 `content differs from the signed <size> bytes
  sha256 <hex>`, the size only for a secret); those of a stream are
  computed. The answer is that of the upload: 201 created or 202 receipt
  (202 for a link replace), or a refusal (422, 507, 500) that ends the
  upload as an ABORT does.
- 410 `upload aborted` or `upload expired`: the upload ended without a
  commit.
- The answer of the COMPLETE that ended the upload is kept: a COMPLETE
  sent again (a new attempt, or a new round) gets the same answer while
  the session lives. A COMPLETE that arrives while another one finalizes
  waits for it and gets its answer.

Created (201, `respond: url`): `{"id", "url", "expires", "ttl",
"ttl_note", "ttl_min", "ttl_max", "size", "sha256", "deduplicated",
"permanent", "version_url"}`; `url` always, `expires` always (RFC 3339 in
UTC, `""` when the upload never expires), the others omitted when empty.
Receipt (202, `respond: accept`): `{"id", "size", "sha256", "ttl",
"ttl_note", "ttl_min", "ttl_max", "deduplicated"}`. `ttl` is the lifetime
given (`7d`, `1h30m`; omitted: never expires), `ttl_note` what became of
the client ttl (`capped`, `raised`, `ignored`; omitted: as asked),
`ttl_min` and `ttl_max` the bounds of the storage. A client compares the
answered `sha256` with the one it sent or computed (`luk`: a mismatch is
an error). The `url` of a private upload, or of a storage served only to
signed requests, has the scheme `luk` (section 6).

#### ABORT

ABORT (kind 4, number 0, empty plaintext; a resend counts the attempt
up, `luk` as for every message) ends an open upload: 200 `{}`
(also for an upload that already ended without a commit), 409 `upload
committed` after a commit. A client sends it when it gives up (`luk`:
on a failure and on an interrupt, waiting at most 5s for the answer). A
COMPLETE whose answer never came followed by an ABORT answered 409
`upload committed` means the upload was stored and its answer lost.

#### KEEPALIVE

KEEPALIVE (kind 6, number: its own sequence from 0, empty plaintext)
counts as activity of the upload: 200 `{}`. A client that waits on a slow
source sends one at least every `idle` / 3 (`luk` sends them only while
it waits on its source; parts and their answers are activity
otherwise).

#### States and losses

An upload is open, then finalizing (a COMPLETE), then committed, aborted
(an ABORT, a refusal, the session dropped) or expired (no activity for
`idle`).

- A session lost before the COMPLETE (404 `unknown session` in the clear
  to a PART): nothing was stored; a file can be sent again from the start
  in a new session, a stream cannot (`luk`: `server lost the upload; the
  stream cannot be sent again`).
- A session lost at the COMPLETE (404 `unknown session` to it), or a
  COMPLETE without an answer after all its attempts: the result is
  unknown. lukd may have committed the upload. A client MUST NOT send it
  again by itself: there is no idempotency key.

#### Client time limits (guidance, from `luk`)

| what | luk |
|---|---|
| handshake | 10s |
| answer to the OP | 60s |
| signature of the OP | notice after 1s; not sent after 55s |
| an attempt of a part without progress (sending or waiting) | 30s, then cut |
| failed attempts of a part | 5, with 1s, 2s, 4s, 8s (+-20%) between them; then the upload fails (ABORT) |
| each attempt of a COMPLETE | 2m; 5 attempts, then the result is unknown |
| rounds of missing parts | 3 |
| ABORT | 5s |
| KEEPALIVE | every `idle` / 3 while waiting on the source |

A 408 to a part also makes `luk` send one part fewer at once (down to
one). A 429 of the window waits `Retry-After` (1s without one) and counts
no attempt.

### 5.3 Link requests

A link request manages an upload the signer owns through its URL. It is
the OP of a session on the endpoint path, like an upload, told apart by
the headers `Luk-Link` and `Luk-Link-Action`.

| action | method | `Luk-Link` | meta |
|---|---|---|---|
| `remove` | `DELETE` | the link URL | `{}` |
| `ttl` | `PATCH` | the link URL | `{"ttl": "3d"}` (or `max`) |
| `replace` | `PUT` | the link URL | the upload meta of the new content |
| `list` | `GET` | empty | `{"limit": 100, "after": "<cursor>", "any": true}`, each optional |

Headers: `Luk-Link`, `Luk-Link-Action` and those of 5.1 (`Luk-Meta` is
required, `{}` being `e30`). Canonical text, namespace `luk-link@v2`:

```
luk-link@v2
<METHOD>
<host>
<path>
<Luk-Link>
<Luk-Link-Action>
<Luk-Timestamp>
<Luk-Nonce>
<Luk-Meta>
<h>
```

- `Luk-Link` is signed as sent: the full URL as the upload answer or the
  list gave it (`https://...`, `luk://...`, with its fragment); its line
  is empty for `list`.
- The meta of `remove`, `ttl` and `list` is a JSON object of `ttl`,
  required for `ttl` and refused for the others (422), and of the list
  fields `limit`, `after` and `any`, refused for `remove` and `ttl` (422);
  any other field makes the meta invalid (401).
- The meta of `replace` describes the new content only: `file`, `source`,
  `type`, `size`, `sha256` and `portal: "direct"`; any other field set is
  422. The link keeps its tags, ttl, access and the rest.
- Header errors: an unknown action, a `remove`, `ttl` or `replace`
  without `Luk-Link`, `Luk-Link` without an action, a `list` with a
  `Luk-Link` are 400; a method that does not fit the action is 405 with
  `Allow`.
- After the checks of 5.1: an action not granted to the signer is 403;
  an URL without a host 422 `bad link URL`; a file that is not there,
  expired, claimed, of another endpoint or of another owner is the same
  404 `link not found`.

Answers:

- `remove`: 200 `{"url", "removed": true}`.
- `ttl`: 200 `{"url", "expires", "ttl", "ttl_note", "ttl_min",
  "ttl_max"}` (`expires` and `ttl` omitted when there is no expiry); 422
  when the storage takes no client ttl.
- `replace`: 409 `link is not mutable` for an upload sent without
  `mutable`; else the OP gets the parts offer and the content goes in
  parts exactly as an upload (5.2; never deduplicated, no dry run); the
  COMPLETE answers 202 `{"url", "id", "size", "sha256"}`.
- `list`: 200 `{"links": [{"url", "file", "size", "received", "expires",
  "once", "mutable", "portal", "access", "updated", "permanent",
  "permanent_url", "shared", "sender", "cursor"}], "next"}`, one page of the links
  of the signer on the endpoint; `links` is `[]` for none.
  - Order: newest first by acceptance order, then by upload id
    (descending), then by the key of the stored name (the first 16 bytes
    of the sha256 of `<storage>/<name>`, lowercase hex, ascending); the
    same order for every page, and no two entries share a place in it. A
    negative accepted seq counts as 0.
  - `limit` is the most entries of the page: absent, 0 or above 1000
    means 1000 (the cap of a page); negative is 422 `bad limit <n>`.
  - `cursor` of an entry is opaque: base64url without padding of
    `<accepted ns>.<accepted seq>.<key>.<upload id in lowercase hex>`
    (an empty id included); it carries no secret and not the URL.
    `after` (a cursor) starts the page strictly after that place in the
    order, also when its entry is gone; a malformed cursor is 400 `bad
    cursor "<cursor>"`. `next` is the cursor of the last entry when more
    follow, absent on the last page. A client walks the list with one
    request (and one session) per page, `after` set to the `next` of the
    page before, and stops at a page without `next`; a `next` other than
    the cursor of the last entry, or one it already followed, means a
    server that never ends the list.
  - `any: true` adds, in the same order, the files of access `any` of
    other identities the signer may download, marked `"shared": true` and carrying `"sender"` (the identity that
    sent it, as lukd logs it; absent on the signer's own links),
    when the endpoint's `private.list` admits the signer; without `any`
    `private.list` is not consulted and only the signer's own links come.

### 5.4 Endpoint listing

The listing tells a client which endpoints of a listener it may use and
what each takes. Handshake and OP go to `/.well-known/luk/endpoints` on
the scheme and host of the endpoint URL.

OP: method `GET`, target `/.well-known/luk/endpoints`, the headers of
5.1 without `Luk-Meta`. Canonical text, namespace `luk-list@v2`:

```
luk-list@v2
GET
<host>
/.well-known/luk/endpoints
<Luk-Timestamp>
<Luk-Nonce>
<h>
```

Answers: 401 for any signature failure (missing headers included), 405
with `Allow: GET` for another method, else 200:

```json
{"endpoints": [
  {"name": "drop", "path": "/drop", "url": "https://lukd.example:8443/drop",
   "respond": "url", "secret": true, "pretty": true, "permanent": false,
   "private": {"owner": true, "any": false},
   "link": {"remove": true, "ttl": true, "replace": false, "list": true},
   "ttl": {"user": true, "min": "1h", "max": "7d", "default": "7d"},
   "secret_ttl": {"user": true, "max": "1d", "default": "1d"},
   "quota": {"mode": "enforce", "rate": "10G/1d", "burst": 53687091200, "tokens": 13421772800},
   "backup_hostname": "principal"}
]}
```

- Only the endpoints whose `allow` admits the signer, sorted by name; the
  booleans are the capabilities as they apply to the signer. `url`
  carries no pin: the pin of the listing session is the pin of every
  endpoint of that origin.
- `ttl` only with `respond: url`; `secret_ttl` only when it differs and
  `secret` is true; `quota` only when a quota applies to the signer;
  `backup_hostname` (`any`, `principal`, `none`) only when the endpoint
  restricts it.

## 6. Downloads

Downloads are plain HTTP(S) requests, outside the channel: a signed
`GET` or `HEAD` to an expose with `auth.ssh` (private files, and the
storages served only to signed requests), and unsigned requests to public
exposes and portal pages. The server is authenticated by TLS (section
2).

### 6.1 Signed GET (`luk-get@v1`)

URL: `luk://host[:port]/path` (always HTTPS) or `https://...`, with an
optional pin fragment. The request goes to the HTTPS URL without the
fragment:

```
GET /<expose path><name>
Host:           <host>
Luk-Timestamp:  <RFC 3339 in UTC>
Luk-Nonce:      <base64url of 16 random bytes>
Luk-Signature:  <base64 of the SSHSIG blob>
```

Canonical text, namespace `luk-get@v1` (no `h`, no meta):

```
luk-get@v1
<METHOD>
<Host header>
<target>
<Luk-Timestamp>
<Luk-Nonce>
```

- `<METHOD>` is `GET` or `HEAD` as sent. `HEAD` never claims a `once`
  file.
- `<Host header>` is the value of the `Host` header exactly as sent
  (not lowercased).
- `<target>` is the path exactly as on the request line, escaped
  (`/a%20b/x7Kq`), followed, when the request has a query, by `?` and the
  raw query as sent (`/v/2026/?recursive=1`). lukd rebuilds the path with
  Go's `URL.EscapedPath`, which returns the path as sent when it is a
  valid escaping of it; escape each path element as `url.PathEscape`
  does and the two always agree.
- The checks of 5.1 apply (clock skew, server start, the shared nonce
  cache, the `Host` served by the listener).

Answers on an expose with `auth.ssh`:

| answer | when |
|---|---|
| 404 | no signature headers at all (an expose that also has `auth.basic` judges such a request by its password instead: 401 with a basic challenge) |
| 401 (plain text with the reason) | any signature header missing, malformed, out of the skew, replayed, not verifying, an unknown key |
| 404 | a valid identity that may not have the file, or a file missing, expired, claimed, of the other kind (public or private); the same answer in every case |
| 405 `Allow: GET, HEAD` | another method |
| 200 / 206 | the content |

Headers of a download: `Content-Disposition: attachment; filename="..."`
(and `filename*=UTF-8''...` for a name that is not plain ASCII),
`Content-Type`, `X-Content-Type-Options: nosniff`,
`Content-Security-Policy: sandbox`, `ETag: "<sha256 hex>"` (when the
sha256 is known), `Luk-Expires` (RFC 3339 in UTC; absent without expiry)
and `Luk-Once: true` (absent when not once). `Range`, `If-Range` and
`If-None-Match` work for files that are not `once`.

- A client compares the sha256 of the content it read with the `ETag`
  (`luk` does). It protects against corruption, not against the server.
- A `once` file is claimed by the first `GET` that reaches it: the answer
  is `200` with `Cache-Control: no-store` and the whole content, `Range`
  is ignored, a second request gets 404. A broken transfer of a `once`
  file cannot be resumed.
- The action URLs of portal uploads (`<name>/reveal`, `/download`,
  `/get`) do not exist for signed requests (404): a signed `GET` of the
  file URL answers the content.

### 6.2 Signed directory listing

A signed `GET` (or `HEAD`) of a directory URL (ending with `/`) of a
storage served to signed requests answers its listing as JSON
(`Content-Type: application/json`, `Cache-Control: no-store`):

```json
[{"name":"2026/","dir":true},{"name":"db.sql.gz","size":1048576,"received":"2026-10-03T10:00:00Z","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]
```

- One level by default: the directories (`name` ending with `/`, `"dir":
  true`), then the files (`size`, `received` in UTC, `sha256`).
- The query `recursive=1` (signed, as part of the target) answers every
  file below, named relative to the directory, without directory
  entries. Any other query is 400.
- 404: a directory with nothing listed, an identity not in the `allow`
  of the expose, a storage with sharded names; the expose root answers
  `[]` when empty. `once`, portal and private files are never listed.
- A client building a local tree from a listing MUST check every name
  itself (`luk`: relative, valid UTF-8, no empty, `.` or `..` element, no
  control or formatting characters) and escape each element to request
  the file.

### 6.3 Unsigned downloads and portals

A public expose serves `GET` and `HEAD` of `<url><name>` without a
signature (with HTTP basic auth when it has `auth.basic`). An upload with
a portal (`reveal`, `download`) answers its URL with an HTML landing
page, never the content, so link previews do not consume a `once`
upload. The content is reached only through:

| URL | methods | answer |
|---|---|---|
| `<url><name>/reveal` (reveal portal) | `POST` | the raw content as `text/plain; charset=utf-8` when `Accept` ranks `text/plain` above `text/html`, else the HTML reveal page (`Vary: Accept`) |
| `<url><name>/download` (download portal) | `POST` | the content with the download headers |
| `<url><name>/get` (both portals) | `GET`, `HEAD`, `POST` | the raw content: the bytes of a reveal upload as `text/plain; charset=utf-8` (at most 64 KiB, else 413), a download upload with the download headers |

- `GET` and `HEAD` of `/reveal` and `/download` are 405 with `Allow:
  POST`. An action of the other portal, or any action on a `direct`
  upload, is 404.
- A `POST` announcing a body over 1024 bytes or without a length is 413;
  a `POST` must pass the cross-origin check (`Sec-Fetch-Site` or `Origin`
  of the same origin; a client sending neither passes), else 403.
- The first `GET` or `POST` of an action counts as the download of a
  `once` upload; `HEAD` never does.
- `/get` is the URL for scripts and terminals: appending it is a
  deliberate request of whoever holds the link. The convention protects
  against prefetchers, not against anyone holding the URL.

## 7. Threat model

### What each signature covers

| namespace | covers | bound to |
|---|---|---|
| `luk-upload@v2` | method `PUT`, Host, path, timestamp, nonce, the whole meta (file name, size, sha256, tags, options) | the session (`h`) |
| `luk-link@v2` | method, Host, path, the link URL, the action, timestamp, nonce, the meta | the session (`h`) |
| `luk-list@v2` | method `GET`, Host, the listing path, timestamp, nonce | the session (`h`) |
| `luk-get@v1` | method, Host, the request target with its query, timestamp, nonce | nothing beyond the request; TLS carries it |

- The content of an upload is not signed. For a file (and a prompted
  secret) the signed `size` and `sha256` bind it: lukd refuses content
  that differs (422 at the COMPLETE). For a stream nothing signed covers
  the content: its integrity is that of the channel (only the client and
  lukd hold `k1`), so the content is what this client sent in this
  session.
- The PART, COMPLETE, ABORT and KEEPALIVE messages are authenticated by
  the session keys, not by a signature: authorization is decided once, at
  the OP.
- Domain separation: the namespace is inside the SSHSIG signed data and
  is the first line of every text; the `v2` texts end with `h` and the
  `v1` text has no such line. No signature verifies as another kind.

### Binding to the channel

The signature of the OP covers `h`, unique to the handshake of one
client ephemeral key and one lukd ephemeral key. It is sent encrypted
under `k1` of that session. So:

- a signature is good for one session only: it never verifies in another
  session, on another lukd, or on another Host or path (also in the
  prologue);
- a lukd the client pinned but that is malicious, or a party that holds
  a lukd key, learns the signature and cannot use it anywhere else: its
  sessions with other lukd instances have other hashes;
- the client knows the session is with the holder of the pinned key: NX
  proves it through `es` in message 2, and only the pin check turns that
  into trust.

### Replay

- A replayed handshake message 1 opens a session nobody can continue (the
  client ephemeral key is unknown to the replayer); lukd's fresh
  ephemeral key gives it another `h`, so old transport messages never
  open in it.
- A replayed transport message of a live session is 409 `repeated nonce`
  (or `the session has had its operation`) and changes nothing.
- A replayed signed text in another session fails on `h`. The timestamp
  window and the nonce cache are a second line, and the only one for
  `luk-get@v1`: a captured signed download is refused after its first
  use and after the skew.
- Limit (lukd side): the nonce cache lives in a tmpfs; after a host
  reboot a download signed with a timestamp ahead of the server clock
  could be replayed until that timestamp. A channel signature cannot:
  the reboot dropped its session.

### What an on-path party or proxy can do

A party between client and lukd (a TLS-terminating proxy included):

- cannot read the meta, the identity of the signer, the content or any
  answer (the URL an upload gets is inside the channel);
- cannot change a message or an answer without the change failing to
  open, nor move a frame into another message, attempt, position or
  answer (the nonce and the AD bind each);
- can see the Host, the path, the channel id, the nonces in the clear
  (message kinds, part numbers, attempts, rounds), the sizes of the
  messages and their timing;
- can drop, delay, duplicate and reorder requests and answers, and send
  answers in the clear (4.8). A client MUST treat those as transport
  errors. `luk` acts on one of them: a forged 404 `unknown session` to a
  PART makes it send a file again in a new session; the old upload cannot
  commit without a COMPLETE of the client, so no second copy is stored.
  To a COMPLETE the same answer only makes the result unknown;
- can rewrite the Host or the path: the handshake then fails.

### What a malicious server can do

lukd holding the pinned key is trusted with the content (it stores it).
A client still bounds what an answer can make it do:

- read every answer whole only within limits (`luk`: 64 KiB for clear
  answers and the handshake, 64 MiB for inner answers, 64 MiB for a
  listing) and refuse heads over 65536 bytes;
- refuse an offer outside its bounds, missing parts outside the upload,
  a 201 without `url`;
- compare the answered `sha256` with the content sent, and the `ETag` of
  a download with the content read;
- check every name of a directory listing before creating it locally;
- never show text of an answer to a terminal without escaping control
  characters (`luk` escapes them).

A lukd learns: the identity of the signer, the meta and the content, the
client address. It cannot sign as the client anywhere else.

### Denial of service a client should expect

- Sessions without an OP are evicted oldest first when lukd has many
  (a flood of handshakes): retry once with a new handshake on 404
  `unknown session` to the OP.
- Uploads open at once are limited per identity and in all: 429 `too
  many open uploads` with `Retry-After`.
- Quotas: 429 `quota exceeded` with `Retry-After`, 413 when an upload can
  never fit.
- Per-part time limits (`idle`, `rate`): a slow client sends fewer parts
  at once.
- An idle upload expires after `idle`; send KEEPALIVE while waiting.
- lukd bounds what a client can make it hold: the handshake body (64
  bytes), the OP (1 MiB), heads (64 KiB), the window of parts ahead
  (`2 x parallel`), the missing list (1024 numbers).

## 8. Test vectors

One complete exchange with fixed inputs: the handshake, the upload OP of
an 11-byte file, its first part and lukd's answer to the OP (the parts
offer). The test `internal/channel/vectors_test.go` recomputes every
value below from the code and fails when this document differs; it also
derives the handshake and the transport keys a second time by the Noise
specification, apart from the library the channel uses.

Inputs:

- `client.seed`: the 32-byte Ed25519 seed of the signing key (RFC 8032
  private key).
- `server.static.private`: the X25519 private key of lukd (its identity
  key); `client.ephemeral.private` and `server.ephemeral.private`: the
  X25519 private keys of the two ephemeral keys (what each side reads
  from its random source for `e`).
- `host`, `path`, `timestamp`, `nonce.bytes` (the 16 random bytes of
  `Luk-Nonce`) and `part.data` (the content, `hello, luk\n`).

The upload meta is
`{"file":"hello.txt","source":"file","size":11,"sha256":"e41eba6132a7499b1ca7c9e0b9bd9d41b93758bd6fba531c9b0f6b319c1edbef","portal":"direct"}`.
The canonical text of the signature (`signed.text` below), line by line:

```text
luk-upload@v2
PUT
lukd.example:8443
/drop
2026-10-06T12:00:00Z
gIGCg4SFhoeIiYqLjI2Ojw
eyJmaWxlIjoiaGVsbG8udHh0Iiwic291cmNlIjoiZmlsZSIsInNpemUiOjExLCJzaGEyNTYiOiJlNDFlYmE2MTMyYTc0OTliMWNhN2M5ZTBiOWJkOWQ0MWI5Mzc1OGJkNmZiYTUzMWM5YjBmNmIzMTljMWVkYmVmIiwicG9ydGFsIjoiZGlyZWN0In0
YKNn1jGpvG0c_T_1mEyOSD5atVbd2xMW4FxnY4wZXoQ
```

Values: one per name, binary values in hex; a long value continues on
the following indented lines without separators.

- `client.public`, `client.fingerprint`: the signing key in
  authorized_keys form and its SHA-256 fingerprint.
- `server.pin.key`, `server.pin.words`: the two pin forms of the lukd key.
- `transport.k1`, `transport.k2`: the keys of `Split()` (4.3).
- `meta` is the `Luk-Meta` header, `nonce` the `Luk-Nonce` header,
  `signature` the `Luk-Signature` header (base64 of the SSHSIG blob).
- `op.plaintext`: the inner OP (4.4): the length and the JSON request
  head `{"method":"PUT","target":"/drop","header":{...}}` with the four
  headers (Go writes the header names sorted); the body is empty.
- `op.nonce`, `op.header`, `op.frame0`: the OP (kind 1, number 0,
  attempt 0), its 25-byte clear header and its only frame (final: the
  frame nonce is `op.nonce` with the last bit set). The transport request
  body is `op.header || op.frame0`.
- `part.*`: the same for PART 0, attempt 0, carrying `part.data`.
- `response.plaintext`: lukd's inner answer to the OP: the head
  `{"status":200,"header":{"Content-Type":["application/json"]}}` and the
  offer as lukd writes it; `response.header` (counter 1) and
  `response.frame0`: the transport answer body is their concatenation.

```vectors
client.seed               000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
server.static.private     202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
client.ephemeral.private  404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
server.ephemeral.private  606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
host                      lukd.example:8443
path                      /drop
timestamp                 2026-10-06T12:00:00Z
nonce.bytes               808182838485868788898a8b8c8d8e8f
part.data                 68656c6c6f2c206c756b0a
client.public             ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4
client.fingerprint        SHA256:lbmsoA0yIEcEiVDRnMWuzm+nV+3ZEEpVIURqFoeSspg
server.static.public      358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
server.pin.key            NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ
server.pin.words          pabom-nobib-basov-ribil-fitav-vozah
prologue                  6c756b2d6368616e6e656c40310a6c756b642e6578616d706c653a383434330a
                          2f64726f70
handshake.request         0179a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a5
                          1a
handshake.response        01675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea5
                          2f03ad26b80f109da162841afa37bf6c5f321dabef1038c10a6df9d17bf3eae5
                          4016b36741a5c90ec0467e8115b81e25055c5902f771618a9caf4e1d7279118f
                          51
h                         60a367d631a9bc6d1cfd3ff5984c8e483e5ab556dddb1316e05c67638c195e84
h.base64url               YKNn1jGpvG0c_T_1mEyOSD5atVbd2xMW4FxnY4wZXoQ
channel.id                31331d98e855dd132ff9025e7a555324
transport.k1              583d857420d6a0e7c6912b589c3c54d1fd02186aaccfa2e64fbe557911a31dfc
transport.k2              0f39ba1b476547394cb25db373c9ac3a6a4477e551a1a5a05fd76089e31d373c
meta.json                 {"file":"hello.txt","source":"file","size":11,"sha256":"e41eba6132a7499b1ca7c9e0b9bd9d41b93758bd6fba531c9b0f6b319c1edbef","portal":"direct"}
meta                      eyJmaWxlIjoiaGVsbG8udHh0Iiwic291cmNlIjoiZmlsZSIsInNpemUiOjExLCJz
                          aGEyNTYiOiJlNDFlYmE2MTMyYTc0OTliMWNhN2M5ZTBiOWJkOWQ0MWI5Mzc1OGJk
                          NmZiYTUzMWM5YjBmNmIzMTljMWVkYmVmIiwicG9ydGFsIjoiZGlyZWN0In0
nonce                     gIGCg4SFhoeIiYqLjI2Ojw
signed.text               6c756b2d75706c6f61644076320a5055540a6c756b642e6578616d706c653a38
                          3434330a2f64726f700a323032362d31302d30365431323a30303a30305a0a67
                          49474367345346686f65496959714c6a49324f6a770a65794a6d6157786c496a
                          6f696147567362473875644868304969776963323931636d4e6c496a6f695a6d
                          6c735a534973496e4e70656d55694f6a45784c434a7a614745794e5459694f69
                          4a6c4e44466c596d45324d544d79595463304f546c694d574e684e324d355a54
                          42694f574a6b4f5751304d5749354d7a63314f474a6b4e6d5a695954557a4d57
                          4d35596a426d4e6d497a4d546c6a4d57566b596d566d49697769634739796447
                          4673496a6f695a476c795a574e30496e300a594b4e6e316a4770764730635f54
                          5f316d45794f534435617456626432784d573446786e5934775a586f51
signature                 U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgA6EHv/POEL4dcN0Y50vA
                          mWfk1jCbpQ1fHdyGZBJVMbgAAAANbHVrLXVwbG9hZEB2MgAAAAAAAAAGc2hhNTEy
                          AAAAUwAAAAtzc2gtZWQyNTUxOQAAAED5/V0MGqSr7LEMihD8prhL1jRvJ+Qc3mcJ
                          kgK43h9Hqq7om4Ba6Oll1aUgQKa2W99fF8XrMXizsj3/4AOmqkAC
op.plaintext              000002507b226d6574686f64223a22505554222c22746172676574223a222f64
                          726f70222c22686561646572223a7b224c756b2d4d657461223a5b2265794a6d
                          6157786c496a6f696147567362473875644868304969776963323931636d4e6c
                          496a6f695a6d6c735a534973496e4e70656d55694f6a45784c434a7a61474579
                          4e5459694f694a6c4e44466c596d45324d544d79595463304f546c694d574e68
                          4e324d355a5442694f574a6b4f5751304d5749354d7a63314f474a6b4e6d5a69
                          5954557a4d574d35596a426d4e6d497a4d546c6a4d57566b596d566d49697769
                          6347397964474673496a6f695a476c795a574e30496e30225d2c224c756b2d4e
                          6f6e6365223a5b226749474367345346686f65496959714c6a49324f6a77225d
                          2c224c756b2d5369676e6174757265223a5b2255314e4955306c484141414141
                          51414141444d414141414c63334e6f4c57566b4d6a55314d546b414141416741
                          364548762f504f454c3464634e3059353076416d57666b316a43627051316648
                          6479475a424a564d6267414141414e624856724c585677624739685a4542324d
                          6741414141414141414147633268684e54457941414141557741414141747a63
                          3267745a5751794e5455784f514141414544352f56304d47715372374c454d69
                          6844387072684c316a52764a2b5163336d634a6b674b34336839487171376f6d
                          344261364f6c6c31615567514b613257393966463858724d58697a736a332f34
                          414f6d716b4143225d2c224c756b2d54696d657374616d70223a5b2232303236
                          2d31302d30365431323a30303a30305a225d7d7d
op.nonce                  1000000000000000
op.header                 0231331d98e855dd132ff9025e7a5553241000000000000000
op.frame0                 cfa2c15b696e3a00e1d894226952b29318a227a85790a048863cce54b2bfd4a7
                          e91cc8653c162190cb877c6ee2e3ebb3d0ba0aa6c94750191289e95fe7779787
                          6c7b714b582d4d620b20404f2d961b066064a84c11fc4f8daea4ffc8f7117ed4
                          5470dfccd6382c967b7ed3ffca65f01b5f11dbe05fd73754571375cfc3e47321
                          ddc940a767bbe1da8c9be3656f5f0eaac6d1911fd6a1ce5c6b8997e0c2b53a83
                          f30527cb8dfeffc5d359d00742f653813f1c09f53e85682f92496939dde4795b
                          f5e5b143dad9d91a1bc8900c2087900550d50f220ecc2d0c7c8387e65868d531
                          6d6e4ec04a48025fed59ce1089f035c30aac46beae4ed4e1dac22422f95011b2
                          46b3d5f931be6233cf8ca85331ac7c925918a8c6580c126c5712573cd8005d1e
                          67363d024cbe95894f8fd30978789982aeb1e85f45ab22db21bbabc3a92ca8f9
                          9d8ffe356ae225e73e8f67b45fca27aea4c0599b652c7333a7a2fc50a9088118
                          6585cb89a4ff531e07ccc69ca76544bc995a991f3ff7f15f44ada7dbc15b9778
                          7cca63fae5e4788a29f614a63ee619b30199af4aa2398db93f791bca58bfbe25
                          0951973d13bff83b9c619ff656bda69380c795ef6399dea010b922f1f4b8a4a3
                          a8d59dd8c21ea873dc8fc9d817ad60710c4f9d9d18af388f6df6ef3ebf6b59a3
                          e7307ed9891bf515fb7950dccaa0b266c30fbfe5637b51fe025399269cba17e7
                          7b2e7d2a1e1ad8e878f983fbf83ed208e471953deca92cbfb692f93448d7f07e
                          6e96a57b6ff256679237d6f32a3de5f60c97df4ac517e3a74d2b0dc1f83145fe
                          7faeef26e85145c61ad03264b557896a28bdd7beca8ab08dd2e1976368ecad15
                          0dfd0b35
part.nonce                2000000000000000
part.header               0231331d98e855dd132ff9025e7a5553242000000000000000
part.frame0               debb088a7e4cbf417a4642b30e27cd5d700d2301714da9f990765f
response.plaintext        0000003d7b22737461747573223a3230302c22686561646572223a7b22436f6e
                          74656e742d54797065223a5b226170706c69636174696f6e2f6a736f6e225d7d
                          7d7b0a2020227061727473223a207b0a202020202273697a65223a2038333838
                          3630382c0a2020202022706172616c6c656c223a20342c0a202020202269646c
                          65223a203132302c0a202020202272617465223a2036353533360a20207d0a7d
                          0a
response.header           020000000000000001
response.frame0           8bdc6918b7e6b0b6e520d36248de6c6d90c11fd2e5544256f13a23f905d39855
                          3c8d23e3a798f212170a643f14b82271883ab4182fb33c0acc8830be9a473f06
                          87f18bcd87233afdb4d72119ec1d1c6db62edf3c02bff9d64fb8a9cd44cd3d6e
                          9a20fd8eec81027e1330909e58ec0410662ebaa5eda569ad09afa316b1cd23c1
                          51f7a8cb9222d6252582a6734cfe172c0dc605933b348d519aa4734b4493e352
                          9660d4e8719360ad1582bbf3cd85aeadce
```
