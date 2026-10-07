# luk - spec

luk is an SSH-authenticated storage server. One file per upload,
authenticated by an SSH key, routed by endpoint and tags into pipelines
that process it and store the results; stored results can be exposed over
HTTP. It replaces two things with one:

- the backup server (`backup.example.net`): hosts push database
  dumps, the dumps are archived, turned into developer dumps and published
  with a catalog;
- the ad-hoc file drop: upload from the CLI,
  get a URL, the file disappears by itself.

Binaries: `luk` (client), `lukd` (server). Language: Go, static binaries
(`CGO_ENABLED=0`).

Stage: phases 1 to 6 are implemented; the Phases section describes
them, and Later lists what is not implemented yet (S3 storage among
it).

## Model

```
luk --channel--> lukd ingest --> queue --> pipeline(s) --> storage --> expose --> GET
     (Noise NX,  (auth, ACL,             (steps: run,     (local)     (optional
      parts)      match, parts)           store)                       HTTP)
```

- **endpoint** - an upload entry point (`/backup`, `/drop`). It is the
  authorization boundary: `allow` lists who may upload to it.
- **tags** - set by the client (`--tag`, repeatable). They select
  pipelines inside an endpoint. They never grant access.
- **pipeline** - a rule (endpoint + tags) and a list of steps. Every
  matching pipeline runs (fan-out).
- **storage** - where results land (`local`; `s3` is not implemented
  yet), with the lifetime of
  the files (TTL, retention). Optionally exposed.
- **expose** - HTTP download of a storage, optional auth, `--once`,
  portal mode; an expose with `auth.ssh` serves the private files of a
  storage to signed requests (see Private files), or, as the `expose` of
  a storage, its public files and a signed listing (see Signed expose).

## Channel

Client authors: the wire contract, with test vectors, is `doc/PROTOCOL.md`.

luk reaches the endpoints of lukd (uploads, link requests, the endpoint
listing) through a channel between the two programs: a Noise handshake
authenticates lukd by its identity key, then every request and every
answer travels encrypted and authenticated from luk to lukd and back.
HTTP, TLS and the proxies in between only carry it. luk does not verify
TLS for an endpoint (no CA, no SPKI pin): `http://` and `https://`
endpoint URLs work the same, and a proxy that ends TLS sees neither the
content nor the answers.

Downloads are not in the channel: `luk get`, signed GETs (`luk-get@v1`),
directory listings and downloads of a signed expose, portals and `once`
stay plain HTTP requests, verified by TLS (the system CAs or the SPKI
pin of the link, see Private files and TLS).

### Carrier

Every channel request is a `POST` of the content type
`application/vnd.luk.channel`; the answer of the channel is `200` with
the same content type.

```
POST /<endpoint>
Content-Type: application/vnd.luk.channel

<body: a handshake or a transport request>
```

- The URL is the endpoint URL (`/drop`) for uploads and link requests,
  and `/.well-known/luk/endpoints` for the endpoint listing. A handshake
  on any other path is 404 (`no endpoint <path>`); a lukd without its
  identity key answers every handshake 404 (`no channel`).
- lukd tells a channel request by its method and content type, before
  the path. A request to an endpoint path or to the endpoint listing
  outside the channel (any other method or content type) is 400
  `protocol mismatch` with `Connection: close`, logged at DEBUG as
  `endpoint request outside the channel`.
- An answer that is not `200` with the channel content type comes from
  outside the channel: a proxy, or lukd refusing a request before any of
  it opened (below). Nothing authenticates it, so luk reports it as a
  transport error (`channel request refused: HTTP <code>: <message>`;
  `not answered by lukd: HTTP <code>` to a handshake), never as the
  result of an operation (exit 3).
- The HTTP status says nothing about the operation: the refusals of lukd
  (401, 403, 422, ...) travel inside the channel, in a `200`. Proxy
  access logs do not show them; the lukd log does.
- luk resolves the host of the URL once per session and sends every
  request of the session to that address (an IP literal as given, else
  the first address of the name), on connections of its own; proxy
  environment variables are not used. A session lives in the memory of
  one lukd and its requests go on separate connections, so all of them
  must reach that lukd.
- A proxy on the way must accept a request body of `parts.size` plus
  about 0.03% (the framing of the channel), keep the `Host` and the path
  (a rewrite of either fails the handshake: luk then reports `the
  handshake failed: was the Host or path changed on the way (a
  proxy)?`), and send each request to the lukd of its session. It needs
  no request buffering, but may buffer. A `413` of a proxy to a part is
  not retried: `the part size (<size>) exceeds what a proxy on the way
  accepts: HTTP 413` (exit 3).

### Handshake

Suite `Noise_NX_25519_ChaChaPoly_SHA256`. luk is the initiator; lukd
sends its static key, the identity key (see Identity key), encrypted in
message 2. Neither message carries application data.

```
Handshake request body:  0x01 || NX message 1 (32 bytes: e)
Handshake response body: 0x01 || NX message 2 (e, ee, s, es; empty payload)
```

The prologue binds the handshake to the URL:

```
"luk-channel@1\n" + host + "\n" + path
```

- `host`: the host of the URL as luk has it, lowercase, with `:port`
  when the URL has one. lukd takes the `Host` of the request, lowercase,
  the host that routed it to its listener (see Listeners).
- `path`: the URL path luk posts to, exactly (on lukd the path of the
  request).

A handshake relayed to another host or path does not finish. A replayed
message 1 gives a handshake nobody can continue: nothing reaches an
endpoint. A handshake body over 64 bytes or not a handshake is 400, in
the clear; the body must arrive within `limits.header.timeout` (408).

After message 2 luk compares the key lukd sent with the pins of the
endpoint (see Pins). In NX this comparison is a step of luk, not a
property of the handshake: it is mandatory and comes before anything
else is sent. A key that matches no pin ends the run with `the lukd key
<words> matches no pin of this endpoint` (exit 3), and an endpoint
without a pin is never contacted: `no pin for this endpoint: run luk
scan URL` (exit 1). Only `luk scan` runs a handshake without a pin, to
show the key it gets. luk gives the handshake 10s.

Both sides derive the channel id from the final handshake hash `h`; lukd
never assigns or sends it:

```
channel id = first 16 bytes of SHA-256("luk channel id" || h)
```

### Messages

```
Transport request body:  0x02 || channel id (16) || nonce (8, big-endian) || frames
Transport response body: 0x02 || counter (8, big-endian) || frames

Request nonce (uint64):
    bits 63..60 kind     1 OP, 2 PART, 3 COMPLETE, 4 ABORT, 6 KEEPALIVE (5 reserved)
    bits 59..28 number   part number (PART), round (COMPLETE), sequence (KEEPALIVE), 0 (OP, ABORT)
    bits 27..16 attempt  0..4095, incremented by the client on every resend
    bits 15..1  frame    frame index within the message
    bit  0      last     1 on the final frame of the message
Response nonce (uint64): counter << 32 | frame << 1 | last
    counter: per session on lukd, starts at 1, +1 per response (never reused)

Frames: plaintext chunks of 65536 bytes; the final frame carries 0..65536
    bytes and has last=1 (data that is an exact multiple of 65536 ends with
    an empty final frame). Each frame = ChaCha20-Poly1305 ciphertext (+16 tag).
    Request frames: key client->server, AD = the 25-byte clear header.
    Response frames: key server->client, AD = 0x02 || channel id ||
    request nonce (8) || counter (8).
    A stream that ends after a frame with last=0 is truncated: error.
```

- The nonce in the clear header is the nonce of the message as a whole:
  its frame and last bits are 0 (anything else is 400). Each frame is
  sealed under that nonce with its own frame index and last bit, so
  every encryption of a session has a nonce of its own, and a frame
  moved into another message, attempt or place does not open.
- A session is found by its channel id, and only on the host, path and
  listener of its handshake: anything else is 404 `unknown session`, in
  the clear. A request of another session fails on its first frame.
- lukd acts on a message only once it opened: an OP, a COMPLETE, an
  ABORT and a KEEPALIVE once the whole message opened, a PART once its
  first frame opened. Nothing is written or cancelled for a message that
  does not open (400 `bad channel message` in the clear); only the checks
  of a PART from its clear nonce answer before it opened (see Uploads in
  parts), and they change nothing.
- Every message of a session is taken once by its nonce without the
  frame bits (kind, number, attempt): a message under a nonce taken
  before is 409 `repeated nonce`, in the clear. luk counts the attempt
  up on every resend, so it never encrypts twice under one nonce.
- An answer carries the request nonce in its associated data: it belongs
  to exactly one request. luk reads an answer whole (at most 64 MiB)
  and trusts it only once its final frame opened.

Inner messages (the plaintext of the frames):

```
OP:             uint32 BE n || JSON {"method","target","header"} (n bytes) || body
Every answer:   uint32 BE n || JSON {"status","header"} (n bytes) || body
PART:           the raw bytes of the part
COMPLETE, ABORT, KEEPALIVE: empty
```

- `header` is a map of lists of strings (HTTP header form); the JSON
  part is at most 65536 bytes, unknown fields and data after it are
  refused.
- The OP is the request the operation would be in HTTP: `method`,
  `target` (the path of the session; another path is 404 inside) and
  `header` with the signature headers of an upload, a link request or
  the endpoint listing (below, Links, Endpoint listing). The inner
  request has the host of the session. The OP is at most 1 MiB (413 in
  the clear) and has no body: the content of an upload goes in parts
  (an upload OP with a body is 400 `an upload inside the channel sends
  its content in parts`).
- An answer is the status, the headers (`Retry-After`, `Allow`) and the
  JSON body described for each operation.

### One operation per session

- A session carries one OP (kind 1, number 0; another number is 400
  `bad channel request` in the clear, the attempt is free), signed.
  Inside the channel only `luk-upload@v2`, `luk-link@v2` and
  `luk-list@v2` verify (any other namespace is 401); their signed texts
  end with `h`, which binds the signature to this one session.
- A second OP is 409 `the session has had its operation`, in the clear,
  and leaves the session alone, whether it opened or not: anybody can
  name a session by the id in the clear and replay its messages.
- A bad signature or any other refusal is the answer to the OP. The
  session ends with that answer, and with every answer to an OP that did
  not open an upload in parts. An upload (and a link replace) keeps the
  session for its PART, COMPLETE, ABORT and KEEPALIVE messages, and only
  for them: a session has exactly one upload, and the messages carry no
  upload id.
- luk signs with the one key it was told to use and does not try
  another one in the session; `luk scan` tries the keys of the agent in
  sessions of their own.

### Sessions and limits

```yaml
limits:
  channel:
    auth: 60s        # from the handshake to the OP (default)
    pending: 1024    # sessions without their OP, all listeners (default)
    idle: 2m         # a session with its OP and no upload, without a request (default)
  uploads:
    total: 256       # uploads in parts open at once (default)
    identity: 8      # uploads in parts open at once per identity (default)
```

- `limits.channel.auth`: the time from the handshake to the OP. It
  covers a touch of a hardware key or unlocking an agent, which happen
  in exactly this window, as the signature covers `h`. The OP, once its
  clear header arrived, must arrive within it too (408). luk prints
  `waiting for the signature (touch the key)` on stderr, once, only when
  it is a terminal and not with `luk send --quiet`, when the signature
  of the OP takes over 1s; one that took over 55s from the handshake is
  not sent: luk fails with `the signature took longer than 55s; lukd
  drops a session that waits longer than 60s (limits.channel.auth): run
  it again`.
- `limits.channel.pending`: the sessions that have no OP yet, over all
  listeners. When it is full the oldest of them is dropped for the new
  handshake (as `MaxStartups` in sshd, evicting the oldest rather than
  refusing the newest). There is no limit per address: behind a proxy
  every client has the address of the proxy. A session dropped so
  answers its OP 404 `unknown session` in the clear; luk then dials once
  more (a new handshake and a new signature), not more.
- `limits.channel.idle`: a session that has its OP and no upload, without
  a request. The session of an upload follows the time of its upload
  (see Uploads in parts).
- `limits.uploads.total` and `limits.uploads.identity` (per owner key,
  see Quota): uploads in parts open at once. An upload over either is
  refused at its OP with 429 `too many open uploads` and `Retry-After:
  1`.
- Each value is positive; an absent or zero value takes the default, a
  negative one is an error. A reload applies them to new sessions and
  uploads.
- The receive role drops the sessions past their time with its expiry
  pass, about every minute, so a time limit acts up to a minute late.
- Sessions live in the memory of the receive role: a restart drops them
  all (luk then gets 404 `unknown session`); a reload keeps them.

### Identity key

The static X25519 key of lukd, the one the channel authenticates:

```
/etc/site/lukd/identity.key    (next to the main config file; -c moves it)
mode 0640, owner root:luk

-----BEGIN LUK IDENTITY KEY-----
<base64 std of the 32-byte X25519 private key>
-----END LUK IDENTITY KEY-----
```

- The receive role reads it at start (a key that is missing or does not
  load fails the start) and again on every `SIGHUP`; a key that does not
  load then is logged and the one in use stays. The process role never
  reads it.
- A file the group may write or others may read is refused (`identity
  key <path> has mode <mode>: want 0640 or stricter`); the group exists
  so that lukd (group `luk`) reads it.
- `lukd check` loads it: missing (`identity key <path> is missing: run
  lukd key generate`), not readable by the user running it, or unusable
  is an error; `--no-identity` skips that (the reload of the process unit
  runs `lukd check --no-identity`). Run as root it also checks that the
  service user can read the file.
- `lukd key [--pin-format words|key]` prints the pin of the key: its six
  words (the default) or the full key.
- `lukd key generate` creates the key (atomically, mode 0640; as root
  with group `luk`) and prints its words. An existing key is kept and
  the command fails, unless `--if-missing` (then it does nothing) or
  `--force` (it replaces the key). The `lukd` package runs `lukd key
  generate --if-missing` at install and on every upgrade, so an upgrade
  never changes the pin.
- Rotation: `lukd key generate --force` writes the new key and prints its
  pin, then on stderr `reload lukd (systemctl reload lukd) for the new
  key to take effect`; the receive role keeps the old key until its next
  reload or restart. Clients get the new pin next to the old one (an
  endpoint takes several pins), then `systemctl reload lukd` switches the
  key, then the clients drop the old pin.
- The key is the identity clients pin: a reinstall without the file
  means a new pin on every client. Keep it with the configuration.

### Pins

A pin is a lukd key a client trusts. It has two forms, told apart by
their length:

| form | written as |
|---|---|
| full key | exactly 43 characters of base64url without padding, decoding to the 32-byte public key |
| words, for people | 6 proquint groups of the first 12 bytes of SHA-256 of the key: `lusab-babad-gutih-tugad-hajop-kizof` |

- luk checks the whole pin it is given (all 96 bits of the words).
- An endpoint takes a list of pins and accepts lukd when its key matches
  any of them (rotation): comma-separated in the fragment of an endpoint
  URL (`https://lukd.vm:8443/drop#lusab-...,<key>`), a YAML list `pin`
  in the luk config (one pin may be a plain scalar, `pin: lusab-...`),
  `--pin` repeated on `luk config endpoint add`.
- Endpoints of one origin are one lukd: an endpoint URL without pins of
  its own takes those of the first config endpoint (by name) with the
  same scheme, host and port.
- An endpoint pin is a channel pin only. `sha256//...` there (config,
  `--pin`, the fragment of `luk config endpoint add --url`, `luk send -e
  URL#...`) is an error: `an endpoint pin is the lukd key: run luk scan
  URL`.
- Display: words by default, whatever form is stored, so a list of
  endpoints shows at a glance that no pin was replaced; `--pin-format
  key` on `luk scan`, `luk config endpoint ls` and `lukd key` shows the
  full key (a pin stored as words stays words: the key cannot be
  recovered from them).
- Downloads keep their own pin: a download URL (`luk get`) takes only
  `sha256//...`, the SPKI pin of the certificate of its listener (see
  TLS). The two pins never share a place: the endpoint URL in the luk
  config carries the lukd key, a download link carries the SPKI pin.
  Endpoints and exposes may share a listener; such a listener has both,
  the lukd key for its endpoints and, with `tls.mode: self` or `files`,
  the certificate pin in its download links.

Several servers (a direction, not implemented): redundancy is a list of
endpoint URLs, each with its own pin and each lukd with its own key, not
one key shared behind a load balancer. luk stays on the address it
resolved for the whole session, and a failed transfer is never resumed
on another address: a part cannot go to another server, so a retry
elsewhere is a new session, a new signature and the upload from the
start.

## Authentication

### Signed request

One operation is one OP of a channel session, signed once by an SSH key
(one touch on a hardware key). No token, no enrollment, no state on the
client. The OP of an upload:

```
PUT /<endpoint>                 (method and target of the OP)
Luk-Meta:       <base64url of the client meta JSON, no padding>
Luk-Timestamp:  <RFC 3339, UTC>
Luk-Nonce:      <16 random bytes, base64url, no padding>
Luk-Signature:  <SSHSIG blob, base64 std, one line (no armor)>
```

The OP has no body: once lukd accepts it, the content follows in parts
(see Uploads in parts). The signature is SSHSIG (`PROTOCOL.sshsig`, as
`ssh-keygen -Y sign`), namespace `luk-upload@v2`, over the canonical text
(lines joined by `\n`, no trailing newline):

```
luk-upload@v2
PUT
<host of the session>
<path of the session>
<Luk-Timestamp>
<Luk-Nonce>
<Luk-Meta>
<h: the final handshake hash, base64url without padding>
```

The host and the path are those of the prologue (see Handshake). The
last line binds the signature to the session: a signature of one session
never verifies in another, and the `v2` namespaces never verify as the
`v1` ones of downloads (`luk-get@v1`). `Luk-Meta` is signed as sent (the
base64url string), so there is no JSON canonicalization. A reverse proxy
in front of lukd must keep the `Host` header.

The public key inside the SSHSIG blob identifies the signer. It is either a
plain key or an OpenSSH certificate (as `ssh-keygen -Y sign` does when a
`-cert.pub` sits next to the key).

### Server verification (before the body)

"Before the body" in this spec means in the answer to the OP, before
lukd takes any part. On the OP of an upload lukd checks, in order:

1. Headers present and well formed; `Luk-Meta` decodes to valid meta.
2. Timestamp within `auth.clock_skew` (default 1m, max 1h) of the server
   clock (else 401 `timestamp outside the allowed window`; the answer does
   not name the allowed skew), and not earlier than the server start (to
   the second). After a reload that raised `auth.clock_skew` beyond what
   the nonce cache remembers (half its TTL, the largest skew in force so
   far), a timestamp is also not earlier than the reload minus that
   half (401 `timestamp before the clock skew was raised`): the older
   ones could carry nonces the cache already dropped.
3. SSHSIG namespace is `luk-upload@v2`, the signature verifies with the
   key in the blob over the text with the host, path and `h` of the
   session. The SHA-1 signature formats `ssh-rsa` and `ssh-dss`
   are refused (RSA keys sign `rsa-sha2-256` or `rsa-sha2-512`, as
   `ssh-keygen -Y sign` and `luk` do), as are a DSA key and an RSA key
   shorter than 2048 bits, also inside a certificate; a certificate
   signed by its CA in a SHA-1 format is refused in step 4.
4. The key resolves to an identity (below).
5. Nonce not seen within the window (entries expire after 2x the skew).
   Checked after the identity, so only known identities can fill the
   cache. The receive role keeps the cache in memory and in the file
   `seen` of `auth.nonces` (default `/run/luk/nonces`, a tmpfs
   directory): each accepted nonce is appended with its expiry, the file
   is loaded at start (expired entries dropped, a line torn by a crash
   skipped) and rewritten without the expired entries about every skew
   (temporary file and rename). A reload keeps the cache; a restart of
   the process reloads it. A missing directory leaves the cache in
   memory only (a warning at start); any other error reading or creating
   the file fails the start; a failed append is logged and does not
   refuse the request.
   - Limit: a host reboot empties the tmpfs and with it the cache. A
     request signed with a timestamp in the future (ahead of the server
     clock, within `auth.clock_skew`) can be replayed after a reboot if
     lukd is back before that timestamp: the start-time rule refuses
     only timestamps before the start. Keeping `auth.clock_skew` short
     keeps that window short. A replay also needs the session of the
     signature (`h`), which a restart drops.
6. The identity is in the endpoint's `allow`.
7. At least one pipeline matches (a secret upload needs none, see
   Volatile secrets).
8. A place among the open uploads (`limits.uploads`, see Sessions and
   limits).
9. The signed `size` fits the quota of the sender on the endpoint, when
   it has one (see Quota).
10. The queue filesystem has room for the
   signed `size` plus a reserve (`limits.queue.reserve`, default 1G).
   Space is reserved for the upload until it is accepted or dropped, so
   parallel uploads cannot overcommit it.

Any failure is the answer to the OP, inside the channel: 401 for 1-5,
403 for 6, 422 for 7, 429 for 8, 429 or 413 for 9, 507 for 10. No part
is taken and the session ends. An upload that passes gets the parts
offer (see Uploads in parts).

Before step 8, an upload whose signed meta carries `size` and `sha256`
answers 429 when its sender already holds `links.max` names of that
content in a storage it goes to (see Storage, `links.max`).

Authorization is checked once, at the OP, as for a single request: a key
removed from `allow`, a certificate revoked or expired while its upload
runs, finishes that upload. The parts and the COMPLETE are authenticated
by the session.

### Identities

```yaml
auth:
  clock_skew: 1m
  nonces: /run/luk/nonces        # nonce cache directory (tmpfs), default
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAA... Robert Socha"
  ca:
    - name: hosts
      type: host                 # host | user
      key: "ssh-rsa AAAA... CA/SSH Number 1"
      revoked:                   # optional
        key_ids: ["old.host"]
        serials: [250622104730]
```

Every key (`keys[]`, `ca[]`, `ssh.d/`, `ssh.d/ca/`) must be at least as
strong as OpenSSH accepts by default: a DSA (`ssh-dss`) key or an RSA key
shorter than 2048 bits is an error (`auth.keys <name>: RSA key of <n>
bits, at least 2048 required`, `auth.ca <name>: ssh-dss keys are not
accepted`).

Plain keys can also live in `ssh.d/` next to the main configuration file
(`/etc/site/lukd/ssh.d/`), one `<name>.pub` file per identity
(`deploy/ssh.d/robert.socha.pub.example`):

- the file base name is the identity name (same rules as `keys[].name`);
- each non-empty line not starting with `#` is one public key in
  authorized_keys form, a comment after the key allowed; a line with
  options (`from=`, `cert-authority`, ...) is an error;
- one identity may hold several keys (one per line), each authenticates
  as `<name>`; `keys[]` entries keep one `key` each;
- certificates and CA keys are an error: CAs are defined in `auth.ca`
  or `ssh.d/ca/` (below);
- files not ending in `.pub` and dotfiles are ignored; a missing
  directory is fine;
- the directory and the files must not be writable by group or others
  (like sshd `StrictModes`); otherwise lukd refuses to start;
- a name defined both in `keys[]` and in `ssh.d/`, or used by a CA, is
  an error, as is a key listed under two identities.

CA keys can also live in `ssh.d/ca/`: `ssh.d/ca/host/<name>.pub` is a CA
of type `host` named `<name>`, `ssh.d/ca/user/<name>.pub` one of type
`user` (`deploy/ssh.d/ca/host/hosts.pub.example`). `ssh.d/` itself
is not read recursively: `ca/` never holds plain keys.

- the file base name is the CA name (same rules as `ca[].name`);
- the file rules of `ssh.d/<name>.pub` apply: one key per line in
  authorized_keys form without options (`cert-authority` included), a
  comment after the key allowed, a certificate is an error, files not
  ending in `.pub` and dotfiles are ignored, a missing directory is fine;
- several lines are several keys of one CA (rotation): a certificate
  signed by any of them is a certificate of that CA; `ca[]` entries with
  `key` keep one key each;
- `ssh.d/ca/` holds only the directories `host/` and `user/`; any other
  entry there is an error;
- `ssh.d/ca/`, `ssh.d/ca/host/`, `ssh.d/ca/user/` and the files must not
  be writable by group or others;
- a name used by a `ca[]` entry with `key`, by a file of the other type or
  by an identity (`keys[]` or `ssh.d/`) is an error naming both sources; a
  CA key equal to a key of `ssh.d/` or to another key of a CA of the same
  type is an error.

Revocations stay in YAML: a `ca[]` entry with `name` and `revoked` but
without `key` applies to the CA file of that name. Its `type` may be left
out; when given it must match the directory of the file. A `ca[]` entry
without `key` and without a file of its name is an error.

```yaml
auth:
  ca:
    - name: hosts  # keys in ssh.d/ca/host/hosts.pub
      revoked:
        key_ids: ["old.host"]
        serials: [250622104730]
```

`allow`, logs (`server.sender`) and the identity are the same whatever
the source of the key.

- **Plain key**: must equal a `keys[].key` or a key of `ssh.d/`.
  Identity: `<name>`.
- **Certificate**: must be of the CA's `type`, signed by a CA key,
  within its validity window (`forever` is accepted), not revoked by Key ID
  or serial. Identity: `<ca name>:<Key ID>`, with the principals kept for
  matching. A certificate whose key is also listed in `keys` resolves as
  the certificate (the CA path is checked first).

`ssh-keygen -Y verify` refuses host certificates, so lukd verifies
certificates itself (`golang.org/x/crypto/ssh`).

Host certificates today have no principals and Key ID set to the host name
(`ping.example`). Key ID is part of the identity (logs, `server.sender`, the
owner key) and can be matched by `<ca>#<glob>` in `allow` (below);
principals will appear with the next distribution cycle (OpenSSH 10
requires them). A CA signs Key IDs unique per host, as the identity of a
certificate is its CA and Key ID.

Key names (`keys[].name`, `ssh.d/<name>.pub`) and CA names contain no `:`
and no `#`, and none is `*`: those mark the forms of an `allow` entry.

### `allow`

Entries of `endpoint.<name>.allow` (and of `expose.<name>.auth.ssh.allow`,
see Private files, of the `members` of a quota class, see Quota, and of
the capability lists of an endpoint, see Capabilities):

- `*` - every identity lukd knows when the request arrives: every plain
  key (`auth.keys`, `ssh.d/`) and every certificate of every CA, as if
  each CA were listed as `<ca>:*`. It is evaluated on the current
  configuration, so a key added by a reload is admitted from then on. No
  key or CA may be named `*`.
- `robert.socha` - a plain key by name.
- `hosts:*` - any certificate from that CA, with or without
  principals.
- `hosts:*.example.net` - a certificate from that CA with at least
  one principal matching the glob (`path.Match`). A certificate without
  principals matches only `*`.
- `hosts#db*.example.org` - a certificate from that CA whose Key ID
  matches the glob (`path.Match`), principals or not; `hosts#*`
  is every certificate of the CA, as `hosts:*`.

### Capabilities

The optional features of an endpoint are granted per identity: each is a
list of entries in the `allow` syntax (key names, `<ca>:<glob>`,
`<ca>#<glob>`, `*`).

| key | grants |
|---|---|
| `link.remove`, `link.ttl`, `link.list` | the link action (see Links) |
| `link.replace` | the link action `replace` and `--mutable` uploads |
| `private.owner`, `private.any` | `--private` and `--private --any` uploads (see Private files) |
| `private.list` | the files of access `any` of others in the link `list` with `any` (`luk link ls --any`), read-only (see Private files) |
| `secret.allow` | `--secret` uploads into the volatile storage (see Volatile secrets) |
| `pretty.allow` | `--pretty-url` (see `endpoint.<n>.pretty`) |
| `backup.hostname.any`, `backup.hostname.principal` | which `backup.hostname` (`--backup`) the signer may send (below) |
| `permanent.names.<name>.allow` | `--permanent` of the names the entry covers (see Permanent names) |

```yaml
endpoint:
  drop:
    allow: [robert.socha, "hosts:*"]
    respond: url
    storage: drop
    link:
      remove: ["*"]
      list: ["*"]
      replace: [robert.socha]
    private:
      owner: ["hosts#db*.example.org"]
    pretty: {allow: ["*"]}
```

- A capability applies to a request when the signer matches its list and,
  as for every request, the endpoint `allow`: a list never admits an
  identity the endpoint `allow` does not. `*` is every identity lukd
  knows, so `["*"]` is everyone the endpoint admits.
- An absent key or `[]` grants the capability to no one. `secret.allow`
  and `pretty.allow` are required in their blocks (`[]` turns the
  feature off while keeping the block); `secret` and `pretty` without
  `allow` are a configuration error (`endpoint <n>: secret.allow is
  required: a list of identities, e.g. ["*"]`).
- A signer without the capability gets the same answer as a signer of an
  endpoint without the feature (the status codes of each feature), so the
  answer tells nothing about who else holds it.
- The lists are checked as `allow` entries: an unknown key name or CA or a
  bad glob is a configuration error (`endpoint drop: link.replace: allow
  "nobody" is not a known key`). A value that is not a list, such as a
  boolean, is an error naming the key (`line 14: link.replace: a list of
  identities, e.g. ["*"]`).
- The lists are evaluated on the configuration current when the request
  arrives; a reload applies to the next request.

`backup.hostname` restricts the client `backup.hostname` (set by
`--backup`, see Client meta), so `.Hostname` and `.Origin` of a path
template name the host that sent the upload:

```yaml
endpoint:
  backup:
    backup:
      hostname:
        any: [robert.socha]        # may send any --backup hostname
        principal: ["hosts:*"]     # only one of the principals of its own certificate
```

- Without `backup.hostname` every identity the endpoint admits sends any
  hostname.
- With it, an upload carrying a non-empty `backup.hostname` is accepted
  when the signer matches `any`; else when it matches `principal` and is
  a certificate one of whose principals equals the hostname (compared
  case-insensitively); else it is refused with 403 before the body:
  `backup hostname "<h>" not allowed for this key`. The answer names
  neither list. A signer in both lists is treated as `any`. A plain key
  has no principals, so a plain key matched by `principal` alone never
  sends a hostname. An empty `backup.hostname: {}` lets no one send one.
- An upload without `backup.hostname` is not affected.
- Both lists are checked as `allow` entries, as every capability list;
  `backup` and `backup.hostname` take no other keys, and a
  `backup.hostname` that is not a mapping is an error
  (`backup.hostname: a mapping of any and principal`).

## Client meta

`Luk-Meta` is JSON, asserted by the signer (who said it is known, whether
it is true is not):

```json
{
  "file": "dump.sql.gz",
  "source": "file",
  "type": "",
  "size": 314572800,
  "sha256": "9f2c...",
  "tags": ["prod", "devdump"],
  "ttl": "24h",
  "once": false,
  "portal": "direct",
  "pretty_url": false,
  "no_owner": false,
  "mutable": false,
  "access": "private",
  "dry_run": false,
  "backup": {"hostname": "db1.example.net", "path": "/var/backups/dump.sql.gz", "mtime": "2026-09-30T03:58:10Z"},
  "permanent": "revocation/hosts.krl"
}
```

- `file` - the file name: `--name` when given, else the base name of a
  regular `--file`; empty for a stream (`--stdin`, or `--file` on a pipe,
  FIFO, device or `/dev/fd/N`) and for a prompted `--secret` without `--name`. It is a name for
  the content, not a storage path: the storage decides whether it is used.
  A `file` holding `/` or a control character (C0, DEL or C1, newline
  and tab included), or longer than 255 bytes, is invalid meta.
- `source` - `file` (a regular file), `pipe` (`--file` on something that
  is not a regular file), `stdin` (`--stdin`) or `terminal` (a bare `--secret`, prompted twice, masked; both entries must
  match).
  `file` and `terminal` require `size` and `sha256` (the whole content is
  in memory or on disk, a blob); `pipe` and `stdin` carry neither, except
  a repeat of `luk send --links`, which carries both, from the first
  answer (both or neither, else invalid meta).
- `type` - Content-Type for downloads (`--type`); optional; a media type
  without control characters, at most 255 bytes. A `--secret`
  upload without `--type` sends `text/plain; charset=utf-8`, whatever the
  source; an explicit `--type` wins. lukd takes `type` as it is (no
  sniffing), so the sidecar and the portal page (without parameters) show it; the raw
  content of a `reveal` upload (`<name>/get`) answers its own
  `text/plain; charset=utf-8` either way.
- `size`, `sha256` - set when the client uploads a file or a prompted `--secret`
  (it hashes it first), and on every repeat of `luk send --links`;
  omitted for streams otherwise. When set, the server compares them with what
  it received; a mismatch rejects the upload. With them the server may
  answer without the body (see Transfer dedup).
- `tags` - lowercase `[a-z0-9._-]+`, deduplicated, sorted.
- `ttl` - the lifetime asked for, a positive duration or `max` (the
  longest the storage allows: its `ttl.max`, or no expiry without one);
  it counts only in a storage with `ttl.user: true`, clamped to its
  `ttl.min` and `ttl.max` (see Storage).
- `ttl` / `once` - combine: a `once` upload is removed after the first
  download or at its expiry, whichever comes first; without `ttl` it
  expires after the storage `ttl.max`.
- `portal` - always sent: `"direct"` (the default: the bare URL serves the
  content), `"reveal"` (`--secret`: a secret page) or `"download"`
  (`--portal`: a download page). Any other value, including an empty one,
  is invalid.
- `pretty_url` - set by `--pretty-url`; asks for a proquint `.Random`
  (see `pretty` under Server configuration). Omitted when false.
- `no_owner` - set by `--no-owner`; the landing page of a `reveal` or
  `download` upload shows no "Sent by" row (see Phase 6), which it shows by
  default. Omitted when false.
- `mutable` - set by `--mutable`; the content of the upload may be
  replaced later through its link (`luk link --file`, see Links). An
  endpoint whose `link.replace` does not grant the signer refuses it with
  422 before the body.
  Omitted when false.
- `access` - set by `--private` (`"private"`) or `--private --any`
  (`"any"`); omitted for a public upload. A private upload is served only
  by the protect expose of the storage, to signed `luk-get@v1` requests:
  `private` to its owner (the `owner_key` of the sidecar), `any` to every
  identity the `allow` of that expose admits (see Private files). It
  takes `portal: "direct"` only (anything else is invalid meta). An
  endpoint whose `private.owner` or `private.any` (of the mode) does not
  grant the signer refuses the upload with 422 before the body. The mode is kept in the
  sidecar with the rest of the client meta.
- `backup` - set by `--backup`; `hostname` is a single path element (no
  `/` or control character, not starting with `.`, at most 255 bytes).
  An endpoint with `backup.hostname` refuses a hostname the signer may
  not send with 403 before the body (see Capabilities).
- `permanent` - set by `--permanent`; the upload is a new version of
  that permanent name of the endpoint (see Permanent names). Omitted
  for an ordinary upload.
- `dry_run` - set by `--dry-run`; the server runs every check up to the
  body (verification, matching, the signed size against the limits, the
  storage names) and answers the debug JSON (200) with `"dry_run": true` in
  `client` as the answer to the OP: no part is sent, nothing is stored, no
  pipeline runs. The answer has no `size` or `sha256` in `server`.
  `pipelines` holds the matched pipeline names, sorted; `schedule` the
  same pipelines in the order they start, each `{"pipeline", "group",
  "order"}`: those without a queue group first (no `group`, `order` 0),
  then every group by name in ascending `order` (see Scheduling). When a
  pipeline claims the upload (see Matching), `claimed` is `{"pipeline",
  "skipped"}`: the claiming pipeline and the other matching pipelines it
  left out; without a claim there is no `claimed`.

Server meta, set by lukd, never by the client: `id`, `sender` (identity),
`key_id` and `principals` (certificates), `fingerprint`, `endpoint`,
`received`, `size`, `sha256`, and unless `no_owner` the sidecar's `owner`:
the identity name of a plain key (`robert.socha`, the name in the server
configuration), or the literal `host` or `user` for a certificate, by the
type of the CA that signed it. It is derived from the authenticated
identity at upload time, never from client-supplied text: nothing of the
key itself (no key comment) and nothing of the certificate (no key id or
principal) is shown. With `no_owner` the sidecar has no `owner`.
Every sidecar also has `owner_key`, who may manage the link of the upload
(see Links): `key:<identity name>` for a plain key (any key of that
identity, also from `ssh.d/`, is the owner) or `cert:<ca name>:<Key ID>`
for a certificate. It is derived from the authenticated identity only and
never shown. A replace through the link adds `updated`.

## Matching

A pipeline matches an upload when the upload's endpoint is in the
pipeline's `endpoint` list and the upload carries every tag of the
pipeline's `tags` (AND; no tags = every upload of that endpoint). All
matching pipelines run, unless one of them has `claim: true`: then it
runs alone and no other pipeline gets the upload (for example one that
encrypts, so a catch-all archive never stores the plain file). Two
matching pipelines with `claim` refuse the upload before the body (422
`upload claimed by <a> and <b>`). `claim` needs `tags`. The `upload
accepted` and `dry run accepted` log lines of a claimed upload add
`claimed=<pipeline>` and `skipped=<the other matching pipelines>`. `endpoint` is
required on every pipeline. A
secret upload (a `reveal` upload of an endpoint with `secret`) matches
no pipeline: it is stored into the secret storage alone (see Volatile
secrets).

## Response

The answer of an upload is the answer to its COMPLETE (see Uploads in
parts), or to its OP for a dry run and a deduplicated upload. Set per
endpoint:

- `respond: accept` - a sink (backups): `202` with
  `{"id", "size", "sha256"}`, plus `ttl`, `ttl_note`, `ttl_min` and
  `ttl_max` when every storage the upload is stored into gives the same
  (none when they differ: the answer names no storage).
- `respond: url` - `201` with `{"id", "url", "expires", "ttl",
  "ttl_note", "ttl_min", "ttl_max", "size", "sha256"}`; the `ttl` fields
  are those of the respond storage (the secret storage for a secret
  upload, see Volatile secrets). The storage name is reserved at
  ingest from the storage `path` template (for a drop `{{ .Random }}`:
  32 characters, about 184 bits), so the URL is known before any
  pipeline finishes; `GET` answers 404 until the file is
  published. `storage` names the exposed storage the URL points to. A
  private upload (`access`) gets the `luk://` URL of the protect expose
  of that storage instead (see Private files); a public upload to a
  storage whose `expose` has `auth.ssh` the `luk://` URL of that expose
  (`https://` when it has `auth.basic` too; see Signed expose). An upload of a permanent name gets the permanent
  URL as `url`, with `permanent` (the name) and `version_url` (the URL
  of the stored version) added (see Permanent names).

Both answers carry `"deduplicated": true` when the server took the
content from what it holds for the sender instead of reading the body
(see Transfer dedup); the field is omitted otherwise.

`ttl` is the lifetime the server gave the upload (`7d`, `3h`, `1h30m`;
omitted when it never expires). `ttl_note` tells what became of the
client `ttl`: `capped` (above `ttl.max`), `raised` (below `ttl.min`),
`ignored` (the storage has no `ttl.user`); omitted when it was applied as
asked or not given. `ttl_min` and `ttl_max` are the `ttl.min` and
`ttl.max` of the storage in the same short form; each is omitted when the
storage has no such bound.

A normal upload answers per `respond` (201 or 202); only `dry_run`
returns the debug JSON (200), without any part. The `200` with the parts
offer is no answer of the upload: it asks for its content.

## Uploads in parts

The content of an upload (and of a link replace, see Links) goes in parts
through the session of its OP. A dry run, a deduplicated upload and a
refusal are answered at the OP and end the session there; any other OP
that passed every check before the body is answered:

```
200 {"parts": {"size": 8388608, "parallel": 4, "idle": 120, "rate": 65536}}
```

```yaml
endpoint:
  backup:
    parts:
      size: 8M        # default 8M; a multiple of 64K, from 64K to 2G-64K
      parallel: 4     # default 4; 1 to 64
    limits:
      body:
        size: 50G     # the largest upload; 0 or absent: none
        idle: 2m      # default 2m
        rate: 64K     # bytes per second, default 64K; 0: off
```

- `parts.size` is the size of every part but the last; `parts.parallel`
  is the most parts a client sends at once (`luk send --parallel N`
  sends up to N, at most this). A reload applies both to new uploads.
- luk takes only an offer lukd can make: `size` a multiple of 64 KiB
  from 64 KiB to 2 GiB - 64 KiB, `parallel` 1 to 64, `idle` at least 1
  and `rate` not negative. Any other offer fails the upload with `bad
  parts offer: <the offer>`, after an ABORT.
- `idle` is `limits.body.idle` in seconds (at least 1), `rate` is
  `limits.body.rate` in bytes per second (0: off), so luk keeps the
  upload alive and paces no part below the rate (see below).
- At the OP lukd takes the place of the upload (`limits.uploads`), the
  quota and the queue space of a signed size, then the acceptance order
  of the upload (see Acceptance order), and creates its staging file
  `<queue>/<id>/.payload.tmp` in the queue directory of the upload (the
  secret queue of a secret upload, so a secret stages in RAM): the
  signed size preallocated where the filesystem can (`fallocate`), else
  a sparse file; a stream grows as its parts land.

PART (kind 2, number n) carries the bytes of the content from n x
`parts.size` on. Every part but the last is exactly `parts.size` bytes;
a file of size S has S / `parts.size` parts rounded up (an empty file
none), a stream ends with its first part shorter than `parts.size`
(possibly empty).

- From the clear nonce, before the body is read: a part beyond the parts
  of a signed size, beyond the last part of a stream once that is known,
  or beyond `limits.body.size` of a stream is 400; a part already
  verified is answered 200 at once (sending a part twice is harmless); a
  part of an aborted or expired upload is 410, of one finalizing or
  committed 409 (once the body is being read, see below, it is 410 in
  every state); a part `2 x parts.parallel` or more ahead of the
  contiguous prefix of verified parts is 429 `part <n> ahead of the
  window` with `Retry-After: 1`. The window bounds the staging a client
  can scatter ahead of the hash.
- Once its first frame opened the part is taken. One writer per part: a
  newer attempt of a part replaces an older one still running, whose
  writes stop at its next frame (409). An older attempt that arrives
  while a newer one is being written (held up on the way) is 409 `older
  attempt` and leaves the newer one alone. Bytes land in the staging at
  their offsets as their frames open.
- An upload that is no longer open (finalizing, committed, aborted or
  expired) once the part's body is being read makes it 410: `upload
  ended` while its bytes are written, `upload <state>` when the whole
  message opened.
- A part is verified once the whole message opened and its length is
  right: exactly `parts.size`, the rest of a file for its last part
  (400 otherwise); a short part of a stream when a later part is there
  already is 400. A verified part never changes. The sha256 of the
  content grows over the contiguous prefix of verified parts, read back
  from the staging.
- A stream is charged to the quota as its parts are verified; a part
  over its quota (429 `quota exceeded`, 413) ends the upload, which gives
  back what it took. A stream over `limits.body.size` is 413 (422 over
  the 64 KiB of a reveal).
- `limits.body.idle`: a part without received bytes for it is 408 `no
  body data for <idle>`. `limits.body.rate`: a part must arrive within
  `parts.size / rate` (8 MiB at 64 KiB/s: 128s), else 408 `body not
  received within <time>`; a slow client then sends fewer parts at once.
- Answers: 200 `{}` (verified), 400, 408, 409, 410, 413, 422, 429, 507
  `not enough space`. A part answered before its body was read ends the
  connection.

COMPLETE (kind 3, number: the round, 0 for the first) asks lukd to commit
the upload; its plaintext is empty (400 otherwise).

- Parts missing: 409 `{"missing": [3, 7]}`, at most 1024 numbers; for a
  stream whose last part has not come, the number after the parts it has.
- Else the upload is finalizing: the hash of the prefix is finished, the
  size and sha256 of a file must equal the signed meta (422 `content
  differs from the signed <size> bytes sha256 <hex>`; for a secret the
  size only), those of a stream are computed (as before, nothing signs
  them). The staging becomes the payload of the queue entry and the
  entry is committed as any upload (see Response): 201 or 202 with the
  answer of `respond`.
- Any other refusal at the COMPLETE (422, 507) ends the upload as an
  ABORT does.
- The answer of the COMPLETE that ended the upload is kept: a COMPLETE
  sent again gets it again while the session lives, 3 x
  `limits.body.idle` after the end.

ABORT (kind 4, number 0; luk counts the attempt up on a resend) ends an
open upload: the staging goes at once, the place, the quota and the
queue space go back; 200 `{}` (also for an upload that had ended without
a commit), 409 `upload committed` after a commit. luk sends it on Ctrl-C
and on a failure, waiting at most 5s for the answer.

KEEPALIVE (kind 6, number: its own sequence from 0) keeps an upload
open while luk waits on a slow source; its plaintext is empty (400
otherwise). Once it opened it counts as activity of the session and is
answered 200 `{}`. A KEEPALIVE in a session without its OP is 409 `the
session has no operation`, in the clear, and changes nothing.

States: open, then finalizing (the COMPLETE), then committed, aborted
(ABORT, a refusal, the session dropped) or expired.

- An open upload whose session has no activity (bytes of a part that
  opened, a message, a KEEPALIVE among them) for `limits.body.idle`
  expires (logged `upload expired`): the staging goes, as for an ABORT.
- A restart of the receive role drops every session; the staging
  directories (without `meta.json`) are removed at start like any half
  received entry (see Service). luk sends a file once more from the
  start in a new session (new handshake, new signature); a stream fails
  (`server lost the upload; the stream cannot be sent again`).
- Result unknown: when the receive role restarts between the commit and
  the answer of the COMPLETE, luk gets 404 `unknown session` to the
  COMPLETE and reports `result unknown: the server lost the upload
  session at its end; check whether it arrived before sending it again`
  (exit 3). It never sends such an upload again by itself; there is no
  idempotency key and no record of it on disk.
- Only lukd's 404 `unknown session` (its message, not the status alone)
  counts as a session lukd lost, to a part or a COMPLETE: any other 404
  in the clear, such as one of a proxy on the way, is a transfer error.

luk sends the parts with `--parallel` workers (default 1):

- An attempt of a part that makes no progress for 30s, in the sending or
  in the wait for its answer, is cut. A part fails after 5 failed
  attempts, with 1s, 2s, 4s and 8s (+-20%) between them; a failed part
  fails the upload (ABORT). A 429 of the window waits `Retry-After` and
  counts no attempt; a 408 also takes one worker away (down to one); any
  other refusal ends the upload. 404 `unknown session` to a part is the
  restart above. A 409 `older attempt` counts no attempt: the part goes
  again under a newer one, after the wait an attempt would have. A 413
  in the clear is a proxy limit (see Carrier) and is not sent again.
- Before the COMPLETE luk checks that a file has the size and
  modification time its hash pass saw: else `file changed while sending:
  send it again` (exit 3, after an ABORT). A 422 of a file whose content
  no longer has its signed sha256 is a hash mismatch (exit 4).
- Missing parts listed by the COMPLETE are sent again, up to 3 rounds; a
  stream cannot send a part again (an error). A COMPLETE whose answer is
  lost, or does not come within 2m, is sent again (5 attempts): lukd
  answers it from the kept answer, or once the first one is done. A
  COMPLETE without an answer after its attempts (each timed out or
  failed in transport, other than a 404 in the clear) leaves the result
  unknown too: `result unknown: the server gave no answer within 120s at
  the end of the upload; check whether it arrived before sending it
  again` (exit 3, not sent again). luk still sends an ABORT; when lukd
  answers it 409 `upload committed`, the error says that lukd reports
  the upload as committed, but its answer with the URL was lost.
- A stream is read ahead into two buffers of `parts.size` per worker,
  so the next part is read while one goes. While luk waits on the
  source it sends a KEEPALIVE every `idle`/3 of the offer, and not
  otherwise.
- `--bwlimit` paces all the parts together; `--progress` counts the
  bytes of the parts, a part sent again once. A `--bwlimit` below the
  `rate` of the offer fails before any part (after an ABORT):
  `--bwlimit <x> is below the minimum rate of this endpoint (<rate>/s)`;
  otherwise luk sends at most `--bwlimit` / `rate` parts at once, so
  each part gets the rate.

## Transfer dedup

An upload whose signed meta carries `size` and `sha256` (a regular file,
a prompted `--secret`, every repeat of `luk send --links`) is answered
without its body when the server already holds that content for the
sender:

- every matched pipeline has only `store` steps (no `run`, not even with
  `tee`, no `relay`, no `encrypt`), into local storages with `hardlink`
  (see Storage);
- in every storage those steps store into, the object of the sha256
  exists with the signed size and its index lists a stored name whose
  `owner_key` is the sender's; or a committed queue entry of the
  queue the upload goes to (the endpoint queue, the secret queue of a
  secret upload), uploaded by the sender with that size and sha256, still holds
  the content (an upload not stored yet, as the first upload of `luk send
  --links` usually is when the second arrives).

An upload over the `links.max` of a storage is refused with 429 before
any of this (see Storage).

After every check before the body (verification, matching, limits, the
names), lukd creates the queue entry with the payload as a hardlink of
the object (or of that entry's payload), commits it and answers as for any
upload (`201` or `202` per `respond`, with a new name and URL) plus
`"deduplicated": true`, as the answer to the OP: no part is sent, no
queue space is reserved, and the session ends. Logged as `upload
deduplicated` instead of `upload accepted`. The pipelines run as for any
upload and store the content as a hardlink of its object. When a
condition fails or the hardlink cannot be made (a queue on another
filesystem than the storage, an object removed meanwhile), the upload
goes on as before: the OP gets the parts offer, the content is checked
against the signed size and sha256, and the store shares the space all
the same.

Never across owners. A sha256 is no secret: the portal page of a
`download` upload shows it, a catalog lists it, whoever saw a file can
compute it. Deduplicating on the hash alone would make it a capability:
anyone who knows the hash of another sender's file would get a link to
that content without having it. Scoped to the owner, a sender only gets
content that a name of its own (or its own queued upload) holds, content
it proved to have by sending it once, and the answer tells nothing about
what other senders stored (no oracle of existence). Another sender with
the same content sends the full body (and shares the space at store).

## Quota

A compromised client host can fill a backup with trash. A quota bounds how
fast one identity writes to an endpoint; with the storage ttl it also
bounds how much (rate times ttl).

```yaml
endpoint:
  backup:
    quota:
      mode: enforce        # enforce (default) | passive
      rate: 10G/1d         # refill rate: <size>/<duration>
      burst: 50G           # bucket capacity = largest single upload; default the size of rate
      class:               # optional
        - name: large
          members: ["hosts#db*.example.org", "hosts:abc1.example.org", robert.socha]
          rate: 50G/1d
          burst: 100G
        - name: small
          members: ["hosts#web*"]
          rate: 2G/1d
```

- A token bucket per endpoint and identity: the owner key of the upload
  (see Client meta), a plain key by its identity name (all its keys
  share the bucket), a certificate by CA and Key ID (`abc1.example.org` and
  `abc2.example.org` count apart).
- `rate` refills the bucket continuously, up to `burst`: on each upload
  `tokens = min(burst, tokens + rate * (now - updated))`. A new identity
  starts full. `burst` is also the largest single upload. Sizes take `K`,
  `M`, `G`, `T` (powers of 1024), durations `d` (see Server
  configuration).
- Classes: `class[]` entries have a `name` (unique), `members` (entries
  in the syntax of `allow`: a key name, `<ca>:<glob>`, `<ca>#<glob>`, `*`),
  `rate` (required) and `burst` (default the size of `rate`). A class
  without `members` is the catch-all; so are the top-level `rate` and
  `burst`. One catch-all at most: top-level `rate` (or `burst`) together
  with a class without members is a configuration error, as are two
  classes without members. A quota needs `rate` or `class`.
- Resolution: an identity that matches no class with members falls into
  the catch-all; without one it has no limit (who may upload at all is
  still `allow`). An identity in one class with members gets that class;
  in several, the lowest: the lowest rate, on a tie the lower burst, on a
  tie the first in the list. So the catch-all can be generous (or absent)
  while hosts get trimmed by classes. The first time per process an
  identity matches several classes the receive role logs a warning:
  `quota: hosts#db1.example.org matches large, small; using small`.
- `lukd check` (and the start, a reload) fails when a plain key matches
  more than one class with members (by name or `*`); certificates are
  matched per request, as their principals and Key IDs are not known
  before.
- Charged with the received bytes. An upload with a signed `size` is
  checked at its OP, after transfer dedup and before the queue space,
  and charged its size: over what the bucket holds it is refused with
  429 and `Retry-After` (seconds until the bucket holds the size) before
  any part. An upload without a signed size is charged as its parts are
  verified and ended by the part over the limit, with 429 and
  `Retry-After` (until the bucket holds what it had received). An upload
  larger than `burst` (the signed size, or a stream past it) can never
  pass and is refused with 413, without `Retry-After`. A dry run is
  checked the same way and charges nothing.
- Deduplicated uploads (no body, see Transfer dedup) cost nothing. An
  upload that is not accepted (refused, aborted, expired, content that
  differs from the signed size or sha256, a failed commit) gives back
  everything it took. Secret uploads and link replaces are uploads to the
  endpoint and count.
- The answer names no limit, no class and no level (as with the clock
  skew): the error is `quota exceeded` (429) or `upload exceeds the quota
  of this endpoint` (413). luk prints `luk: quota exceeded, try again in
  3h` (the `Retry-After` rounded up: seconds under a minute, minutes under
  an hour, hours above) or `luk: upload exceeds the quota of this
  endpoint`; exit 2 for both.
- `mode: passive` (learning): every upload is accounted in the same
  buckets and nothing is refused. An upload enforce would refuse is
  logged (`quota: would refuse` at INFO, with the endpoint, sender, class,
  size and tokens) and counted, and that upload is charged nothing (what
  it took before goes back), so the buckets hold what enforce would hold. Enforce logs `quota: refused` the
  same way.
- State: `<root>/data/quota.json` (JSON, mode 0640, replaced atomically and
  synced after every upload that changed it, and after a refusal), never
  under `/run`: a restart does not refill the buckets. An upload counts
  in the file once it is accepted, so one cut by a crash costs nothing
  (what uploads in flight took is written as still in the bucket). A
  file that is not valid JSON is moved aside to
  `quota.json.corrupt-<UTC time>` with a warning and the buckets start
  full. Per endpoint and identity it keeps the bucket (tokens, the time of
  the last update, the class, mode, rate and burst it was last charged
  under) and hourly stats of the last 7 days: bytes and uploads accepted,
  the largest upload, the uploads refused (or that passive mode would
  have refused), the lowest bucket level after an upload. Older hours are
  dropped; an identity with a full bucket and no stats left is dropped
  (it would start full anyway).
- Reload: `quota` is reloadable; the buckets survive it. A new class,
  rate or burst of an identity applies from its next upload (or listing):
  the bucket is refilled under the old rate up to then and clamped to the
  new burst.
- A quota of an endpoint that a reload removed no longer limits
  anything; its buckets stay in the file until they are full and their
  stats older than 7 days.

### `lukd quota`

Admin commands; they read the config given by `-c` and, for `ls`, the
state file under its `root`, without the daemon or while it runs (as root
or as the service user).

- `lukd quota ls [--endpoint NAME] [--margin 50%]`: one row per endpoint
  and identity (`<key name>` or `<ca>#<Key ID>`, the forms of `members`),
  by endpoint and identity, as aligned columns: `ENDPOINT`, `IDENTITY`,
  `CLASS` (`-` for the top-level rate), `MODE`, `RATE`, `TOKENS` (now, of
  the burst), `24H` and `7D` (bytes and, in parentheses, uploads), `LOW`
  (the lowest level after an upload in 7 days), `REFUSED` (refusals, or
  would-be refusals, in 7 days) and `SUGGEST`: a limit from those 7 days,
  in both modes (most useful in passive): the rate is the largest volume
  of a day (UTC) times 1 + `--margin`, per day (`<size>/1d`); the burst
  the largest single upload times 1 + `--margin`, never below the size
  of that rate; both rounded up to whole units of the largest unit they
  reach (12.6G is 13G, 950.2M is 951M). `-` with less than a day of stats
  or no upload. `--margin` is a percentage (`50%` or `50`, default 50%).

```
ENDPOINT  IDENTITY               CLASS  MODE     RATE    TOKENS     24H       7D        LOW   REFUSED  SUGGEST
backup    hosts#db1.example.org  small  enforce  20G/1d  10.4G/20G  10G (2)   18G (3)   10G   0        15G/1d 15G
logs      robert.socha           -      passive  1G/1d   945.3M/1G  100M (1)  100M (1)  924M  0        -
```

- `lukd quota explain CERT.pub|KEY.pub|NAME [--endpoint NAME]`: for every
  endpoint with a quota (or the one named), the classes that apply to the
  identity, the one in force marked with `*`, with its rate, burst, the
  mode of the endpoint and the members that matched (`(catch-all)` for
  the catch-all); `no class applies, no limit` when none does. The
  identity is a certificate or a public key file (resolved as a
  signature with it would be now: a revoked or expired certificate is an
  error) or the name of a plain key.

```
ENDPOINT  CLASS    RATE    BURST  MODE     MATCH
backup      large  50G/1d  100G   enforce  hosts#db*
backup    * small  20G/1d  20G    enforce  hosts:*.example.org
logs      * -      1G/1d   1G     passive  (catch-all)
```

## Links

The owner of an upload of a `respond: url` endpoint may manage its link:
remove it, set a new lifetime, or replace the content under the same URL;
and list the links it owns on the endpoint. Each action is granted per
endpoint to a list of identities (see Capabilities):

```yaml
endpoint:
  drop:
    respond: url
    link:
      remove: ["*"]               # luk link --rm
      ttl: ["*"]                  # luk link --ttl
      replace: [robert.socha]     # luk link --file / --stdin (mutable uploads)
      list: ["*"]                 # luk link ls
```

`link.remove`, `link.ttl`, `link.replace` and `link.list` are lists of
identities in the `allow` syntax; absent or `[]` grants the action to no
one. A non-empty list on an endpoint without `respond: url` is a
configuration error. A non-empty `link.replace` needs every pipeline of the endpoint to consist
of `store` steps only: a `run`, `relay` or `encrypt` step is a
configuration error naming the pipeline and the step (`endpoint drop: link.replace needs
pipelines of store steps only: pipeline drop step 2 is run`). A reload
applies to new requests.

### Wire format

A link request is the OP of a channel session on the endpoint path (see
Channel), like an upload. The headers `Luk-Link` and `Luk-Link-Action`
tell it from an upload; exposes never take link requests.

```
<METHOD> /<endpoint>             (method and target of the OP)
Luk-Link:        <the full link URL, as luk send printed it; empty for list>
Luk-Link-Action: remove | ttl | replace | list
Luk-Meta:        <base64url of the meta JSON, no padding>
Luk-Timestamp:   <RFC 3339, UTC>
Luk-Nonce:       <16 random bytes, base64url, no padding>
Luk-Signature:   <SSHSIG blob, base64 std, one line>
```

| action | method | meta | body |
|---|---|---|---|
| `remove` | `DELETE` | `{}` | none |
| `ttl` | `PATCH` | `{"ttl": "3d"}` | none |
| `replace` | `PUT` | the upload meta of the new content | the new content, in parts (see Uploads in parts) |
| `list` | `GET` | `{"limit": 100, "after": "<cursor>", "any": true}` (each optional) | none |

The signature is SSHSIG, namespace `luk-link@v2`, over the canonical text
(lines joined by `\n`, no trailing newline):

```
luk-link@v2
<METHOD>
<host of the session>
<path of the session>
<Luk-Link>
<Luk-Link-Action>
<Luk-Timestamp>
<Luk-Nonce>
<Luk-Meta>
<h: the final handshake hash, base64url without padding>
```

`Luk-Link` and `Luk-Meta` are signed as sent; for `list` `Luk-Link` is
empty (or absent) and its line of the canonical text is empty. The namespace and the
first line differ from an upload, so an upload signature never verifies
as a link request and a link signature never as an upload (401). The
timestamp, clock skew, server start, nonce cache (shared with uploads),
`Host` and `allow` checks are those of an upload (Server verification).

- `remove`, `ttl` and `list` meta: a JSON object of `ttl` (a positive
  duration or `max`, as in the upload meta), required for `ttl` and
  refused for `remove` and `list` (422), and the list fields `limit`,
  `after` and `any`, refused for `remove` and `ttl` (422 `<action> takes
  no limit, after or any`); any other field is 401 (an invalid meta).
- `replace` meta: the upload meta of the new content (`file`, `source`,
  `type`, `size` and `sha256` when known, as `luk send` builds it), with
  `portal: "direct"`. `tags`, `ttl`, `once`, `pretty_url`,
  `no_owner`, `mutable`, `access`, `backup` and `dry_run` must be absent
  (422): the link keeps its own. The new content takes the tags and the
  `access` of the link, also in the other storages its pipelines store
  into.

### Resolution

1. Signature, identity, nonce and `allow` of the endpoint: 401 or 403 as
   for an upload.
2. The list of the action grants the signer, else 403 (`endpoint <n> does
   not allow link <action> (link.<action>)`), the same answer whether
   the list is empty or names others: the answer tells nothing about who
   else holds the action. A `list` continues as described under
   Actions; steps 3 to 5 are for the other actions.
3. The link URL is parsed: an URL without a host is 422 (`bad link URL`).
   The scheme (`http`, `https`, `luk`), the port, the query and the
   fragment (a pin) are ignored. Its host and path are matched against
   the exposes of local storages, the `expose` and the `protect` of each:
   the host must be served by a listener of the expose (in its `host`
   list, the host of its `public`, or any host for a listener without
   `host`) and the path must start with the expose `path`; the longest
   path wins. The rest of the path is the stored name. A private file is
   managed through its `luk://` URL like any other.
4. Checks of the request and the storage, before the file is looked up:
   `remove` with a `ttl`, `ttl` without one, a `replace` meta with a
   field it must not have (422); `ttl` on a storage without `ttl.user:
   true` (422, `storage ttl policy does not take client ttl`).
5. The stored file: its sidecar must exist, not be an alias, have
   `endpoint` equal to the endpoint receiving the request and `owner_key`
   equal to the signer's, and not be expired. A file that is not there,
   was claimed (`once`), expired, belongs to another endpoint or to
   another owner all answer the same 404 (`link not found`), so the
   answer is no oracle of existence.

### Actions

- `remove`: the file and its sidecar are removed under the base lock (the
  empty directories pruned, an alias moved, the catalog rebuilt). 200
  `{"url", "removed": true}`.
- `ttl`: the new expiry is now plus the lifetime the storage `ttl` policy
  gives the requested `ttl` (clamped to `ttl.min` and `ttl.max` as for an
  upload; `max` gives `ttl.max`, and without one clears the expiry); the
  sidecar `expires` is replaced atomically under the base lock. 200
  `{"url", "expires", "ttl", "ttl_note", "ttl_min", "ttl_max"}` with the
  `ttl` fields as in an upload answer (`expires` and `ttl` omitted when
  there is no expiry). The janitor removes a file only while
  the expiry it found is still the sidecar's, so a ttl set meanwhile
  keeps it.
- `replace`: only for an upload sent with `mutable` (else 409, `link is
  not mutable`). The size, the reveal limit of a `reveal` link (64 KiB)
  and `limits.body` are checked before the body; the pipelines matched
  are those of the endpoint for the tags of the stored upload, and one of
  them must store into the storage of the link (else 422); a link of the
  secret storage of the endpoint is replaced as a secret upload (its
  secret queue, no pipeline, see Volatile secrets). The OP then gets the
  parts offer and the content goes through the queue like an upload (in
  parts, space reservation, limits, inotify pickup): the COMPLETE answers
  202 `{"url", "id", "size", "sha256"}` once it is committed, `id` being
  the queue entry. The
  pipelines of a replace (store steps only, see above) run as one
  publish, whatever their queue groups: every storage they store into gets a copy of the new content
  under a temporary name first; then the stores into the other storages
  are placed (ordinary stores), and the store into the link storage last
  writes the content under the same name instead of rendering a path:
  the new data is renamed over the old one, then the new sidecar over the
  old one, under the base lock; a failure between them puts the old data
  and sidecar back. Before the first rename the old data and sidecar get
  a second name in `.db/tmp/`, recorded with the names they keep in
  `.db/replace` (synced); the record goes (synced) after the second
  rename. A crash in between leaves the record: the next lukd process or
  command that takes the base lock (at the latest the maintenance of the
  process role at its start) puts the old data and sidecar back before
  anything else, so the link never serves the new content under the old
  sidecar. The sidecar keeps the id, sender, `received`, owner,
  `expires`, `once`, portal, `access` and the rest of the client meta of
  the upload, and takes the new `size` and `sha256`, the `file` and `type` of
  the new content when it names them (a new `file` without `type` drops
  the old `type`), and `updated` (the time of the replace request). A
  link removed, claimed or expired in between fails the replace. Any
  failure (a copy, an ordinary store, the replace of the link) drops the
  temporary copies and removes the names placed so far in the other
  storages: the link keeps its old content and the other storages get
  nothing new. A failed replace fails every pipeline of the entry (the
  one that failed with its step and error, the others at step 0 with
  `replace not published: pipeline <name> failed`) and the upload is
  dropped with a failure record (see Failures); the sender sends the
  replace again. A crash between the
  ordinary stores and the replace of the link, or during that replace
  (rolled back as above), leaves the entry in the queue; it runs again
  at the next start. A link that declares an alias
  is not changed in place (409 for `ttl`, a failed store for
  `replace`). Replaces are not ordered by acceptance: of two replaces of
  one link, the content of the one processed last stays.

- `list`: one page of the files of the respond storage of the endpoint
  (the link storage) and of its secret storage (see Volatile secrets)
  whose sidecar has `endpoint` equal to the endpoint receiving the
  request and `owner_key` equal to the signer's, not expired; claimed
  (`once`) files and aliases are not listed. 200 `{"links": [{"url",
  "file", "size", "received", "expires", "once", "mutable", "portal",
  "access", "updated", "permanent", "permanent_url", "shared",
  "sender", "cursor"}, ...], "next"}` (`file`, `expires`, `access` and `updated`
  omitted when empty, `links` is `[]` for none). The current version of
  a permanent name the endpoint allocates (the one `current/meta.json`
  names) has `permanent` (the name) and `permanent_url` (its permanent
  URL); both are omitted for any other file, an older version not
  removed yet included. The `url` of a private file is its `luk://` URL,
  as the upload answered it (see Private files). Sidecars that cannot be
  read are left out and logged. Logged as `link list` (with the number
  of links, `any` and whether more follow).
  - Order: one order for every entry and every page, newest first by
    acceptance order (`accepted`, `accepted_seq`, see Acceptance order),
    then by upload id (descending), then by the key of the stored name
    (the first 16 bytes of the sha256 of `<storage>/<name>`, lowercase
    hex, ascending), so no two entries share a place; an `accepted_seq`
    below 0 counts as 0. Shared entries take their place in the same
    order, between the signer's own links.
  - Pages: meta `limit` is the most entries of the page; absent (or 0)
    and anything above 1000 is 1000, the cap of a page; a negative one is
    422 `bad limit <n>`. Each entry has `cursor`: base64url without
    padding of `<accepted ns>.<accepted_seq>.<key>.<id in lowercase
    hex>` (any id, also an empty one, has a cursor), opaque to a client;
    it carries no secret and not the URL: the acceptance order, the
    upload id and the key of the stored name. Meta `after` (a cursor)
    starts the page with the first entry strictly after that
    place in the order; the entry it came from need not exist any more.
    A malformed cursor is 400 `bad cursor "<cursor>"`. `next` is the
    cursor of the last entry of the page when more entries follow it,
    absent on the last page. Each page is a request of its own, walking
    the storage again: an upload accepted meanwhile is newer than every
    cursor and shows only on a list from the start, and so does an entry
    a deduplicated re-upload of its content moved ahead (it takes the
    acceptance order of the re-upload, see Acceptance order); a file removed or
    expired meanwhile is not listed on a later page.
  - Shared entries: with meta `"any": true`, a signer `private.list`
    admits (see Private files) also gets, in the same walk and order, the
    files of access `any` other identities sent through the endpoint into
    its respond storage (never the secret storage) that the protect
    expose of that storage serves it (its `auth.ssh.allow` admits the
    signer), not expired and not `once` (a viewer must not claim a file
    meant for someone else); these have `"shared": true` and `"sender"`, the identity
    that sent the file as `link list` logs it (the sidecar's `sender`: a key
    name or `<ca>:<key id>`); both omitted for the signer's own links and no `permanent`. Without `any`, `private.list`
    is not consulted and only the signer's own links are listed; with
    `any` and a signer `private.list` does not admit, the same (no
    error). `link.list` is still needed. A shared entry stays read-only:
    `remove`, `ttl` and `replace` of it are 404 `link not found`, as for
    any link of another owner. Files of access `private` of others are
    never listed.

Other statuses: an unknown `Luk-Link-Action`, or a remove, ttl or replace
without `Luk-Link` (or `Luk-Link` without an action), is 400; a `list`
with a non-empty `Luk-Link` is 400 (`link list takes an empty
Luk-Link`); a method that does not fit the action is 405
with `Allow` set to the right one. Rejections are logged as `link
rejected`, successes as `link removed`, `link ttl set` and `link replace
accepted`.

## Permanent names

A permanent name is a fixed URL of a `respond: url` endpoint that serves
the version published under it last, such as a key revocation list or
the latest build, or nothing at all. The names are allocated in the configuration
only: there is no runtime reservation, and a name no entry covers can
never be published.

```yaml
endpoint:
  drop:
    respond: url
    storage: drop
    permanent:
      path: permanent                 # URL prefix under the expose of the storage (default permanent)
      names:
        revocation/hosts.krl:         # an exact name
          allow: [robert.socha, kf, matt]
        builds/*:                     # a pattern
          allow: ["ci:*"]
          max: 50                     # distinct names the pattern may hold (default 100)
```

```
luk send -e drop --file hosts.krl --permanent revocation/hosts.krl
https://drop.example.com/d/permanent/revocation/hosts.krl
```

- Names: a permanent name is a clean relative name: not empty, at most
  1024 bytes, not absolute, no control character, no empty, `.` or `..`
  element, each element at most 255 bytes, and no element `current` or
  starting with `current.` (lukd keeps the version of a name in such a
  directory). A key of `names` is an exact name, or a pattern when it
  holds `*`, `?`, `[` or `\`: `path.Match` on the whole name, so `*` and
  `?` never match a `/` and `builds/*` covers `builds/x` but not
  `builds/x/y`. A pattern has the element rules of a name.
- Precedence: the exact entry of the name when there is one, else the
  matching pattern with the most literal characters (every character but
  `*`, `?`, a `[...]` class and the backslash of an escape, so `\*`
  counts one), and among patterns with as many literal characters the
  one that sorts first (byte order of the key). `lukd check` warns about
  two patterns of one endpoint with as many literal characters that may
  cover the same names (a guess: patterns of as many elements whose
  elements are equal, a bare `*`, a literal one the other matches, or
  two patterns of which one matches the shortest name of the other; a
  class is assumed to meet anything).
- Who: an upload of a permanent name needs the signer in the endpoint
  `allow` and in the `allow` (identity list syntax) of the entry that
  covers the name.
- Upload: `luk send --permanent NAME` sends the client meta `permanent`.
  Before the body the server checks, in order: the upload sets none of
  `once`, a portal (`--secret`, `--portal`), `access` (`--private`),
  `mutable` and `pretty_url` (422 `permanent excludes <options>`); an
  entry grants the signer (else 422 `endpoint <n> does not offer
  permanent names`, as on an endpoint without `permanent`); the name is
  valid (422 naming the fault); the entry covering it grants the signer
  (else 403 `permanent name "<name>" not allowed for this key`, the same
  answer for a name no entry covers, so the answer tells nothing about
  the other entries); a new name of a pattern that already holds `max`
  names with a live version is 409 `limit of <max> permanent names of
  this pattern reached`. The store checks again under the base lock (an
  upload of a new name queued meanwhile, a reload): a version the
  endpoint no longer allocates, or one over `max`, fails the store (see
  Failures). `luk send` refuses `--permanent` with
  `--once`, `--secret`, `--portal`, `--private`, `--mutable`,
  `--pretty-url` or `--links` above 1 itself (usage error).
- Versions: each upload is an ordinary stored file of the respond
  storage (its path template, a random name, its ttl, its URL); its
  sidecar keeps the client `permanent` and `permanent_path` (the
  `permanent.path` of the endpoint when it was accepted). The answer
  (201) has `url` the permanent URL `<expose url><path>/<name>`,
  `permanent` the name and `version_url` the URL of the stored version.
  The version is a version of its name while its endpoint allocates the
  name under that path; a version of another path is not.
- Serving: `GET` and `HEAD` of the permanent URL on the expose of the
  storage serve the current version of the name, the one published
  last, with its own sidecar: its size, `ETag` (sha256), `Content-Type`
  and file name, under the rules of any file. A name whose current
  version has expired answers 404 at once (the request checks the
  expiry, also before the maintenance pass removes it), as does a name
  without a version, or one the configuration no longer allocates. There
  is never a fallback to an older version. Link actions take the version
  URL; the permanent URL is no link (404 `link not found`).
- Last published: a new version is compared with the current one by
  acceptance order (see Acceptance order; that of the current one is read
  from `current/meta.json`); `received` and the order the queue entries
  are processed in do not count. An upload is processed seconds after its
  acceptance and a failed one never runs again (see Failures), so the
  current version is all a new one is compared with. After a version is
  stored, under the base lock:
  - no current version (the first, or the current one went or expired):
    it becomes current;
  - accepted after the current version: it becomes current;
  - either way every other stored version of the name is then removed as
    `lukd storage rm` removes a file (sidecar, objects, catalog), logged
    as `permanent version replaced`; a name has at most one stored
    version;
  - accepted before the current version (an older upload whose entry ran
    late): it never becomes current; it is removed again at once, logged
    as `permanent version superseded`;
  - the current version itself (its store run again after an
    interruption): it stays current.
- Gone: when the current version goes (`luk link --rm`, `lukd storage
  rm`, retention, a replace of its stored name) or expires, the name is
  empty and answers 404 until a version is published. The expiry
  pass (every minute) removes an expired version and with it `current`;
  the maintenance pass of the process role unpublishes an expired or
  removed current version it finds. A `luk link --ttl` of the current
  version publishes its new expiry at once.
- On disk: `<base>/.db/permanent/<path>/<name>/current/` holds `data`, a
  hardlink of the current version, and `meta.json`, a copy of its
  sidecar; the directory of an empty name is empty. A new version is prepared in full as
  `<base>/.db/permanent/<path>/<name>/current.<random>/` (the hardlink,
  the sidecar, both synced with the directory), then swapped with
  `current` in one `renameat2(RENAME_EXCHANGE)` (a plain rename when
  there is no `current`), the directory synced and the old version (now `current.<random>`) removed. A current version
  that goes is renamed away in one step before its files are removed.
- Atomic for readers: a reader opens `current` once (a directory
  handle) and reads `meta.json` and opens `data` through it, so it gets
  the old version or the new one whole, with its own size, sha256 and
  type, never new content with an old sidecar, and never a missing name
  in between. A reader that opened the old directory just before the
  swap reads it whole while it exists, or finds it gone and opens
  `current` again. A download in progress keeps streaming the version
  it opened (the open file holds its inode).
- Crash: a crash before the exchange leaves the old `current` and a
  `current.<random>` beside it, after it the new `current` and the old
  version beside it; either way `current` is one whole version. Every
  publish, removal and repair of a permanent name runs under the base
  lock of the storage, so permanent names of one storage change one at a
  time (two uploads of one name apply one after the other, the one
  accepted last wins), and a `current.<random>` found under the lock is a
  crash leftover by definition: it is removed before the next version is
  prepared, and by the maintenance of the process role. That pass also
  finishes a switch a crash interrupted: the newest live version becomes
  current when there is no current version or it was accepted after the
  current one (stored, not published), and
  every other stored version of the name (replaced or superseded, not
  removed yet) is removed.
- `renameat2(RENAME_EXCHANGE)` is required: the receive and process
  roles probe it on the base of every storage with permanent names at
  start (two directories in `.db/tmp/`) and refuse to start without it
  (`storage <n>: permanent names: the filesystem of the storage does not
  support renameat2 RENAME_EXCHANGE, which permanent names need`). A
  publish that meets a filesystem without it fails the store with that
  error and leaves the published version as it was; there is no
  fallback that readers could observe half done.
- Namespaces: `permanent.path` names the namespace of an endpoint in
  the storage, on disk and in the URL. Two endpoints storing into one
  storage need different paths that do not nest (`lukd check`), so no
  name of one can meet a name of the other. Changing `path` starts a new,
  empty namespace (the permanent URLs change anyway): the versions keep
  their `permanent_path` and are no versions of the new one.
- Reserved: `<path>` and every stored name under `<path>/` of the
  storage are refused for stored files (a path template rendering there
  fails with 422 before the body, `reserved for the permanent names
  under <path>/`) and for aliases; an expose nested in the expose of the
  storage under `<path>/` (or containing it) is a configuration error.
- Orphans: a directory of `.db/permanent/` that no endpoint of the
  storage maps (its path is no `permanent.path` any more) or whose name
  no entry of that endpoint covers any more is an orphan. It is not
  served and lukd never removes it by itself (neither role); `lukd check`
  warns about each (`storage <s>: permanent name <path>/<name> is an
  orphan: no endpoint allocates it`), `lukd storage permanent` lists it
  with `ORPHAN`, and `lukd storage permanent --prune` removes it.
  Its versions stay ordinary stored files (ttl, retention, `lukd storage
  rm`); adding the entry back publishes the name again (its version
  accepted last).
- Empty names: the directory of an empty name (a directory without
  `current`) stays; `lukd storage permanent` lists it without a current
  version and `--prune` removes it when it is empty (a name with nested
  names keeps the directory they live in).
- Listing: the endpoint listing shows `permanent: true` when an entry
  grants the signer, never the names or patterns. `luk link ls` lists
  the current version of a name as a link with the flag `permanent`, and
  then a block per permanent name with its permanent URL and the URL of
  that version, on the page that holds that version (see Client).
- Cost: a store, a removal and every maintenance pass of a storage with
  permanent names read every sidecar of the base (O(files)), as aliases
  do; the gate of an upload reads them once.

## Private files

An upload sent with `--private` is private: only its owner downloads it,
or, with `--private --any`, every identity lukd knows (as far as the
protect expose allows). A private file is fetched by `luk get`, with a
signed request; it has no portal page and no public URL.

```yaml
listen:
  secure:
    addr: 0.0.0.0:8444
    host: [secure.box.example.com]
    tls: {mode: self, cert: tls/secure.crt, key: tls/secure.key, host: secure.box.example.com}

endpoint:
  drop:
    respond: url
    storage: drop
    private: {owner: ["*"], any: ["*"]}  # who may send which mode
    # private: {owner: ["*"], any: ["*"], list: [robert.socha]}  # + who lists the any files of others

storage:
  drop:
    type: local
    expose: drop                       # the public files
    protect: secure                    # the private files

expose:
  secure:
    listen: secure
    path: /
    auth:
      ssh:
        allow: ["*"]                   # who downloads the "any" files
```

- `endpoint.<n>.private.owner` and `endpoint.<n>.private.any` (lists of
  identities, see Capabilities; absent or `[]` is no one): who may send
  `access: private` and `access: any`. A non-empty list needs `respond:
  url`, and its respond storage needs `protect`. An upload of a mode not
  granted to the signer is refused with 422 before the body (`endpoint
  <n> does not accept private uploads of access <mode>
  (private.owner|any)`), also when the list names others.
- `endpoint.<n>.private.list` (a list of identities, see Capabilities;
  absent or `[]` is no one): who gets, in `luk link ls --any` (link
  `list` with `any`, see Links), besides its own links the files of access `any` other
  identities sent through the endpoint into its respond storage that it
  may download (the protect expose admits it, the same check as for `luk
  get`), not expired and not `once`, marked `shared` and read-only: their link actions stay
  refused (404). Files of access `private` of others are never listed.
  It grants no upload; a non-empty list needs `respond: url` and a
  respond storage with `protect` (`endpoint <n>: private.list needs
  respond url`, `... private.list needs storage <s> to have protect`).
- `storage.<n>.protect` (local storages only): the expose that serves the
  private files of the storage. That expose must have `auth.ssh` and no
  `auth.basic` (`expose <n>: auth.basic on a protect expose`: a password
  names no owner of private files), must
  differ from the storage `expose` (which may have `auth.ssh` too, see
  Signed expose), and serves no other storage (an
  expose belongs to one storage, as `expose` or as `protect`). The
  public URL of its first listener must be `https` (`luk://` means
  https).
- `expose.<n>.plain: true`: the expose serves without authentication on
  purpose; it excludes `auth.basic` and `auth.ssh` and silences the
  `lukd check` warnings for a storage `catalog` and for an `index` on an
  expose without auth.
- `expose.<n>.index: true`: the directory URLs of the expose answer an
  HTML listing (see Expose). It excludes `auth.ssh` alone (that expose
  serves only signed GETs; as a storage `expose` it answers the signed
  listing instead, see Signed expose); with `auth.basic` the listing is
  behind the password, also with `auth.ssh` beside it (a signed directory
  request then gets the signed listing). Its storage has no `shard` (`storage <s>: shard on expose
  <n> with index` is a config error): the URLs of a sharded storage are
  flat while its files lie in hash directories, so a listing would read
  every hash directory, and a sharded drop of random names would list
  every link. Without `auth` and without `plain` `lukd check` warns
  `expose <n>: index without auth lists every stored name`.
- `expose.<n>.auth.ssh.allow`: the expose serves only signed `luk-get@v1`
  requests (below): named in `protect`, only private files; as the
  `expose` of a storage, only its public files (see Signed expose).
  `allow` takes the entries of
  an endpoint `allow` (key names, `<ca>:<glob>`, `*`, see Identities) and
  may be empty.
- `expose.<n>.auth` with more than one method (`basic` and `ssh`): any one
  of them suffices, there is no mode key. A request with any of the
  signature headers (`Luk-Timestamp`, `Luk-Nonce`, `Luk-Signature`) is
  judged by its signature and `auth.ssh.allow` alone, never by
  `auth.basic`: a bad signature or an unknown key is 401 even with a
  valid `Authorization` header. A request without them is judged by
  `auth.basic` as on an expose without `auth.ssh` (401 with the basic
  challenge). Only the storage `expose` takes both (see Signed expose).
- Who gets a file: a file of access `private` its owner only (the
  identity whose `owner_key` the sidecar holds: any key of a plain-key
  identity, or a certificate of the same CA and Key ID, as for Links);
  `allow` does not apply, but the identity must still resolve on the
  current configuration. A file of access `any` every identity `allow`
  admits. Both are decided on the configuration current when the request
  arrives (a reload applies to the next request).
- A public expose (without `auth.ssh`) never serves a private file: 404,
  even with the exact name, and also through an alias (an alias has the
  sidecar of its target). A protect expose never serves a public file
  (404), no request authenticated by `auth.basic` gets a private file
  (404), and a protect expose never serves the catalog (the storage
  `expose` with `auth.ssh` does, see Signed expose). Private files are never listed in the
  catalog, never the target of an alias and never deduplicated by
  `dedup` (their space is shared through `hardlink` like any file's).
- The storage keeps the mode for every copy: a private upload stored into
  other storages too is private there as well (served only by their own
  `protect`, never by their `expose`).

### URL

The upload answer (`url`) of a private upload is the URL of the protect
expose (the `public` of its first listener, its path, the stored name)
with the scheme `luk`: `luk://secure.box.example.com/<name>`. `luk://`
always means HTTPS. When the first listener of the protect expose has
`tls.mode` `self` or `files`, the SPKI pin of the certificate it serves
is appended as the fragment, `luk://secure.box.example.com/<name>#sha256//...`,
so `luk get` verifies the server without any configuration; an `acme`
listener, or a plain listener behind a proxy (an `https` `public`), adds
no pin (clients verify against the system CAs). `luk link ls` and `lukd
storage ls` show the same URL for a private file.

### Wire format (`luk-get@v1`)

```
GET /<expose path><name>
Luk-Timestamp:  <RFC 3339, UTC>
Luk-Nonce:      <16 random bytes, base64url, no padding>
Luk-Signature:  <SSHSIG blob, base64 std, one line>
```

`HEAD` is signed the same way and never claims a `once` file. The
signature is SSHSIG, namespace `luk-get@v1`, over the canonical text
(lines joined by `\n`, no trailing newline; no `Luk-Meta`):

```
luk-get@v1
<METHOD>
<Host header>
<request path>
<Luk-Timestamp>
<Luk-Nonce>
```

`<METHOD>` is `GET` or `HEAD` as sent. `<request path>` is the path as
requested, escaped as on the request line (`/a%20b/x7Kq`), followed,
when the request has a query, by `?` and the query as sent
(`/v/2026/?recursive=1`); a request without a query signs its path
alone, so the text of a file download is the same as before queries
were covered. The query is part of what is signed: a captured signature
of `/v/` never verifies for `/v/?recursive=1`. Byte for byte, a `GET` of `/x7Kq` on `secure.vm:8443` is (`\n`
being the byte 0x0a):

```
luk-get@v1\nGET\nsecure.vm:8443\n/x7Kq\n2026-10-03T10:00:00Z\nAAECAwQFBgcICQoLDA0ODw
```

The timestamp, clock skew, server start, nonce cache (the receive role's,
shared with uploads and link requests) and `Host` checks are those of an
upload (Server verification). The namespace and the first line differ
from an upload and a link request, so a signature of either never
verifies as a get, and a get signature never as either (401).

Answers on an expose with `auth.ssh`:

- no `Luk-Timestamp`, `Luk-Nonce` and `Luk-Signature` at all: 404, the
  answer of a missing file (with `auth.basic` too: judged by
  `auth.basic`, see Signed expose);
- a signature that is incomplete, malformed, out of the clock skew,
  replayed or does not verify, or a key that resolves to no identity:
  401 (plain text with the reason, logged as `get rejected`);
- a valid identity that is not the owner (`private`), not in `allow`
  (`any`), or a file that is missing, public, expired or claimed: 404,
  the same answer in every case;
- success: the content with the download headers of a direct download
  (`Content-Disposition` with the file name, `Content-Type`, `ETag` with
  the sha256, `Range`), and a `once` file is claimed by the `GET` as a
  direct once download is (no `Range` then). The answers to `GET` and
  `HEAD` also carry `Luk-Expires` (the expiry, RFC 3339 in UTC; absent
  without one) and `Luk-Once: true` (absent when the file is not `once`);
  only an expose with `auth.ssh` sends them, a public expose never. Logged as `private download`
  with `auth=ssh` and the sender.

`GET` and `HEAD` are the only methods (`405` with `Allow: GET, HEAD`
otherwise, decided by the path as on every listener without endpoints).

### Signed expose

An expose with `auth.ssh` may also be the `expose` of a storage: it then
serves the public files of that storage to signed `luk-get@v1` requests
of the identities its `allow` admits, and answers a signed listing of
its directories. The private files of the storage stay with its
`protect` (an expose with `auth.ssh` of its own, or none); the same
expose is never both.

```yaml
storage:
  backups:
    type: local
    base: /storage/backups
    path: "{{ .Sender }}/{{ .Year }}/{{ .File }}"
    expose: vault                      # every file, to signed requests
    # protect: secure                  # private files, as before

expose:
  vault:
    listen: secure                     # its first listener has an https public URL
    path: /v/
    auth:
      ssh:
        allow: [robert.socha, "hosts:*"]
```

- Configuration: the first listener of the expose needs an `https`
  public URL, as for `protect` (`luk://` URLs mean https); `index`
  without `auth.basic` stays refused (`expose <n>: index excludes
  auth.ssh alone`): the signed listing below is the listing of such an
  expose. A `catalog` on its storage is served at `<url>catalog.json`
  to the identities its `allow` admits (and with `auth.basic` too to
  the unsigned requests it admits), with the answers of a signed file
  request and the headers of the catalog (Phase 4), not logged as a
  download; the `lukd check` warning for a catalog without auth does
  not apply.
- Files: the expose serves exactly what a public expose of the storage
  would serve (not expired, not claimed, not private, not a reserved
  name, not under a nested expose), to an identity its `allow` admits.
  Private files (`access`) are 404 there; they belong to `protect`.
- Answers: as for a private file (Wire format): no signature 404 (401
  with the basic challenge when the expose has `auth.basic` too); a bad
  signature or an unknown key 401; an identity not in `allow`, or a
  missing, expired, claimed or private file 404, the same answer in
  every case. Downloads carry the headers of a direct download plus
  `Luk-Expires` and `Luk-Once`, and are logged as `signed download`
  with `auth=ssh`.
- Portal uploads (`reveal`, `download`) have no landing page there for
  signed requests: the
  file URL answers the stored content as a direct download (download
  headers, `Range`), and the action URLs (`<name>/reveal`,
  `<name>/download`, `<name>/get`) do not exist (404; `POST` is 405).
- `once` files are claimed by the signed `GET` as by a direct download
  on any expose (`HEAD` never claims); the signed listing never lists
  them, so a directory download never claims one.
- URLs: the upload answer, `luk link ls` and `lukd storage ls` give a
  public file of such a storage the `luk://` URL of the expose (with the
  pin of a `self` or `files` certificate), as for a private file
  (`https://` with `auth.basic` too, below).
- Both methods: with `auth.basic` beside `auth.ssh` the expose serves
  the same public files to either (`auth` with more than one method,
  Server configuration). A signed request is answered as above, judged
  by its signature alone (a bad signature 401, never a fallback to
  `auth.basic`). An unsigned request is answered as on an expose with
  `auth.basic` only: 401 with the basic challenge without the right
  password, then the files, the portal pages and actions of portal
  uploads, and with `index` the HTML listing of the directory URLs
  (Expose), and the `catalog`. Its downloads are logged as
  `basic download` with `auth=basic` and the user when the content is
  sent: an answer `200` or `206` with the content (not a landing page,
  not `HEAD`, not a `304`, `416` or `404`, so not a `once` file another
  request claimed meanwhile). A signed request takes only
  `GET` and `HEAD` (405 otherwise) and never the index redirect of a
  directory name without its slash (404, as for a missing file). Private
  files are never served to an unsigned request (404), on this expose or
  on `protect`.
- URLs with both methods: the upload answer (`url`, `version_url`),
  `luk link ls` and `lukd storage ls` give the public files the
  `https://` URL of the expose instead of `luk://`, with the same pin
  fragment (a `self` or `files` certificate of its first listener): a
  browser opens it with the password, `luk get` signs it as a `luk://`
  URL. An expose with `auth.ssh` alone keeps `luk://`.

```yaml
expose:
  vault:
    listen: secure
    path: /v/
    index: true                        # the HTML listing, for basic
    auth:                              # either method suffices
      ssh:
        allow: [robert.socha]          # luk get, luk get <dir>/
      basic:
        - 'dev:$2y$05$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W'   # a browser
```

Signed listing: a signed `GET` (or `HEAD`) of a directory URL (the
expose path, or `<path><dir>/`, ending with a slash) answers the
directory as JSON (`Content-Type: application/json`, `Cache-Control:
no-store`), logged as `signed listing` with the sender and the count:

```json
[{"name":"2026/","dir":true},{"name":"db.sql.gz","size":1048576,"received":"2026-10-03T10:00:00Z","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]
```

- One level by default: the directories (`name` ending with `/`,
  `"dir": true`), then the files (`size` in bytes, `received` RFC 3339
  in UTC, `sha256`), each sorted by name ignoring case as the HTML index
  (Expose).
- `?recursive=1` answers every file below the directory instead, with
  names relative to it (`2026/10/db.sql.gz`), no directory entries,
  sorted by that name ignoring case. Any other query is 400. The query
  is signed (Wire format).
- Listed: the files of the HTML index the expose serves to the signer:
  never `once`, portal or private uploads, expired or claimed files,
  files without a sidecar, symlinks, the catalog or the directories of
  nested exposes. A directory is listed when it holds a listed file at
  any depth.
- 404: a directory with nothing listed (missing, empty, only unlisted
  files), every listing for an identity not in `allow`, and every
  listing of a storage with `shard` (its names are flat while its files
  lie in hash directories); the expose root answers `[]` when it holds
  nothing. A directory URL without its slash is a file name (404 for a
  directory). The protect expose has no listing.
- Cost: a one-level listing reads the sidecars of the files of the
  directory and walks each subdirectory until a listed file is found; a
  recursive listing reads every sidecar below the directory. Each is
  built from the disk on every request.

## Endpoint listing

Every listener (except an `acme: true` one, which redirects it like any
request) serves `/.well-known/luk/endpoints` through the channel (see
Channel): a session whose handshake and OP go to that path gets the
endpoints of that listener the signer may upload to, with what each
takes. It is the contract a client (or an agent driving `luk`) reads to
configure itself (`luk scan`). The OP:

```
GET /.well-known/luk/endpoints   (method and target of the OP)
Luk-Timestamp:  <RFC 3339, UTC>
Luk-Nonce:      <16 random bytes, base64url, no padding>
Luk-Signature:  <SSHSIG blob, base64 std, one line>
```

The signature is SSHSIG, namespace `luk-list@v2`, over the canonical text
(lines joined by `\n`, no trailing newline; no `Luk-Meta`):

```
luk-list@v2
GET
<host of the session>
/.well-known/luk/endpoints
<Luk-Timestamp>
<Luk-Nonce>
<h: the final handshake hash, base64url without padding>
```

The timestamp, clock skew, server start, nonce cache and `Host` checks are
those of an upload (Server verification). The namespace and the first
line differ from every other signed request, so no other signature
verifies as a listing and a listing signature as nothing else (401).

Answers (inside the channel; the session ends with them):

- a request without the signature headers, incomplete, malformed, out
  of the clock skew, replayed or not verifying, or a key that resolves to
  no identity: 401 (`{"error": ...}` as for an upload, logged as
  `endpoint list rejected`, at DEBUG when none of the signature headers
  is there). Nothing about the endpoints is in the answer.
- another method: 405 with `Allow: GET`.
- success: 200, logged as `endpoint list` with the sender and the count:

```json
{"endpoints": [
  {"name": "drop", "path": "/drop", "url": "https://lukd.vm:8443/drop",
   "respond": "url", "secret": true, "pretty": true,
   "private": {"owner": true, "any": false},
   "link": {"remove": true, "ttl": true, "replace": true, "list": true},
   "ttl": {"user": true, "min": "1h", "max": "7d", "default": "7d"},
   "secret_ttl": {"user": true, "max": "1d", "default": "1d"},
   "quota": {"mode": "enforce", "rate": "10G/1d", "burst": 53687091200, "tokens": 13421772800},
   "backup_hostname": "principal", "permanent": true}
]}
```

- `endpoints` - the endpoints of the listener the request came in on
  whose `allow` admits the signer (`*` admits every identity, as for an
  upload), by name; `[]` for none.
- `name` and `path` - the endpoint name and its `endpoint` path; `url` -
  the scheme of the listener (of its `public`, else `https` with `tls`,
  `http` without), the host of the session (port included) and the path.
  The URL carries no pin; `luk scan --print` adds the lukd key.
- `respond` - `url` or `accept` (see Response).
- `secret`, `pretty`, `private` and `link` are the capabilities (see
  Capabilities) as they apply to the signer: `true` when its list grants
  the signer, never the lists themselves, so the answer tells nothing
  about what others may.
- `secret` - `secret.allow` grants the signer: its `--secret` uploads go
  to the volatile storage (see Volatile secrets).
- `pretty` - `pretty.allow` grants the signer: its `--pretty-url` is
  accepted.
- `private` - `private.owner` and `private.any`: the modes of `--private`
  and `--private --any` accepted from the signer.
- `link` - the link actions granted to the signer (`link.*`, see Links);
  `replace` is also what `--mutable` needs.
- `ttl` - with `respond: url`, the ttl policy of the respond storage:
  `user` (a client ttl counts), `min` and `max` (`ttl.min`, `ttl.max`) and
  `default` (the lifetime of an upload without a client ttl), each
  duration in the short form and omitted when there is none. Without
  `respond: url` there is no `ttl` (the storages depend on the tags).
- `secret_ttl` - the same for the secret storage when it differs from
  `ttl` and `secret` is `true`; omitted otherwise.
- `quota` - the quota of the signer on the endpoint (see Quota): `mode`
  (`enforce` or `passive`), `rate` of the class in force (`<size>/<duration>`),
  `burst` and `tokens` (what the bucket holds now) in bytes; omitted when
  no class applies to the signer. It names no class and nothing of the
  other classes.
- `permanent` - an entry of `permanent.names` grants the signer: its
  `--permanent` uploads of the names that entry covers are accepted (see
  Permanent names). The names and patterns are never listed.
- `backup_hostname` - with `backup.hostname` on the endpoint, which
  `--backup` hostname the signer may send: `any`, `principal` (one of
  the principals of its certificate) or `none`; omitted without the
  block (any hostname).

Nothing else of the configuration is in the answer: no pipelines, tags,
storages, exposes, paths on disk, limits or quotas of others. A request
for the listing outside the channel is 400 (see Carrier).

`/.well-known/` is reserved: an endpoint or expose path equal to
`/.well-known` or under it is a configuration error, so the listing and
the ACME HTTP-01 answers (`/.well-known/acme-challenge/`, see ACME) never
meet a configured path. On a listener whose expose is `/`, any other
path under `/.well-known/` still goes to the expose (404 for a name
that is not stored).

## Volatile secrets

The content of a `--secret` upload (portal `reveal`) can be kept off the
disk: an endpoint with `secret` puts every `reveal` upload of the
identities of `secret.allow` into a queue and a storage of its own, both
on a tmpfs (`/run`).

```yaml
endpoint:
  drop:
    respond: url
    storage: drop
    secret:
      allow: ["*"]                      # whose reveal uploads go here (required)
      path: /run/luk/volatile/queue     # queue directory of the reveal uploads
      storage: volatile                 # their storage
      reserve: 16M                      # free space kept on the tmpfs (default 16M)

storage:
  volatile:
    type: local
    base: /run/luk/volatile/storage
    path: "{{ .Random }}"
    expose: volatile
    ttl: {user: true}

expose:
  drop:
    listen: download
    path: /
  volatile:
    listen: download
    path: /volatile/                    # nested in /: the longest path wins
```

- `endpoint.<n>.secret` is optional and needs `respond: url`. `allow`
  (required, see Capabilities) is who may send secret uploads; `path` is
  the queue directory (relative to `<root>/data` or absolute, like
  `endpoint.<n>.path`); `storage` a local, exposed storage other than
  the endpoint `storage`. Without `secret` an endpoint works as before.
- A `reveal` upload of a signer `secret.allow` does not grant is refused
  before the body (422 `endpoint <n> does not keep secrets in RAM for
  this key`): a secret meant for RAM never lands on disk by a fallback
  (the endpoint listing shows `secret: false` to that signer).
- A `reveal` upload of a granted signer is received into `secret.path`,
  never into the endpoint `path`, and is stored into `secret.storage`
  only: no pipeline of the endpoint runs for it (no `run`, no `encrypt`,
  no store into other storages) and its tags select nothing; it needs no
  matching pipeline. The answered URL is on the expose of the secret
  storage. Uploads with another portal go through the endpoint queue and
  pipelines as before. A `replace` of a link of the secret storage goes
  through the secret queue again (it needs `link.replace`, not
  `secret.allow`: the link stays where it is).
- Everything else of the endpoint applies: `allow`, `limits` (and the
  64 KiB of a reveal), `quota` (a secret is an upload to the endpoint), the `ttl` policy of the secret storage, `pretty`
  (the path of the secret storage must use `.Random` too), `once`,
  `no_owner`, the link actions (`list` shows the links of both storages,
  `remove` and `ttl` work on a secret link, `replace` of a `mutable`
  secret goes through the secret queue again), transfer dedup within the
  secret storage and its queue, and `hardlink` objects within its base.
  `--private` on a `reveal` upload stays invalid meta.
- The process role stores a secret as a pipeline named `.secret` (a
  configured pipeline name never starts with a dot): one store step into
  the secret storage. A failed store deletes the secret like any failed
  upload (see Failures): nothing of it stays, the failure record goes to
  `failed/` of the secret queue, shown by `lukd queue ls` and counted in
  `status.json` under that name; the sender sends the secret again.
- Space: the queue reservation works per filesystem as for any queue
  (the tmpfs is a filesystem of its own), but the free space kept on the
  filesystem of `secret.path` is `secret.reserve` (a size, default
  `16M`), not `limits.queue.reserve`, which still applies to the other
  queues: a `/run` with less free space than the general reserve takes
  secrets as long as it keeps `secret.reserve` free (507 below it).
  Endpoints sharing a secret queue keep the largest of their reserves.
- In RAM: the queue entry (payload and `meta.json`) and the stored file
  with its sidecar, the content objects of `hardlink` and the claimed copy
  of a `once` download. The volatile base has the layout of any local
  base (`file/` and `.db/`, see Layout under Storage). On disk: nothing of the content. The log line of
  a secret upload carries `sha256=-` instead of the hash, and the 422
  for a body that differs from the signed one names only the size, in
  the answer and in the log; the URL is
  logged as for any upload, and `status.json` keeps the entry `.secret`
  per sender (time, size, failures).
- `--secret` only keeps the content off persistent storage. It is not
  encryption and does not protect the content from anyone with access
  to the running server (root reads RAM, the tmpfs and the process
  memory); protecting the content is the job of the sender, who
  encrypts it before the upload (kufer).
- Swap: tmpfs pages may be swapped out. Run without swap, or with
  encrypted swap, to keep the content off the disk.
- A reboot empties `/run`: queued and stored secrets, sidecars and
  objects are gone (their links answer 404). lukd starts on empty or
  missing directories and creates them.
- Directories: `deploy/luk.tmpfiles.conf` creates `/run/luk/volatile`
  (`luk:luk`, 0700) at boot; the receive and process roles create
  `secret.path` (mode 0700) and the storage base at start and on reload,
  like the other queue and storage directories. `ProtectSystem=strict`
  leaves `/run` read-only; both shipped units carry
  `ReadWritePaths=-/run/luk/volatile` (the `-`: a missing directory does
  not fail the start), so no drop-in is needed for that path. Secrets
  elsewhere need a drop-in like any directory outside `/var/lib/luk`.
- Validation: `secret` needs `respond: url`; `secret.allow` is required
  and checked as `allow` entries; `secret.path` is required
  and lies outside every local storage base, every endpoint queue
  (`path`), every other secret queue (an equal one is shared) and the
  work directory; `secret.storage` is a known local storage with an
  `expose`, other than `storage`.

## Server configuration

`/etc/site/lukd/config.yaml` (YAML; `lukd -c PATH` overrides). The
directory of the main file holds:

```
/etc/site/lukd/
  config.yaml          main configuration
  config.d/*.yaml      configuration snippets, merged with config.yaml
  ssh.d/<name>.pub     plain keys of identity <name> (see Identities)
  ssh.d/ca/host/<name>.pub
  ssh.d/ca/user/<name>.pub
                       keys of CA <name> of type host or user (see Identities)
  identity.key         the identity key of the channel (see Identity key)
  run.yaml             lukd run global settings (see Jobs with other users)
  run.d/<job>.yaml     lukd run jobs
  gpg.d/               *.asc, *.gpg, *.pgp, *.key keys of encrypt recipients (gpg.keys)
  password.d/<name>    password <name> of the insecure encrypt options (see Encryption)
```

`config.d/` and `ssh.d/` sit next to the file given to `-c`. A snippet
has the schema of `config.yaml` and sets any part of it. Files not ending
in `.yaml` and dotfiles are ignored; a missing directory is fine. The
files are read in lexical order, but the result does not depend on it:

- named entries merge by name: `listen`, `endpoint`, `pipeline`,
  `storage`, `expose` and the lists `auth.keys` and `auth.ca` (by
  `name`). An entry is defined whole in one file; the same name in two
  files (`config.yaml` or snippets) is an error naming both files;
- every other value (`root`, each `limits.*` leaf, `auth.clock_skew`,
  `auth.nonces`,
  `gpg.*`, `log.level`) is set in one file only; a second definition is an error
  naming both files. Different leaves of one section may come from
  different files (`limits.conn.max` in one, `limits.header.timeout` in
  another);
- unknown keys and malformed values are errors of the file they are in;
- each file holds exactly one YAML document: a second document (after a
  `---` separator) is an error naming the file; trailing comments and
  blank lines are fine. The same holds for `run.yaml`, the `run.d` jobs
  and the luk config files;
- validation runs on the merged result, each error prefixed with the
  file that defines the faulty entry or value (`config.yaml` when no
  single file does).

Example of the merged configuration:

```yaml
root: /var/lib/luk                    # default; relative paths resolve against <root>/data

listen:                               # see Listeners
  intake:
    addr: 0.0.0.0:8443
    host: [lukd.vm]
    tls:
      mode: self                      # self, files or acme
      cert: tls/tls.crt
      key: tls/tls.key
      host: lukd.vm                   # CN/SAN of the self-signed cert
  proxied:
    addr: 127.0.0.1:8080              # plain HTTP behind a proxy
    host: [drop.example.com]
    public: https://drop.example.com

limits:                               # connection level, all listeners; optional, values shown are the defaults
  conn:
    max: 1024                         # per address; connections over it are closed at accept
    idle: 60s                         # keep-alive idle time; a response the client stops reading
  header:
    timeout: 10s                      # reading request headers, including the TLS handshake
  failed:
    age: 3d                           # failure records are removed after it; 0 keeps them
  channel:                            # the channel sessions (see Sessions and limits)
    auth: 60s                         # from the handshake to the signed operation
    pending: 1024                     # sessions without their operation; the oldest goes first
    idle: 2m                          # a session after its operation, unless it is an upload
  uploads:
    total: 256                        # uploads in parts open at once
    identity: 8                       # per identity

log:
  level: info                         # debug, info (the default), warn or error; both roles, live on reload

auth: {...}                           # see Identities

endpoint:
  backup:
    listen: intake
    endpoint: /backup
    path: queue/backup
    allow: [robert.socha, "hosts:*"]
    respond: accept
    backup:                           # optional: who may send which --backup hostname (see Capabilities)
      hostname:
        any: [robert.socha]
        principal: ["hosts:*"]
    limits:                           # request level, per endpoint; optional
      body:
        size: 50G                     # max upload size, 413 above it; 0 or absent = unlimited
        idle: 2m                      # max time without bytes in a part, and of an idle upload (default 2m)
        rate: 64K                     # a part arrives within parts.size / rate (default 64K; 0 = off)
    parts:                            # how the content goes (see Uploads in parts); optional
      size: 8M                        # default 8M
      parallel: 4                     # default 4
  drop:
    listen: intake
    endpoint: /drop
    path: queue/drop
    allow: [robert.socha]
    respond: url
    storage: drop
    pretty:                           # optional: allows pretty_url (--pretty-url)
      allow: ["*"]                    # who may ask for it (see Capabilities)
      bits: 64                        # 64 to 128, rounded up to a multiple of 16; default 64
    link:                             # optional: who may manage their links (see Links)
      remove: ["*"]
      ttl: ["*"]
      replace: [robert.socha]
    permanent:                        # optional: fixed URLs of the version published last (see Permanent names)
      names:
        revocation/hosts.krl: {allow: [robert.socha]}
    limits:
      body:
        size: 2G

pipeline:
  archive:
    endpoint: [backup]
    tags: [prod]
    queue:
      group: backup
      order: 1
    steps:
      - store: archive
  devdb:
    endpoint: [backup]
    tags: [prod, devdump]
    timeout: 2h
    queue:
      group: backup                   # optional: run after archive (see Scheduling)
      order: 2
      concurrency: 1                  # parallel runs across uploads (default 1)
    steps:
      - store: archive
      - run: /opt/luk/dbdump
      - store: publish
  secure:
    endpoint: [backup]
    tags: [secure]
    steps:
      - run: /opt/luk/gpg-encrypt
        env:
          RECIPIENTS: "robert@example.net"
      - store: archive
  drop:
    endpoint: [drop]
    steps:
      - store: drop

storage:
  archive:
    type: local
    base: storage/archive
    path: "{{ .Sender }}/{{ .Year }}/{{ .Month }}/{{ .Day }}/{{ .File }}"
  publish:
    type: local
    base: storage/publish
    path: "{{ .File }}"
    expose: publish
    cleanup:
      age: 14d
  drop:
    type: local
    base: storage/drop
    path: "{{ .Random }}"
    expose: drop
    ttl:
      user: true
      min: 1h
      max: 7d

expose:
  drop:
    listen: [proxied, intake]
    path: /d/
  publish:
    listen: intake
    path: /magento/
    auth:
      basic:
        - 'dev:$2y$05$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W'   # example: dev/dev
```

`limits` bounds resource use against slow-client exhaustion. `limits.conn.max` must be at least 1, each duration positive and `limits.body.size` and `limits.body.rate` not negative; an absent or zero value takes the default (`body.size`: no limit; `body.rate` 0 turns the rate off, absent is 64K). An upload goes in parts (see Uploads in parts): `limits.body.idle` measures the time between the bytes of a part and the time an open upload goes without activity, and `limits.body.rate` gives each part `parts.size / rate` to arrive, so a part never holds a connection longer than that; the upload as a whole has no time limit. A stalled or too slow part is answered with 408. `limits.channel` and `limits.uploads` bound the channel sessions and the open uploads (see Sessions and limits). The other direction is bounded the same way: a download whose client takes nothing of the response for `limits.conn.idle` is cut (the write deadline moves with every write, so a slow but reading client is never cut). `limits.conn.max` counts connections; an HTTP/2 connection runs at most 16 requests at once, so an address runs at most 16 x `limits.conn.max` requests and open files. The limit is per address, not per client.

`endpoint.<n>.pretty` lets an upload with `pretty_url` (`luk send
--pretty-url`) of an identity of `pretty.allow` (required, see
Capabilities) get a pronounceable `.Random`: a proquint of
`pretty.bits` bits from crypto/rand. Each 16 bits are five letters,
consonant-vowel-consonant-vowel-consonant, consonants `bdfghjklmnprstvz`,
vowels `aiou` (the standard proquint encoding, big-endian), the groups
joined with `-`: 64 bits are 4 groups (`lusab-babad-gutih-tugad`), 128
bits 8. `bits` is 64 to 128 and is rounded up to a multiple of 16 (65
becomes 80); without `bits` it is 64. The proquint replaces `.Random` in
every storage of that upload, a storage `random.alphabet` included, so
the answered URL and the stored names agree. `pretty` needs `respond:
url` and a `path` of the respond storage that uses `.Random`; otherwise
the configuration is invalid. An upload with `pretty_url` on an endpoint
without `pretty`, or of a signer `pretty.allow` does not grant, is
refused with 422 before the body ("endpoint <n> does not offer pretty
URLs"). A reload applies to new uploads.

`root` is an absolute path (default `/var/lib/luk`) on btrfs, owned by
root, with two entries: `<root>/data`, everything lukd writes, and
`<root>/root`, root's (see Service, State). Relative `tls.cert`,
`tls.key`, `endpoint.<n>.path` and `storage.<n>.base` are resolved against
`<root>/data`; absolute values are used as given. A relative value that
leaves `<root>/data` (for example `../x`) is a validation error.

Durations accept Go syntax plus `d` (days). Sizes accept `K`, `M`, `G`,
`T` (powers of 1024).

Validation (`lukd check`, and at start; it covers `config.d/`, `ssh.d/`
and `ssh.d/ca/`):

- every `endpoint.<n>.endpoint` is an absolute path, unique; neither it
  nor an expose `path` is `/.well-known` or under it (see Endpoint
  listing);
- every `allow` entry names a key, `<ca>:<glob>` or `<ca>#<glob>` of a
  known CA, or is `*`;
- `quota` has `rate` or `class`, `mode` `enforce` or `passive`, `burst`
  only with `rate`, one catch-all at most, unique class names, a `rate` on
  every class, `members` as `allow` entries, and no plain key in two
  classes with members (see Quota);
- every pipeline has a non-empty `endpoint` list of known endpoints;
- every `store` names a known storage that is not an `s3` storage (not
  implemented yet), every `storage.expose` a known expose;
- `storage.<n>.ttl` and `storage.<n>.cleanup.age` need a local storage;
  `ttl.min`, `ttl.max` and `cleanup.age` are not negative; `ttl.min`
  needs `ttl.user: true` and is at most `ttl.max` when both are set;
  `ttl` or `cleanup` under an expose is an
  error naming the new place (`expose <n>: ttl moved to
  storage.<storage>.ttl.max`, `cleanup moved to
  storage.<storage>.cleanup.age`);
- `storage.<n>.retention` needs a local storage and `conflict` `version`
  or `reject` (`storage <n>: retention needs conflict version or reject,
  not replace`: a replace overwrites a stored path at once and bypasses
  retention); every `origin` glob is
  non-empty and valid for path.Match; the `keep` counts and `keep.within`
  are not negative and at least one count or `within` is above 0; a rule
  without `origin` (every origin) is
  the last (`storage <n>: retention rule <i> matches every origin and
  must be the last: the rules after it are unreachable`);
- `storage.<n>.watch` needs a local storage; every `origin` and `file`
  glob is non-empty and valid for path.Match; `every` is above 0,
  `size.min`, `size.max` and `size.step` are above 0, `size.min` is at
  most `size.max`, `same` is at least 2, and a rule has at least one
  check (`storage <n>: watch rule <i>: needs a check (every, size.min,
  size.max, size.step, same)`); a rule without `origin` and `file` (every
  series) is the last;
- `respond: url` requires `storage`, and that storage must be exposed;
- a storage with `shard` is not the `expose` of an expose with `index`;
- the capability lists (`link.remove`, `link.ttl`, `link.replace`,
  `link.list`, `private.owner`, `private.any`, `private.list`, `secret.allow`,
  `pretty.allow`, `backup.hostname.any`, `backup.hostname.principal`) are lists whose entries are those of an endpoint
  `allow` (known key names and CAs, valid globs); a boolean or other
  scalar is an error naming the key; `secret.allow` and `pretty.allow`
  are required in their blocks (see Capabilities);
- a non-empty `link.*` list requires `respond: url`;
- `secret` requires `respond: url` and a local exposed `secret.storage`
  other than `storage`; `secret.path` overlaps no base, queue or the
  work directory; `secret.reserve` is not negative (see Volatile
  secrets);
- an endpoint `path` is equal to or apart from every other endpoint
  `path` (never nested in it), and no queue directory (`path`,
  `secret.path`) overlaps `<root>/data/acme`, `<root>/data/gpg-cache`,
  `auth.nonces` or the work directory, or holds a `tls.cert` or
  `tls.key`;
- a non-empty `private.*` list requires `respond: url` and a respond
  storage with `protect`;
  `protect` names an expose with `auth.ssh` other than the storage
  `expose`, on a local storage; every expose with `auth.ssh` that serves
  a storage (as `protect` or as `expose`) has a first listener with an
  `https` public URL;
  a `protect` expose has no `auth.basic`; `index` needs `auth.basic`
  beside `auth.ssh`; `auth.ssh.allow` entries are those of an endpoint
  `allow`;
- `permanent` requires `respond: url` and a local respond storage with
  an `expose` without `auth.ssh`; `permanent.path` (default `permanent`)
  is a permanent name without wildcards, does not overlap a nested
  expose of that expose nor, with `catalog`, `catalog.json`, and differs
  from the `permanent.path` of every other endpoint storing into the
  same storage without nesting in it; `names` is not empty; every key
  is a valid name or pattern; every entry has `allow` (an identity list,
  checked as an endpoint `allow`) and no key besides `allow` and `max`;
  `max` is at least 1 and only on a pattern. Warnings: two patterns of
  one endpoint that may tie, and orphaned permanent names in a readable
  base (see Permanent names);
- `pretty` requires `respond: url` and a respond storage `path` (and a
  secret storage `path`) that uses `.Random`; `pretty.bits` is 64 to 128;
- `parts.size` is a multiple of 64K from 64K to 2G-64K (`endpoint <n>:
  parts.size must be a multiple of 64KiB from 64KiB to 2GiB-64KiB`),
  `parts.parallel` 1 to 64; `limits.body.rate` is not negative;
  `limits.channel.*` and `limits.uploads.*` are positive;
- `run` is an absolute path or a mapping with exactly the key `job`
  (`run must be an absolute path or {job: NAME}`); `run.job` is a job
  name (`run.job "<job>": invalid job name`) and takes no `tee`, `env`
  or `jobs` (`run job takes no tee, env or jobs`); `tee` only on a `run`
  step (`tee needs run`); `relay` is a job name (`[a-z0-9][a-z0-9._-]*`,
  at most 64 bytes) and takes no `tee` or `env` (`relay takes no tee or
  env`); `jobs` only on a `run: <program>` step, with or without `tee`
  (`jobs needs run`), each a job name (`jobs: "<job>": invalid job
  name`) listed once (`jobs: <job> listed twice`); an `env` name of a
  `run` step does not start with `LUK_` (`env.<name>: LUK_* names are
  reserved`);
- `root` lies on btrfs (`statfs`, `BTRFS_SUPER_MAGIC`; `root <root>: not
  a btrfs filesystem`), and no path of the configuration (a queue, a
  storage base, a TLS file, `auth.nonces`, `gpg.keys`) lies in
  `<root>/root`, root's part of the root with the workspaces of lukd run
  (`<key>: <path> lies in <root>/root`); see Service, State;
- `queue.concurrency` and `timeout` are not negative, `queue.order` is
  not negative and needs `queue.group`, `queue.group` does not start
  with a dot or contain a slash; the pipeline key `concurrency` is an
  error (`concurrency moved to queue.concurrency`);
- a step is exactly one of `run`, `store`, `encrypt`, `relay`; encrypt recipients
  are valid, unique addresses and `key` recipients need `gpg.keys`;
  `encrypt.insecure` sets `symmetric` or `openssl` (or both), password
  names follow the rule of a job name (`[a-z0-9][a-z0-9._-]*`, at most
  64 bytes) and appear once in `symmetric`, `openssl` needs `key` and a
  non-empty `files` of valid `path.Match` globs without a slash.

## Reload

`SIGHUP` (`systemctl reload <unit>`) reloads the whole configuration in
both roles (`receive`, `process`) without interrupting uploads,
downloads or pipelines: lukd runs the same load as at start on the same
path (`config.yaml`, `config.d/`, `ssh.d/` with `ssh.d/ca/`) and, when it succeeds,
switches at once to the new configuration and everything derived from it
(identities, endpoint routing, pipelines, storages, exposes, gpg
settings, limits, `log.level`). Nothing is ever half applied. The
handlers of `SIGHUP`, `SIGTERM` and `SIGINT` are installed before the
configuration is loaded: a `SIGHUP` that arrives while the role starts
is kept and reloads once the role runs, never ends the process.

- Invalid configuration: the errors are logged (`reload failed, keeping
  the current configuration`) and lukd keeps running on the current one.
- Restart-only settings: `root`, everything under `listen` (`addr`,
  `host`, `tls`, `public`, `acme`), `limits.conn.max`, `limits.conn.idle` and
  `limits.header.timeout` (they belong to the open sockets and their HTTP
  server), and `auth.nonces` (the open nonce cache file). When one of them differs, the whole reload is refused (`reload
  refused: <setting> changed, restart required`) and nothing else of the
  new configuration is applied either; a restart applies it. The process
  role refuses the same changes, as both roles share the configuration.
- New queue and local storage directories are created as at start; one
  that cannot be prepared fails the reload like an invalid configuration.
- The passwords of the encrypt steps are read on every run of the step
  (see Encryption), so a changed password file needs no reload; a reload
  applies a changed `encrypt.insecure`.
- The identity key is re-read on every `SIGHUP` by the receive role; a
  key that does not load is logged and the current one stays (see
  Identity key).
- The TLS certificates and keys are re-read on every `SIGHUP` (see TLS),
  also when the configuration reload fails or is refused. Acme listeners
  keep their certificates (lukd renews and swaps them itself, `SIGHUP` is
  not needed for them, see `lukd tls acme`); `SIGHUP` logs each with its
  expiry.
- `log.level` is live: a new level applies from the reload on, in both
  roles, without a restart (the `config reloaded` line is logged at the
  new level).
- Success logs one line: `config reloaded` with the number of keys
  (identities), CAs (inline and `ssh.d/ca/`), endpoints, pipelines and
  storages and the files read (`ssh.d/` and `ssh.d/ca/` files included).
  Warnings of the new configuration (as `lukd check` prints them) follow.

In-flight work keeps the configuration it started with:

- A link request takes the configuration once when it arrives, like an
  upload; a replace runs its pipelines as an upload does.
- A signed get (`luk-get@v1`) takes the configuration once when it
  arrives: the identity, the `allow` of the expose (`*` included) and
  the expose itself.
- An upload takes the configuration once when its OP arrives and uses it
  to the end, its parts and COMPLETE included: identity, endpoint,
  matched pipelines, body limits, the parts size,
  `respond`, the storage and expose of the answered URL and the `ttl`
  policy of every storage it is stored into (the expiries are fixed at
  receipt, so a reload of `ttl` applies to new uploads only; stored
  expiries are never recomputed).
- `cleanup.age` applies from the next expiry pass of the janitor, to the
  files already stored too; `retention` from the next maintenance pass
  of the process role, to the files already stored too.
- A pipeline takes the configuration when it gets its concurrency slot
  and keeps it until it ends, so a running pipeline finishes even when
  the reload removed it, its storage or its endpoint. Queue entries not
  started yet use the configuration current when their pipeline starts:
  a pipeline that no longer exists fails (`pipeline not in the config`,
  see Failures); a storage that no longer exists fails its store step
  the same way.
- Queue entries of an endpoint removed by a reload are still picked up
  by the running process (its queue directory stays watched until the
  next restart). Their failure records are listed by `lukd queue`,
  counted in the status and expired only while an endpoint uses that
  queue directory.
- `queue.concurrency` of a pipeline: a new limit applies to the
  pipelines started after the reload; running ones are neither stopped
  nor counted out (a lower limit lets new runs start once enough of them
  ended).
- `queue.group` and `queue.order` apply to the uploads received after
  the reload; an upload received before keeps the group order it was
  received with (see Scheduling).
- A quota takes the configuration when the upload arrives; its buckets
  are not part of the configuration (see Quota).
- State survives a reload: the channel sessions and the open uploads in
  parts, the quota buckets, the nonce cache (its window only grows when
  `auth.clock_skew` changes, so a nonce seen under the longer skew is
  still refused; a raised skew does not reach back past what the cache
  remembers, see Server verification), queue space reservations (`limits.queue.reserve`
  applies to new reservations), failed counts and `status.json`, running
  pipelines and their claims, once claims and the locks of the storages
  and catalogs.

```sh
systemctl reload lukd             # both roles
systemctl reload lukd-receive     # one role (or lukd-process)
```

`lukd.service` runs `lukd check` and passes the reload on to both role
units (`ReloadPropagatedFrom=`); each role unit runs `lukd check` again
before sending `SIGHUP` (`ExecReload`), so `systemctl reload` fails
visibly on an invalid configuration and on a changed restart-only
setting, and the role keeps the current one. Each role reloads
independently.

Every role writes the restart-only settings it runs with to
`<root>/data/<role>.running.json` (`receive`, `process`) at start and
after every successful reload: JSON, replaced atomically, mode `0640`.
Nothing removes it on stop. `lukd check` compares the configuration
with the running file of every role whose lock
(`<root>/data/<role>.lock`, see Service) is held, so a file left by a
stopped role is ignored, and fails (exit status 1) with one line per
setting the reload would refuse, from the same comparison the reload
uses:

```
listen.main.addr changed, restart required (reload would be refused)
```

- No role runs on the `root` of the configuration: nothing is compared,
  `lukd check` prints a `note:` and passes as before.
- A changed `root` points `lukd check` to the new root, where no role
  runs: it passes with that note, and only the running lukd refuses the
  reload (in the journal, `journalctl -u <unit>`).
- A role running without its running file (written by an older lukd, or
  not writable): a `note:`, its settings are not compared.
- `lukd check --no-running` skips the comparison, for a configuration
  meant for a restart.
- Every password an encrypt step names (`password.d/<name>`, see
  Encryption) must be readable by the user running the check and not
  empty (`password <name>: ...`); `--no-passwords` skips that (the reload
  of the receive unit runs `lukd check --no-passwords`, as that role
  never reads them and its unit hides `password.d`).

Run as root (as `lukd.service` runs it on `systemctl reload lukd`), `lukd
check` also checks that the service user (`--user`, default `luk`) can
read every configuration input: `config.yaml`, `config.d/` and its
`*.yaml`, `ssh.d/` with `ssh.d/ca/{,host/,user/}` and their files,
`identity.key` (unless `--no-identity`), the
`cert` and `key` of `self` and `files` listeners, the `eab.key_file` of
acme listeners, `gpg.keys` with its key files, and the password files of
the encrypt steps (unless `--no-passwords`). Each file needs read
permission, each listed directory read and search, and every directory
above them search, computed from the owner, group and mode bits for the
uid and groups of that user (ACLs are not read). Each problem is an error
line (`<path>: not readable by luk`, `<path>: not searchable by luk`) and
the check fails (exit status 1). Inputs that do not exist are skipped. Run
as any other user the check is skipped: the role units run `lukd check` as
`luk`, where loading the configuration opens the same files.

Run as root, `lukd check` never opens a file of the service user, which
could put a FIFO, a symlink or an endless file there: the part that
reads them (the running files and locks of the roles, the layouts of the
local storage bases and their orphaned permanent names) runs again as
the owner of `<root>/data` (the service user; `<root>` itself is
root's) with its groups (as `lukd queue` and `lukd storage` do; neither
`root` nor `<root>/data` may be a symlink), with the same flags, and
its output and failure join root's own. A missing `root` or
`<root>/data` holds none of them: root then does that part itself. `lukd.service` bounds its reload with
`TimeoutSec=5min`, so a check that hangs fails the reload instead of
blocking it.

## Pipelines

A pipeline is a list of steps working on a set of files:

- `run: <program>` - a transformation. lukd asks `lukd run` to run
  `<program> <workspace>` as a transient unit of a dynamic user, in a
  workspace of its own (plus `LUK_IN`, `LUK_OUT`, `LUK_META` and the
  step's `env`), with the pipeline `timeout` (see Step contract and
  Service, Jobs with other users). `in/` holds the current file set,
  `out/` starts empty. Exit 0: `out/` becomes the file set for the next
  step. Non-zero: the pipeline stops. The program runs with the
  workspace as its current directory. It never runs as `luk`.
- `run: {job: <job>}` - a transformation by a job of run.d: the
  admin-allowlisted job `<job>` runs as the step, in its own workspace,
  with the job's `user`, `group`, `groups`, `credentials`, `env`,
  `timeout` and `state` (see Service, Jobs with other users); its
  `command` gets the workspace like a `run` program. Its `out/` becomes
  the file set of the next step under the rules of a `run` step. It
  takes no `env`, `tee` or `jobs`.
- `run: <program>` with `tee: true` - a consumer: the program delivers
  the set somewhere (an upload to S3, a copy to another host) and must
  leave `out/` empty; the next step gets the same file set it got (the
  files and their per-file meta). It may be the last step.
- `jobs: [<job>, ...]` on a `run: <program>` step (with or without
  `tee`): the jobs of `lukd run` its program may start with `luk-job run
  --job` in the middle of its work (see luk-job), for a program that
  needs another user's credentials for a part of the work. `lukd run`
  runs such a nested job only for the step that lists it here.
- `relay: <job>` - a consumer run by another user: lukd asks `lukd run`
  to run the admin-allowlisted job `<job>` as the step, in its own
  workspace (see Service, Jobs with other users), like a `tee` run step
  of that job. The next step gets the same file set; it may be the last
  step.
- `store: <storage>` or `store: [a, b]` - writes the current set to the
  storages (tee); the set passes on unchanged.

What `run` is (a shell script, a script that starts a container, a
binary) is not lukd's concern. lukd runs natively (systemd), not in a
container.

Workspace and work directory: see Step contract below.

Name: a pipeline name is of `[A-Za-z0-9_.-]`, does not start with a
dot or a dash and has at most 128 bytes (a config error otherwise). It
is a component of the work directory path, and `lukd run` refuses any
other name (see Jobs with other users).

Failure: the steps already done stay done (a `store` before a failed
`run` keeps its files). The upload is dropped with a failure record
naming the step (see Failures).

Queue: the body streams (never buffered in memory) into a temporary file
in `<endpoint path>/<id>/`, hashed on the way; on a size or sha256
mismatch the file is deleted (422), otherwise it is renamed atomically to
`payload` next to `meta.json`, and only then the upload is accepted.
`lukd receive` only commits it and `lukd process`, woken by inotify on the
commit, picks it up at once; a poll every 5 seconds is the
fallback (see Service). A
stream without a signed size cannot be checked for space up front: the
server stops it with 507 when the free space drops below the reserve
while receiving. The queue entry is removed once all its pipelines
ended, whether they succeeded or not (see Failures). When that removal
fails (an I/O error) the entry is parked in the running `lukd process`:
its pipelines do not run again, only the removal is tried again, after
a minute and then doubling up to an hour, with an ERROR log line
`queue entry parked` per try; a restart forgets it and runs its
pending pipelines again. A queued upload whose pipeline no longer
exists (configuration reloaded in between) fails that pipeline
(`pipeline not in the config`, see Reload).

### Failures

Simple ingest: failures are reported, the source resends. lukd keeps
nothing of an upload whose processing failed and never runs it again;
the sender (a backup job, CI) sees the failure in monitoring and sends
the upload again, a new upload with its own id and acceptance order.

- When the pipelines of an upload all ended and one or more of them
  failed, lukd writes its failure record, then removes the work
  directories of the upload and its queue entry (the payload and any
  copy in the entry). The work directories go like on success, also
  those of the failed steps, which may hold plaintext copies of the
  input; the record keeps the output tail of the failed step in its
  `error`.
- Pipelines are independent: what a pipeline that succeeded stored, and
  what the earlier steps of a failed pipeline stored, stays where it is
  (an encrypted copy stored before a relay that failed stays; the
  record says the relay failed). Queue groups keep their rule: the later
  orders of a group are not run after a failure, and the record lists
  them as not run.
- The same holds for a secret upload (see Volatile secrets): nothing of
  the secret is kept.
- A record that cannot be written (a full disk) does not keep the
  upload: the payload is removed all the same, with an ERROR log line
  `failure record not written, the upload is removed all the same`;
  `status.json` still has the failure (`last_failure`, `error`). The
  record is written once: a parked entry (see Queue) only tries its
  removal again.
- The record is `<queue dir>/failed/<id>.json` (written to a temporary
  file, synced and renamed into place): no payload, no plaintext, only
  what the upload was and how each pipeline ended:

```json
{
  "id": "20261005T101500Z-0a1b2c3d",
  "endpoint": "backup",
  "sender": "hosts:db1.example.net",
  "origin": "db1",
  "received": "2026-10-05T10:15:00Z",
  "accepted": 1791195300123456789,
  "size": 1027604480,
  "sha256": "...",
  "client": {"file": "db.sql.zst", "source": "file", "tags": ["prod"], "portal": "direct",
             "backup": {"hostname": "db1", "path": "/var/backups/db.sql.zst"}},
  "failed_at": "2026-10-05T10:16:02Z",
  "pipelines": [
    {"pipeline": "archive", "state": "failed", "step": 3, "error": "relay s3-upload: exit status 1\n...",
     "at": "2026-10-05T10:16:01Z", "stored": ["archive:db1/db.sql.zst.gpg"]},
    {"pipeline": "devdb", "state": "not_run", "step": 0, "error": "not run: archive failed",
     "at": "2026-10-05T10:16:01Z"},
    {"pipeline": "local", "state": "ok", "step": 0, "at": "2026-10-05T10:15:30Z",
     "stored": ["local:db1/db.sql.zst"]}
  ]
}
```

  `origin` is the backup hostname, else the sender; `client` the client
  meta of the upload (what the sender signed; the owner key is not part
  of it); `secret` the
  secret storage of a secret upload; `accepted_seq` as in the sidecar.
  Per pipeline, sorted by name: `state` (`ok`, `failed`, `not_run`),
  `step` (of a failure; 0 before the first step), `error` (up to 4 KiB,
  with the output tail), `at` (when it ended) and `stored` (what it
  stored, `<storage>:<path>`, ` (dedup)` appended to a deduplicated
  store; also for a failed pipeline, from the steps before the failure).
- An interrupted pipeline (shutdown) is no result: the entry stays in
  the queue with the results so far and the pipeline runs again from its
  first step at the next start.
- `lukd queue ls / rm`, `limits.failed.age`, the `failed` counts of
  `status.json` and monitoring work on the records (see Phase 5).

### Acceptance order

An upload is ordered by its start: `lukd receive` takes its acceptance
order when it admits the OP, before the first part (a deduplicated
upload, committed at its OP, at the commit). A dump started at 01:00
holds the state of 01:00, whenever its last part arrives. The upload is
committed with its COMPLETE (`meta.json` renamed into the entry), so
entries commit in another order than their acceptance when a long upload
finishes after a newer one.

- `accepted` (Unix nanoseconds) and `accepted_seq` are written into
  `meta.json` and are part of it, so they are on disk with the entry the
  moment it is committed (a crash before the rename leaves a half entry
  that is removed at start, the client got no 2xx and its retry is a new
  upload with a new order). The value is the wall clock read
  once at the start of `lukd receive` plus the time elapsed since, on
  the monotonic clock: it never goes back while the process runs, also
  when NTP or an administrator steps the wall clock back.
  `accepted_seq` orders acceptances of one process within the same
  nanosecond (0, 1, 2, ...); it is omitted when 0. The order is
  `accepted`, then `accepted_seq`.
- The receive role keeps a mark of the order in `<root>/data/accepted.json`
  (`{"mark": <ns>}`, mode 0640, replaced atomically and synced): a new
  `lukd receive` starts after the mark whatever the wall clock says, so
  a clock moved back between restarts (or one that ran ahead for a
  while) never makes new uploads older than the stored files. The mark
  is moved a minute past an order before that order is handed out, so a
  crash reuses none (a restart may skip up to a minute of order). A
  missing file starts from the wall clock; one that does not read stops
  the receive role (remove it to start from the wall clock); a failed
  write of the mark is logged (`acceptance mark not written`, WARN) and
  tried again with the next upload. The role units start after
  `time-sync.target`: with `systemd-time-wait-sync.service` enabled, a
  clock still wrong at boot neither orders uploads nor moves the mark.
- The queue entry keeps both at the top of `meta.json` and in its
  sidecar (`sidecar.accepted`, `sidecar.accepted_seq`); every stored
  file of the upload carries them in its sidecar. `received` stays the
  time shown (second resolution, the start of the request).
- What uses it: `lukd process` picks up the entries of a queue directory
  in acceptance order (FIFO); the version of a permanent name published
  last (see Permanent names), the newest declarer of an alias (and so
  `latest` of the catalog), the order of the files of a retention series
  and the newest copy of a watch series, `luk link ls`, `lukd storage
  ls` and the last upload of a pipeline in `status.json`
  (`last_accepted`, `last_accepted_seq`) all go by it.
- Entries and sidecars written before it (no `accepted`) count by their
  `received` time (whole seconds), then by id (and, where files of one
  upload tie, by stored name).

An upload that is older by acceptance does not replace a newer one in a
store step, however late it finishes:

| stored under the name | incoming is newer | incoming is older (late) |
|---|---|---|
| nothing | stored | stored |
| a file, `conflict: version` | becomes `<name>`, the previous file a version | stored as the version `<name>.<its received ts>`; `<name>` stays |
| a file, `conflict: replace` | replaces it | skipped: nothing is written, logged `store: older upload skipped` (WARN) and counted in `older_skipped` of `status.json`, the step succeeds |
| a file, `conflict: reject` | the store fails | the store fails |
| an alias, `latest`, a permanent name | moves to it | stays where it is |

- The files a `run` step produces carry the acceptance order of their
  upload, so a late dump still runs its pipelines and its results lose
  at the store step.
- A store run again for the upload that holds the name (the same id, after
  an interruption) is never older.
- A deduplicated store (`dedup`, see Storage and catalog) of an upload
  newer than the kept file gives the kept file (`<name>`) the acceptance
  order of that upload: it holds the content of the newest upload, so an
  upload accepted in between that finishes later goes to the versions.
  The alias the file declares follows.
- A replace through a link (`luk link --file`, see Links) is not
  ordered: of two replaces of one link, the one processed last wins,
  whichever started first.

### Scheduling

`queue` of a pipeline orders the matched pipelines of one upload and
bounds the runs of the pipeline:

```yaml
pipeline:
  archive:
    endpoint: [backup]
    tags: [prod]
    queue:
      group: backup        # pipelines of one upload in the same group run in order
      order: 1
    steps:
      - store: archive
  devdb:
    endpoint: [backup]
    tags: [prod, devdump]
    queue:
      group: backup
      order: 2
      concurrency: 1       # at most this many devdb runs at once (all uploads)
    steps:
      - store: archive
      - run: /opt/luk/dbdump
      - store: publish
```

- `queue.concurrency` (at least 1, default 1) limits the parallel runs of
  the pipeline across all uploads. A pipeline waits for a free slot
  before its first step; a pipeline waiting for its group predecessors
  holds no slot, so uploads waiting on each other cannot deadlock.
- `queue.group` (a name with the syntax of a pipeline name) and
  `queue.order` (at least 0, default 0; it needs `group`). For one
  upload, the matched pipelines that share a group run in ascending
  `order`: all pipelines of the lowest order (concurrently with each
  other), then, once all of them succeeded, those of the next order, and
  so on. A pipeline without a group runs at once, concurrently with
  everything else, the group stages included. Groups are per upload:
  pipelines of different uploads never wait for each other except for
  `concurrency`.
- When a pipeline of a group fails, the pipelines of the higher orders
  of that group do not run for that upload: each is recorded as failed
  at step 0 with the error `not run: <pipeline> failed` (the first
  failed pipeline of the order by name), logged as `pipeline skipped`
  with that `reason`, and shown as a failure in `status.json`. The
  failure record lists them as `not_run` (see Failures). Other groups
  and the pipelines without a group are not affected.
- The group and order of the matched pipelines are fixed when the upload
  is received (kept in the queue entry with the pipelines), so a reload
  changes them for the uploads received after it; a queued or running
  upload keeps them. A queue entry written by a lukd without
  groups has none: its pipelines run concurrently.
- A link replace ignores groups: its pipelines (store steps only) run as
  one publish (see Links).
- The old pipeline key `concurrency` is an error naming the new place
  (`pipeline <n>: concurrency moved to queue.concurrency`).

### Step contract

What lukd gives a `run` program (and the job of a `run: {job}` or a
`relay` step) and what it takes back. The contract is stable: later
versions only add to it (variables, keys of `meta.json`, files of the
workspace); nothing listed here is removed or changes its meaning.

Two directories take part in a step. The work directory
`<root>/data/work/<id>/<pipeline>/<step>/` is lukd's own, recreated empty
before every run, owned by `luk` and never seen by the program:

```
<work>/
  in/<name>             # the current file set (step 1: the upload), hardlinks
  in/<name>.meta.json   # per-file meta of <name>, when it has any
  out/<name>            # the results received from the workspace
  out/<name>.meta.json  # their meta
  meta.json             # {"server", "client", "pipeline", "step", "produced"}
  log                   # stdout and stderr of the unit
```

The workspace `<root>/root/job/<unit>/` is the program's: a btrfs subvolume
a helper unit of lukd run creates for the run, owned by the user of the unit, mode 0700
(see Service, Jobs with other users):

```
<workspace>/
  in/<name>             # the current file set, the program's own clones
  in/<name>.meta.json   # per-file meta of <name>, when it has any
  out/                  # empty; the program puts its results here
  out/<name>.meta.json  # optional: meta of out/<name> for the catalog,
                        # e.g. kind, compression, encryption, "alias"
  tmp/                  # TMPDIR and LUK_TMP, on the filesystem of out/
  meta.json             # the step meta, as in the work directory
  fail                  # optional: the step error, written by the program
  .luk/                 # 0700: the socket of luk-job run (nested jobs)
```

Files travel between the two as open descriptors, never as paths (see
Service, Channel of a unit): lukd process opens `meta.json` and the files
of its `in/` and sends them; the wrapper of the unit clones each into
the workspace. After the program ended the wrapper sends the entries of
`out/`; lukd process clones each into its own `out/` under a temporary
name, renames it once complete and then validates `out/`. No path of the
workspace names the upload, the pipeline or the step.

- Invocation: `<program> <workspace>`, with `<workspace>` as the current
  directory, as a dynamic user (see Service, Jobs with other users), in
  a transient unit of its own, under the pipeline `timeout` (it counts
  from the start of the unit: waiting for a unit slot of lukd run does
  not count, see `limits.units.max` under Jobs with other users); stdin is
  `/dev/null`, stdout and stderr are the step output. The job of a
  `run: {job}` step is invoked the same way as its `command`, as the job
  user.
- Environment: `PATH` (system default, includes `/usr/local/bin`),
  `LANG=C.UTF-8`, the step's `env` (a job: its `env` of run.d), then the
  metadata variables of the Step environment (last, so `env` cannot
  override them). Every `LUK_*` name is reserved: an `env` key `LUK_*` is
  a config error, so a metadata variable left unset (see Step
  environment) never takes a value from `env`.
- `meta.json`: `server` (`id`, `sender`, `endpoint`, `received`, `size`,
  `sha256`, `expires` when set), `client` (the client meta as sent:
  `file`, `source`, `tags`, `backup`, ...), `pipeline`, `step` and
  `produced` (`true` when the set was written by an earlier `run` or
  `encrypt` step; absent while the set is still the upload itself).
- Inputs: the files of `in/` are the program's own clones (copies when
  the stored file lies on another filesystem), owned by the user of the
  unit. Changing or removing them changes nothing stored and nothing
  another step or pipeline gets; their mode 0400 is a hint, not a
  protection. To pass an input on unchanged, link it into `out/` (`ln
  "$LUK_IN/x" "$LUK_OUT/x"` or `luk-job output --file "$LUK_IN/x"`).
- `tmp/` lies on the filesystem of `out/`: a result prepared there moves
  into `out/` with a rename.
- Results: the wrapper opens each top-level entry of `out/` with
  `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` and checks it with `fstat`. Anything
  but a regular file (a directory, a symlink, a FIFO, a socket, a
  device) is refused: the wrapper sends the refusal naming the entry,
  sends no result and exits non-zero, the unit ends, and the step fails
  (`out: "<name>": not a regular file`), also on a `tee` step. A result
  may have any owner and mode; the copy lukd keeps is owned by `luk`,
  mode 0440. At most 1024 top-level entries (files and meta files
  together; `out: more than 1024 entries`).
- Exit status 0, `tee: true`: `out/` must be empty; any entry (a file, a
  meta file, a dotfile) fails the step (`run <program>: tee step wrote
  out/<name>`). The next step gets the input set of the tee step
  unchanged: the same files with the same per-file meta, the upload
  itself when the tee step was the first one. A tee step that is the
  last step ends the pipeline; it stores nothing. A tee step still counts
  as a `run` step for a link replace (store steps only) and for the
  transfer dedup (store steps only); `tee` on a `store` or `encrypt` step
  is a configuration error (`tee needs run`).
- Exit status 0 (without `tee`): `out/` as received is validated and
  becomes the file set of the next step. Rules: at least one file; only
  regular files at the top level (no directories, no symlinks); names
  follow the rules of `file` (not empty, no `/` or control character, not
  starting with `.`, at most 255 bytes); a `<name>.meta.json` next to
  `<name>` is its meta, a JSON object of at most 64 KiB; a
  `<name>.meta.json` without its file fails the step. Any violation
  fails the step (`out: ...`).
- Non-zero exit status: the step fails and the pipeline stops. The step
  error is the text of `<workspace>/fail` when the program wrote one (the
  wrapper reads at most 4 KiB of a regular file, opened with
  `O_NOFOLLOW|O_NONBLOCK`, and sends it with the exit status; control
  characters other than newline and tab become spaces, surrounding white
  space is trimmed, empty means none); otherwise it is `run <program>:
  exit status N` (`run job <job>: exit status N` for a `run: {job}`
  step) followed by the last 4 KiB of the output. The output tail is
  logged in either case; after exit status 0 it is logged at debug level
  (`step output`). A `fail` file is ignored when the program exits 0 and
  on a timeout (`timeout after <d>` with the output tail); a stop of lukd
  interrupts the pipeline instead of failing it (Phase 3).
- The program hands results over only through `out/`; nothing else of
  lukd (queues, storages, other work directories, the processes of lukd)
  is reachable from its unit. How it gets the work done is its own
  business: it may hand the input to another process, a container (see
  Containers under Jobs with other users) or a remote host, as long as
  the results end up in `out/` before it exits. A background process it
  leaves lives in the cgroup of the unit until the wrapper ends and may
  still change `out/` while the wrapper sends it; then the unit ends,
  systemd kills what is left of its cgroup, and the workspace is removed.

### Step environment

The metadata variables of a step. A `run` program, the job of a `run:
{job}` or `relay` step and every nested job (`luk-job run --job`) get the
same list with the same values, built by one function:

- Workspace-bound, set by lukd run from the path of the workspace it
  created: `LUK_WORK`, `LUK_IN`, `LUK_OUT`, `LUK_META`, `LUK_TMP` (and
  `TMPDIR`), and `LUK_FILE` (from a file name of the request).
- Step-bound, from the fields of the request lukd run checked (see
  Request flow under Jobs with other users): `LUK_ID`, `LUK_PIPELINE`,
  `LUK_STEP`.
- Metadata, derived by lukd process from `meta.json` and the files of
  the set the unit gets (regular files; a `<name>.meta.json` next to its
  file is that file's meta, not a member of the set): `LUK_SENDER`,
  `LUK_ENDPOINT`, `LUK_FILE`, `LUK_NAME`, `LUK_TAGS`, `LUK_HOSTNAME`,
  `LUK_ORIGIN`. lukd process passes them in the request (for a nested
  job, derived for the files that job gets); lukd run never reads the
  channel or the workspace. Their values come from the `luk` user (see
  Jobs with other users, the boundary).

The variables:

- `LUK_WORK`: the workspace (also the argument and the cwd).
- `LUK_IN`: `in/`.
- `LUK_OUT`: `out/`.
- `LUK_META`: path of `meta.json`.
- `LUK_TMP`: `tmp/`, scratch space on the filesystem of `out/`; `TMPDIR`
  has the same value.
- `LUK_ID`: the upload id (equal to `server.id`).
- `LUK_SENDER`: the authenticated key name (`server.sender`).
- `LUK_ENDPOINT`: the endpoint name (`server.endpoint`).
- `LUK_PIPELINE`: the pipeline name.
- `LUK_FILE`: absolute path of the input file when the set has exactly
  one file; unset otherwise. Always `<workspace>/in/<valid file name>`.
- `LUK_NAME`: that file's name (the upload: the client `file`; a set
  `produced` by a `run` or `encrypt` step: the produced name); empty
  when the set has several files or the upload is an unnamed stream (or
  its `file` is not a valid name: the file in `in/` is then named by the
  id).
- `LUK_STEP`: the step number, 1-based, as in the work directory.
- `LUK_TAGS`: the client tags joined with `,`.
- `LUK_HOSTNAME`: `backup.hostname` when present, else empty.
- `LUK_ORIGIN`: `LUK_HOSTNAME` when present, else the sender.

The metadata variables pass one filter, the same in lukd process and
lukd run: only the seven names above in a request; a value of valid
UTF-8 without a control character (C0 such as NUL and newline, DEL,
C1); `LUK_NAME` empty or a valid file name; `LUK_FILE` a valid file name
in the request, set as `<workspace>/in/<name>`; the other five at most
1 KiB (the cap is not applied to `LUK_FILE` or to the workspace-bound
variables). Any other name in a request is ignored. A variable that
fails the filter is left unset, for a `run` program and a job alike. An
exec environment cannot carry a NUL, systemd refuses most other control
characters in an environment value (the unit would not start), and a
newline or a tab it accepts would reach the program raw. lukd refuses
control characters in client values at upload already; a tag list
longer than 1 KiB is what the cap leaves unset in practice. A program
or job treats an unset `LUK_*` variable as unknown, not as not
applicable. Every variable is its own `--setenv=NAME=value` argument of
`systemd-run` (no shell, `--expand-environment=no`), so no value (a tag,
a file name, a host name) can add an argument or expand anything.

### luk-job

`luk-job` is the helper for `run` programs and jobs, a separate static
binary (installed next to `lukd`, `/usr/bin/luk-job` from the lukd
package). It is tiny and needs nothing but the workspace, so a step
script can bind-mount it into a container and call it there. It works on
the workspace from `LUK_WORK`, or `--work` when given, and refuses (exit
1) when neither is set or the directory has no `in/`, `out/` and
`meta.json`. Values are passed by flags only. Errors go to stderr with
exit 1.

- `luk-job inputs [--json]`: the absolute paths of the input files, one
  per line, sorted by name (`<name>.meta.json` next to its file is not an
  input). `--json`: an array of `{"path", "name", "size", "meta"}`,
  `meta` being the file's per-file meta or `{}`.
- `luk-job input`: the path of the single input; exit 1 with
  `N inputs; use luk-job inputs` when the set has not exactly one file.
- `luk-job meta [--json] [--field PATH]`: the upload `meta.json`, as
  sorted `dotted.path=value` lines, or the JSON object with `--json`.
  `--field` with a dotted path (`client.backup.hostname`,
  `server.sender`) prints one value: a string raw, anything else as JSON
  (always JSON with `--json`); a missing field exits 1.
- `luk-job output --file PATH [--name NAME] [--meta key=value ...]
  [--meta-file FILE] [--move]`: puts PATH into `out/` as NAME (default
  the base name of PATH) and prints the new path. A hardlink on the same
  filesystem, else a copy synced to disk; with `--move` a rename, else a
  copy and the removal of PATH. PATH must be a regular file (not a
  symlink); NAME follows the `out/` rules and may not end in
  `.meta.json`; an existing `out/NAME` or `out/NAME.meta.json` is
  refused. Meta: `--meta` pairs (repeatable, applied in order) over the
  JSON object of `--meta-file`; a value is JSON when it parses as JSON
  (`count=42`, `keep=true`, `list=[1,2]`), else a string; a dotted key
  builds nested objects (`backup.origin=web1`). When any meta is given
  it is written atomically to `out/NAME.meta.json`, at most 64 KiB.
- `luk-job fail --message TEXT`: writes TEXT (sanitized as above, at
  most 4 KiB) to `<workspace>/fail` and exits 1, so `exec luk-job fail
  ...` or `luk-job fail ... || exit 1` ends the step with TEXT as its
  error.
- `luk-job run --job NAME [--file PATH ...] [--out DIR]`: runs the
  nested job NAME, an admin-allowlisted job of `lukd run`, as its own
  user in its own workspace (see Service, Jobs with other users; the
  `run` step must list NAME in `jobs`). luk-job connects to the socket
  of the wrapper, `<workspace>/.luk/run.sock`; the wrapper forwards the
  request over its channel to lukd process, which asks `lukd run` for
  the job. Inputs of the job: the files named by `--file` (repeatable;
  regular files, not symlinks, opened by luk-job and sent as
  descriptors; their base names are valid names and distinct, and a
  `<name>.meta.json` among them is the meta of `<name>`); without
  `--file`, the input set of the step. Results of the job: cloned into
  DIR of `--out` (an existing directory, each file under a temporary
  name and renamed once complete; an existing name is refused); without
  `--out` the job must leave its `out/` empty (`job NAME wrote
  out/<name>`, exit 1). The job's stdout and stderr are relayed to
  luk-job's stdout and stderr and luk-job exits with the job's exit
  status; a refused request, a connection or protocol error exits 1
  with a message. One nested job at a time per step: a second `luk-job
  run` while one runs is refused (`luk-job run: another job of this step
  is running`). `SIGTERM` or `SIGINT` (the step timeout, a stop of lukd)
  closes the connection, which stops the job, and exits 1. A pipeline
  that only hands its set to one job needs no program: see the `relay`
  and `run: {job}` steps.
- `luk-job version`: the version.

Example (`contrib/examples/run-step.sh`):

```bash
#!/bin/bash
set -eufo pipefail
IFS=$'\t\n'

in=$(luk-job input)
origin=$LUK_ORIGIN
tmp=$LUK_WORK/tmp
mkdir -p -- "$tmp"

# Placeholder for the real work (a restore test in a container, a conversion).
if ! gzip -t -- "$in" 2> "$tmp/err"; then
  exec luk-job fail --message "not a gzip file: $(head -c 200 -- "$tmp/err")"
fi
gzip -dc -- "$in" | sha256sum > "$tmp/sum"

luk-job output --file "$in" --name "$origin.sql.gz" \
  --meta kind=logical --meta compression=gzip --meta "backup.origin=$origin"
luk-job output --file "$tmp/sum" --move --name "$origin.sql.sha256" \
  --meta kind=checksum --meta "of=$origin.sql.gz"
```

Scratch files belong in `tmp/` (`LUK_TMP`) or elsewhere in the workspace
outside `in/` and `out/`; a helper unit of lukd run removes the workspace after its unit.

### Encryption

`encrypt` is a built-in step producing OpenPGP messages any `gpg` can
read. A step is exactly one of `run`, `store`, `encrypt` or `relay`.

```yaml
gpg:
  keys: /etc/site/lukd/gpg.d           # the default (gpg.d next to config.yaml); *.asc, *.gpg, *.pgp, *.key public keys of `key` recipients
  wkd:
    cache: 1d                         # WKD keys are refetched after it (default 1d)

pipeline:
  secure:
    endpoint: [backup]
    steps:
      - encrypt:
          wkd: [robert@example.net, marek@example.net]
          key: [matt@example.com]
          strict: false               # optional, default false
      - store: archive
```

- Recipients: `encrypt.wkd` and `encrypt.key` are lists (or one value) of
  bare e-mail addresses, compared in lowercase. At least one recipient;
  an address may appear once, in one list only. `key` needs `gpg.keys`,
  an absolute path.
- `key` recipients: every `*.asc`, `*.gpg`, `*.pgp` and `*.key` file of
  `gpg.keys` (by default `gpg.d/` next to the main file, like `ssh.d/`;
  a missing directory holds no keys) is parsed (armored or binary whatever the extension, one or
  more keys per file; other files are ignored; an unreadable file is logged and skipped)
  and the keys are found by the e-mail address of their user ids. Never
  the network.
- `wkd` recipients: the Web Key Directory of the address domain, never
  `gpg.keys`. The advanced method
  `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>`
  is used; only when that host does not answer (no HTTP response) the
  direct method `https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>`.
  `<hash>` is the z-base-32 encoded SHA-1 of the lowercased local part.
  The answer is a binary key (armored is accepted too), at most 1 MiB,
  over TLS verified against the system CAs, 10 s per request. The key is
  cached in `<root>/data/gpg-cache/<address>.pgp` and used without a request
  while younger than `gpg.wkd.cache`; after that it is refetched. When the
  refetch fails for any reason but a 404, the stale cached key is used
  and a warning logged. A 404 makes the recipient unusable, as does a
  failed fetch without a cached key.
- A key is usable for an address when it has a valid (self-signed, not
  revoked, not expired) user id with that address and a valid (not
  expired, not revoked) encryption-capable key or subkey now. Every
  usable key found for an address is a recipient.
- Unusable recipients: each is logged (`recipient unusable`, with the
  address and the reason) and the files are encrypted to the others; no
  usable recipient fails the step. `strict: true` fails the step on any
  unusable recipient.
- Every file of the current set is streamed into a binary (not armored)
  OpenPGP message to all usable recipients, `out/<name>.gpg` in the step
  work directory `<root>/data/work/<id>/<pipeline>/<step>/` (with `in/` as in
  a run step); the encrypted files are the set of the next step. The
  per-file meta is carried over and extended with `"encryption": "gpg"`,
  `"recipients"` (the primary key fingerprints, uppercase hex) and
  `"plain": {"name", "size", "sha256"}` of the input file; a store keeps
  it under `meta` of the sidecar as for a run step.
- The pipeline `timeout` does not apply; stopping lukd interrupts the step
  like a run step.
- Decrypt with the secret key of any recipient:
  `gpg --output f.txt --decrypt f.txt.gpg`. The decrypt commands for every
  case are in [encryption.md](encryption.md).

#### Insecure options (legacy)

`encrypt.insecure` adds password based encryption for receivers that
cannot use an OpenPGP key. It is very insecure and exists only for such
legacy receivers; nothing new should use it. The passwords sit on the
server (anyone who reads `password.d` decrypts the files), a password is
only as strong as it is long and random, and the `openssl` format has no
integrity check. The key reads as a warning in the configuration on
purpose.

```yaml
      - encrypt:
          key: [backup@example.com]
          insecure:
            symmetric: [receiver-a]          # passwords that also decrypt the .gpg files
            openssl:
              key: receiver-a                # one password
              files: ['*-latest.sql.zst']    # globs on the file name as it enters the step
```

- Passwords: `password.d/<name>` next to the main file
  (`/etc/site/lukd/password.d/receiver-a`), owned `root:luk`, mode 0640
  (the directory 0750). The content is the password, one line: one
  trailing newline is stripped, spaces are part of it, and a `\r` or a
  further newline is an error (both decrypt commands read the first line
  only). An empty file, or one over 4096 bytes, is an error. lukd reads
  the passwords when the step runs, so a changed file takes effect with
  the next run, without a reload; a missing or empty one fails the step.
  Only the process role reads them: `lukd-receive.service` and
  `lukd-run@.service` hide `password.d` (`InaccessiblePaths=`), and a
  job of lukd run never sees the configuration directory (see Jobs with
  other users). The run programs of the process role share its user and
  can read them.
- Recipients stay required: `insecure` adds to the keys, never replaces
  them. The recipients are looked up only when the set has a file for the
  `.gpg` path.
- `symmetric`: every password adds one symmetric-key encrypted session
  key packet to the same `.gpg` file, next to the recipients' keys: any
  recipient key or any of the passwords decrypts it. The password is
  turned into a key with the iterated and salted S2K with SHA-256
  (16777216 bytes hashed), which every OpenPGP implementation reads,
  GnuPG 2.4 among them; the password decrypts without a gpg agent. The
  meta of the file gets `"passwords"`: the names (never the passwords),
  next to `"recipients"`. Key holders: gpg tries the password packet
  first, so a script decrypting with a key needs `--pinentry-mode cancel`
  (see [encryption.md](encryption.md)).
- `openssl`: a file whose name (as it enters the step) matches one of
  the `files` globs (`path.Match`: `*`, `?`, `[...]`, never across a
  slash) is written only as `out/<name>.enc`, never as `.gpg`, in the
  format of `openssl enc -aes-256-cbc -pbkdf2 -salt` (OpenSSL 1.1.1 and
  3.x): `Salted__`, an 8-byte random salt, then AES-256-CBC with PKCS#7
  padding; key (32 bytes) and IV (16 bytes) are PBKDF2-HMAC-SHA256 of the
  password and the salt, 10000 iterations. The file is streamed, never
  held in memory. The format has no integrity check: a changed or
  truncated file decrypts to garbage, or fails only on the padding of the
  last block; check the plain `sha256` of the meta after decrypting.
  Files that do not match take the `.gpg` path. The meta of an `.enc`
  file is `"encryption": "openssl"`, `"passwords": [<key>]` and `"plain"`
  as for `.gpg` (no `"recipients"`).
- Decrypt commands: [encryption.md](encryption.md). The openssl
  command reads at most 1023 bytes from `-pass file:`, so the
  password named by `insecure.openssl.key` must not be longer than that
  (without the trailing newline); the encrypt step and `lukd check`
  reject a longer one. The passwords of `symmetric` keep the limit of
  4096 bytes. A password file holds one line: more than one line is
  rejected, as both decrypt commands read the first line only.

## Storage and catalog

- `local` - files under `base`, path from the required `path` template
  (Go text/template): `.Sender`, `.Endpoint`, `.Year`, `.Month`, `.Day`, `.Hour`,
  `.Minute`, `.Seconds` (the receive time in UTC, zero-padded: `2026`,
  `10`, `03`, `14`, `05`, `09`; one moment for every store of an upload),
  `.Id`, `.Random` (fixed per upload and storage; see `random` below),
  `.File` (the client `file`, or the id when empty), `.Tags` (joined with `-`),
  `.Hostname` (the client `backup.hostname`, set by `--backup`; empty
  without it) and `.Origin` (`.Hostname` when set, else `.Sender`).
  Without `backup.hostname` on the endpoint the hostname is only what
  the signer asserts. With it (see Capabilities) a signer of `principal`
  sends only a principal of its own certificate, so `.Hostname` and
  `.Origin` are trustworthy: the host the CA certified, or the sender.
  The result must be a relative path (not absolute, no NUL byte) whose
  elements are names: `.` and `..` are refused, while a leading dot is a
  name like any other (`.bashrc`, `.env`, even `.db` or `.luk`: the data
  tree holds nothing else, see Layout). Other empty elements (`a//b`, a
  trailing `/`) are cleaned away, but an empty `.Hostname` that leaves an
  empty element (for example `{{ .Hostname }}/{{ .File }}` without
  `--backup`) makes the path invalid. A path that cannot be built fails
  the upload with 422 before the body, naming the storage and why
  (`storage path "a/..": element ".." is not a name`).
- `random` (local only) - the characters of `.Random`. Without it
  `.Random` is 32 characters drawn from
  `aAbBcCdDeEfFgGhHjJkKmMnNpPqQrRsStTuUvVwWxXyYzZ23456789` (letters and
  digits without the look-alikes i, l, o, 0, 1; about 184 bits).
  `random.alphabet` sets the characters, drawn uniformly
  from crypto/rand (rejection sampling, no modulo bias); it has at least 2
  characters, none repeated, all from `A-Z a-z 0-9 _ ~ -` (never `.`, so
  a random name is never a dotfile). `random.length` (at most 128) sets
  the number of characters; the default is the shortest length with at
  least 128 bits, ceil(128 / log2(len(alphabet))), and a shorter length
  is refused with its bits and the minimum. A length without an alphabet
  draws from the default alphabet (minimum 23). The values are
  drawn when the upload is accepted, so the answered URL and the stored
  name agree across a reload; a reload applies to new uploads.
  An upload with `pretty_url` replaces `.Random` of every storage with
  one proquint (see `endpoint.<n>.pretty`).
- `ttl` (local only) - the lifetime policy:
  - `ttl.user` (default `false`) - whether the client `ttl` counts here.
  - `ttl.min` - the lowest client `ttl`; only with `ttl.user: true`.
  - `ttl.max` - the highest client `ttl` (with `ttl.user`) and the
    lifetime of an upload without one; without `ttl.user`, the lifetime
    of every upload (a fixed lifetime).

  The lifetime per storage: with `ttl.user` and a client `ttl`, that
  `ttl` clamped to `[ttl.min, ttl.max]` (a missing bound does not limit;
  clamping is not an error); with `ttl.user` and no client `ttl` or the
  client `ttl` `max`, `ttl.max`; without `ttl.user`, `ttl.max` whatever
  the client asks (`max` included, noted `ignored`). No
  lifetime (no `ttl.max`, and no client `ttl` that counts) means the
  file never expires. The expiry is computed when the upload is
  received, for every storage a matched pipeline stores into (the
  respond storage of `respond: url` included), whatever the `respond`:
  each stored copy carries the expiry of its own storage in its sidecar
  `expires`, and the 201 answer carries the one of the respond storage,
  with the `ttl` fields (see Response). A `once` upload is removed
  after the first download or at its expiry; `once` is a download count,
  independent of the policy.

  ```yaml
  storage:
    drop:
      ttl: {user: true, min: 1h, max: 7d}   # the client picks, within bounds
    archive:
      ttl: {max: 21d}                       # fixed; the client ttl is ignored
  ```
- `cleanup.age` (local only, e.g. `14d`) - the retention of files without
  an expiry: they are removed once their `received` time is older,
  exposed or not (an archive too). Files with an expiry are left to it.
- `retention` (local only) - rules that keep a number of files per series
  (grandfather-father-son), and optionally every file of a recent window,
  and prune the rest:

  ```yaml
  storage:
    archive:
      type: local
      base: storage/archive
      path: "{{ .Origin }}/{{ .Year }}/{{ .Month }}/{{ .Day }}/{{ .File }}"
      retention:
        - origin: ["db1-prod", "*-prod"]          # globs (path.Match) on the origin
          keep: {last: 3, daily: 14, weekly: 8, monthly: 12, yearly: 2}
        - origin: ["*-stage"]
          keep: {daily: 7, within: 2d}            # and everything of the last 2 days
        - keep: {daily: 7, weekly: 4}               # no origin: every other origin
  ```

  - A series is the stored files of one pipeline, origin and file name:
    the sidecar `pipeline` (the pipeline whose store step stored the
    file), the sidecar `origin` (the `.Origin` of the upload: its backup
    hostname when sent with `--backup`, else the sender) and the file name
    (the name a run step produced, else the client `file`). A sidecar
    written before these fields has no `pipeline` (an empty one) and
    takes the backup hostname of its client meta, else the sender, as its
    origin. Aliases are not files of a series.
  - The first rule whose `origin` globs match the origin of the series
    applies; a rule without `origin` matches every origin. A series no
    rule matches is never pruned by retention.
  - The time of a file is its sidecar `received` (server time); the
    buckets are in UTC: the day, the ISO week (`2026-W40`), the month and
    the year. A file whose `received` cannot be read is kept and takes no
    place in the counts.
  - Selection, per series, newest first (by acceptance order, see
    Acceptance order, then by id and name): `last` keeps the newest
    `last` files; `daily`, `weekly`, `monthly` and `yearly` each walk
    the files from the newest and keep the first file of each distinct
    bucket (of its `received` time) until that many buckets are kept (a
    bucket without files counts for nothing, so gaps reach further back;
    a bucket met again further down, a file received earlier but
    accepted later, is not counted twice). `within` (a duration, `2d`, `36h`) keeps every file received
    at most that long before now, whatever the counts. The kept set is
    the union; every other file of the series is pruned. Each count is 0
    or more and a rule has at least one count or `within` above 0.
    Without `within` the selection depends on the files and the rules
    only, not on the current time.
  - A storage with `retention` stores with `conflict: version` (the
    default) or `reject`; `replace` is refused, since it overwrites a
    stored path at once and so bypasses retention.
  - Retention works next to `ttl` and `cleanup.age`: a file goes when any
    of them removes it.
  - The maintenance of the process role applies the rules (see Service)
    whenever the base or the rules changed since its last pass, or a file
    that pass kept for `within` has left its window since (the pass
    remembers the earliest moment one does, so a file pruned once its
    window ends goes within a minute, the maintenance interval): each
    pruned file is removed as `lukd storage rm` removes it (base lock,
    sidecar, the alias moved to the next newest declarer, content
    objects, emptied directories), only while its sidecar still has the
    id of the plan, so a file replaced meanwhile is kept; claimed `once`
    files and files being written are not in the data tree and are never
    pruned. The catalog is rebuilt once after the pass. Each removal is
    logged at INFO: `retention removed` with `storage`, `name`, `id`,
    `pipeline`, `origin`, `file` and `rule` (1-based).
  - `lukd storage retention` shows the plan without changing anything.
- `watch` (local only) - monitoring rules of the series (as in
  `retention`: pipeline, origin and file name), with thresholds that are
  only the configured values (nothing is learned or adapted):

  ```yaml
  storage:
    archive:
      watch:
        - origin: ["db1-prod"]            # globs on the origin; absent: any origin
          file: ["db.sql*"]               # globs on the file name of the series; absent: any
          every: 26h                      # newest copy older than this: CRIT
          size: {min: 2G, max: 20G, step: 500M}
          same: 3                         # this many newest copies with one sha256: WARN
        - origin: ["*-stage"]
          every: 50h
          size: {min: 100M}
  ```

  - The first rule whose `origin` globs match the origin and whose `file`
    globs match the file name of a series applies (path.Match; an absent
    list matches anything). A series no rule matches is not watched.
  - The copies of a series are its stored files whose `received` can be
    read, newest first (by acceptance order, see Acceptance order); the
    newest copy is the first. The checks, each
    only when set:
    - `every` (a duration): the newest copy was received longer than
      `every` before now: CRIT (`last copy 31h ago (every 26h)`);
    - `size.min`, `size.max`: the size of the newest copy is below
      `min` or above `max`: CRIT (`980M below min 2G`, `25.5G above max
      20G`);
    - `size.step`: the size of the newest copy differs from the one
      before it by more than `step`: WARN (`grew by 1G to 5G (step
      500M)`, `shrank by 1G to 3G (step 500M)`); one copy passes;
    - `same` (2 or more): the `same` newest copies have one known sha256:
      WARN (`last 3 copies identical (sha256 0123456789ab)`).
    A series without a copy (only unreadable `received`) is CRIT (`no
    copy with a readable received time`).
  - All checks of the rule combine: the state is the worst, and the
    message names the series and every failed check, CRIT ones first,
    sizes in K, M, G, T (`db1-prod/db.sql: 980M below min 2G; last copy
    31h ago (every 26h)`). A series that passes is OK with the age and
    size of its newest copy (`db1-prod/db.sql: last copy 3h ago, 4.1G`).
  - A rule no series matches (none at all, or every match taken by an
    earlier rule) is WARN: `rule 2 (origin *-stage): no series matches`.
  - The process role evaluates the rules of every storage after each
    maintenance pass (every minute) and after each pipeline that stored
    a file into a storage with `watch`, and writes the result to the
    `watch` section of `status.json` (see Status); `lukd status` shows
    it, the checkmk check makes a service of each record.
  - With `dedup` (see below) an upload identical to the newest version
    of its path places no new copy, so `every` keeps counting from the
    stored one and `same` sees no repeat; with a path per upload (a
    date or `.Id` in `path`) every upload is a copy of its own.
  - `lukd storage watch` shows the evaluation and, with `--suggest`,
    values observed on recent copies as hints for the thresholds.
- The janitor covers every local storage, exposed or not: the expiry
  pass (expired files, `cleanup.age`, stale claimed files, every minute)
  runs in the receive role, the maintenance (retention, aliases, catalog,
  content objects, crash leftovers, empty directories) in the process
  role (see Service).
- `protect` (local only) - the expose with `auth.ssh` that serves the
  private files of the storage (see Private files). The `expose` itself
  may have `auth.ssh` too (see Signed expose).
- `s3` - bucket + prefix template. Not implemented yet: the type is
  accepted, but a `store` step to an s3 storage is a config error
  (`pipeline <p>: step <n>: storage <s>: s3 storage is not implemented
  yet`).
- Layout: a local `base` holds two directories and nothing else:

  ```
  <base>/file/            the stored files, under their stored names (and nothing else)
  <base>/.db/lock         the base lock and generation (see Service)
  <base>/.db/replace      the record of a replace between its renames (see replace)
  <base>/.db/meta/        the sidecars: meta/<path on disk under file/>.json
  <base>/.db/objects/     the content objects and their indexes (hardlink)
  <base>/.db/catalog.json the catalog (catalog)
  <base>/.db/claimed/     once files taken out of file/ while they are downloaded
  <base>/.db/tmp/         temporary files: staged copies, files written before their rename
  <base>/.db/permanent/   the permanent names: <path>/<name>/current/ (see Permanent names)
  ```

  Every stored name maps to `file/<name>` (with `shard`, under its hash
  directories), so any name is free for the uploads: dot names
  included, none of them can reach `.db/`. `file/` and `.db/` lie on the
  one filesystem of the base, so hardlinks (objects, versions, aliases,
  claims) and the renames from `.db/tmp/` into place keep working; every
  temporary file is synced before its rename and the directory after it.
  The receive and process roles create both directories (mode 0750) at
  start and on a reload, and refuse a base that holds anything else at
  its top (a base of an older layout, or a directory that is no storage
  base): `storage <n>: <base>: holds .luk, .luk-lock besides .db/ and
  file/: not a storage base of this layout (move its content away and
  empty it)`. `lukd check` and `lukd storage` report the same. There is
  no migration of an older layout. Stored names are refused when empty,
  absolute, holding a NUL byte or an empty, `.` or `..` element, or when
  an existing symlink lies along them, each with that reason.
- Writes are atomic (temporary name in `.db/tmp/`, then rename).
- Empty directories are removed: every removal of a stored file (expiry,
  `once` claim, remove, failed store) removes the directories it leaves
  empty, in the data tree and in the sidecar tree, up to but never
  including `file/` and `.db/meta/` themselves, under the base lock a
  store holds from creating its directories to placing its files. Only
  empty real directories go (rmdir, never a symlink). The periodic
  maintenance prunes any other empty directory of both trees bottom-up,
  dot names included; the other directories of `.db/` stay.
- A local `base` is one filesystem (no mount points inside, `file/` and
  `.db/` included) and one lukd process owns it. Bases never overlap each other, an endpoint queue or
  a secret queue
  path; the config check refuses that.
- `shard: N` (0-4, default 0) spreads a local storage over N levels of
  directories named by the first hex pairs of sha256 of the stored name
  (`ab/cd/<name>` for N = 2). It is transparent: names in URLs, the
  catalog and aliases stay the stored names; only the files on disk are
  placed deeper. Use it for flat names such as a drop's random names,
  where one directory would otherwise hold every file
  (`file/ab/cd/<name>`). The sidecar mirrors the path on disk under
  `file/` (`.db/meta/ab/cd/<name>.json`).
- Every stored file has a sidecar with its meta in a mirror tree:
  `<base>/.db/meta/<stored path>.json` - client meta (original `file` name,
  `type`, `ttl`, `once`, `portal`, tags) and server meta (id, sender,
  size, sha256, received, `accepted` and `accepted_seq` (see Acceptance
  order), expires, `owner` unless `no_owner`, `owner_key`,
  `pipeline` and `origin` of the store (see `retention`), `updated` after
  a replace). Keeping sidecars out of the data tree
  means an uploaded `x.json` can never collide with the sidecar of `x`,
  and expose never serves anything under `.db/`. A drop stores the blob
  as `<base>/file/<random>`; two uploads with the same `--name` get two
  independent random names.
- `conflict` - what a write does when the target path exists:
  `version` (default; keep both: `<name>` holds the content of the
  newest upload by acceptance order, and the previous content is renamed
  to `<name>.<unix ts>`,
  the ts being that previous version's own `received` time from its
  sidecar (its data mtime when it has none), then `<name>.<unix ts>.000001`
  and so on when that name is taken, so the name tells when the old
  version arrived), `reject` (the pipeline fails, visible in status),
  `replace` (atomic overwrite; for deliberate cases such as aliases).
  Newest is by acceptance order: an upload accepted before the stored
  file is placed as a version under `version` and skipped under
  `replace` (see Acceptance order).
  A `version` store runs under the base lock in an order that never
  loses data: first the old data is hardlinked (not renamed) to its
  versioned name and its sidecar is copied there unchanged (same
  version); only then the new data is renamed over `<name>` and the new
  sidecar is written, so the old link at `<name>` goes only by that
  rename. A crash after the first step leaves both names of the old
  version; the retry recognises that versioned copy (same inode and
  sidecar) and does not version it twice; a crash between the new data
  and its sidecar is finished by the retry too. A versioned name is a
  name of its own: with `shard` it lies under its own hash, on the same
  filesystem. An alias on the old version is re-evaluated (the newest
  declarer by acceptance order keeps it, as always), and the catalog, rebuilt
  once per store, lists every version.
- `dedup` (default `true`, only with `conflict: version`) - when the
  target path exists, it (the bare name, always the newest version) is
  compared by size and sha256 from its sidecar with the incoming file (no
  re-hashing).
  When they match nothing is placed: the store keeps the existing file,
  sidecar (it only takes the acceptance order of a newer upload, see
  Acceptance order), aliases and catalog, and the pipeline logs
  `deduplicated` with
  the existing path (`<storage>:<path> (dedup)` in its stored list); it
  counts as a success. Only the newest version is compared, so A, B, A
  keeps three files (`<name>` is A, with two dated versions). Once, portal and expiring files are never shared.
  Dedup happens only at store time: the upload is received and the
  pipeline runs as usual. `dedup: false` always adds a version.
- `hardlink` (default `true`, local only) - one copy of each content on
  disk. The storage keeps content objects in `<base>/.db/objects/`,
  outside the data tree (no stored name can collide with it):
  `ab/cd/<sha256>` is a hardlink of the stored
  files with that content (`ab` and `cd` the first hex pairs of the
  sha256), and `ab/cd/<sha256>.json` the index of the stored names
  holding it, each with its `owner_key` and the id of its upload
  (`{"size", "names": {"<stored name>": "<owner_key>"}, "ids": {"<stored
  name>": "<upload id>"}}`, for the transfer dedup, see Transfer dedup,
  and `links.max`).
  - Store: when the object of the file's sha256 exists (a regular file of
    the file's size), the new name is a hardlink of it (linked to a
    temporary name, then placed by the rules of `conflict` like any store)
    instead of the data; otherwise the data is stored as before and then
    linked as the object. Sidecars stay per name: expiry, `once`, owner,
    `access`, portal and file name of each upload are its own. Unlike
    `dedup`, every upload keeps its own name and sidecar: the space is
    shared, the names are not.
  - Removal of a name (expiry, `cleanup.age`, `retention`, `lukd storage rm`, `luk link
    --rm`, the end of a `once` claim) only unlinks that name and drops it
    from the index; a version rotation moves the old content's name in the
    index to the version. The maintenance removes an object whose only
    link is its own, with its index; a claimed copy being downloaded or a
    queue entry still holding the content keeps it.
  - A `once` claim renames only the claimed name, so the other names of
    the content stay. A replace through the link (`luk link --file`,
    `--stdin`) renames a new file over the name: only that name leaves the
    shared inode (the new content links to its own object).
  - Objects and indexes change under the base lock, as a mutation (the
    generation grows).
  - The maintenance of the process role reconciles the objects with the
    sidecars whenever the base changed since its last run: a stored file
    whose content has no object becomes the object (its sha256 and size
    come from the sidecar, nothing is hashed; a file whose size differs
    from its sidecar is not taken), so files stored before, or with
    `hardlink: false`, dedup the stores after them; every index is rebuilt
    from the sidecars; indexes without an object go (temporary files of
    `.db/tmp/` older than an hour go with the crash leftovers).
    Files that already hold the same content as separate copies stay
    separate.
  - Stored files are immutable (written once, replaced only by rename), so
    a shared inode is invisible to downloads.
  - `hardlink: false` stores separate files; the maintenance removes
    `.db/objects/` of that storage.
- `links.max` (default 100, `0` is the default, at least 1; local only) -
  the most stored names holding one content (sha256) that one identity
  (`owner_key`) may have in the storage. The count is the names of that
  owner in the index of the object (see `hardlink`) plus the committed
  queue entries of that owner with that content in the queue the upload
  goes to whose upload id the index does not list yet, so a burst of
  uploads cannot overshoot it and an upload stored while its entry is
  still queued (later steps running, or the entry not removed yet) counts
  once. The queue is read before the index, so an upload stored in
  between is not counted twice either.
  Expired, removed and claimed names no longer count; other identities
  are counted on their own.
  - At acceptance: an upload whose signed meta carries `size` and `sha256`
    and whose pipelines store it into the storage (a `store` step before
    any `encrypt` step and any `run` step without `tee`; `relay` steps
    pass the upload on) answers 429 `limit of <N> links to the
    same content reached` before the body, before the transfer dedup
    answers and in a dry run too; nothing is stored.
  - At store, for content whose hash was not known up front (a stream):
    a store step that would add one name more fails for that storage with
    the same message, like any store failure (see Failures). A replace through the link into that content counts too; a
    store over the same name without versions (`conflict: replace`) does
    not add one.
  - Only storages with `hardlink` keep the index and enforce the limit;
    with `hardlink: false` it is not enforced.
- Each storage has a generic `catalog.json`, built by lukd from the files
  and their `.meta.json`, rebuilt after every `store` and every cleanup:
  server fields at the top level (`name`, `size`, `sha256`, `created`,
  `tags`), pipeline meta nested under `meta`. The sender is not listed:
  the catalog is served to whoever its expose serves the public files
  (also signed requests on an expose with `auth.ssh`, see Signed
  expose); a protect expose never serves it.
- `alias` in a file's meta: lukd keeps a hardlink `<alias>` to the newest
  file declaring it (by acceptance order, see Acceptance order), and a `latest` map (`alias -> name`) in the catalog.
  The alias goes when its target goes.

### `lukd storage`

Admin commands on the files of a local storage, read from their sidecars
(an `s3` storage is refused: `storage <n> is not a local storage (s3)`).
They read the config given by `-c` and work on files, without the daemon
or while it runs. The files must stay owned by the service user, so they
run as the owner of the storage `base`: as root they run again as that
owner, as `lukd queue` does for `root`; any other user gets `lukd storage
must run as root or as <owner> (owner of <base>)`. A `base` that is a
symlink is refused (`lukd storage: <base> is a symlink`).

- `lukd storage ls --storage NAME [--owner IDENTITY] [--older DURATION]
  [--json]`: the stored files, newest first (by acceptance order), as aligned
  columns `NAME`, `SIZE` (bytes), `RECEIVED`, `EXPIRES`, `OWNER` (the
  display name of the sidecar), `OWNER KEY`, `ENDPOINT`, `FLAGS` (`once`,
  `mutable`, then `reveal` or `download`, then `private` or `any`, then
  `shared` when other names hold the same content as hardlinks: other
  uploads through `hardlink`, versions, aliases, claimed copies), and
  `URL` (the expose URL of the name; for a private file the `luk://` URL
  of the protect expose, and for a file of an `expose` with `auth.ssh`
  the `luk://` URL of that expose (`https://` with `auth.basic` too),
  with the pin when the certificate
  file is readable) when the storage has an `expose` or a `protect`; `-` for an
  empty value. Aliases
  and claimed files are not listed. `--owner` keeps the files whose
  `owner_key` is the identity: a key name (`robert.socha` for
  `key:robert.socha`) or the full owner key (`key:<name>`,
  `cert:<ca>:<keyid>`). `--older` keeps the files received longer ago
  than the duration (`7d`, `12h`). `--json` prints an array of the full
  records: `name`, `url` (when exposed), `links` (the number of names
  holding the content: the hardlinks of the file less its object) and
  every sidecar field. Sidecars
  that cannot be read are reported after the list (exit 1).
- `lukd storage rm --storage NAME --name STORED [--name STORED]... [--yes]`:
  removes each stored file and its sidecar under the base lock, as the
  link remove does (the empty directories pruned, an alias moved, the
  catalog rebuilt). Every name is checked first and nothing is removed
  when one fails: an invalid name (see Layout) or one through a symlink
  is refused with the reason (`--name "../x": refused: "../x": element
  ".." is not a name: invalid path`), an unknown one (no file or no
  sidecar) and an alias (`"<name>" is an alias of "<target>"; remove
  that file`) fail. Without
  `--yes` it lists the files on stderr and asks for confirmation on a
  terminal (`[y/N]`), and refuses when stdin is not one. A file replaced
  between the check and the removal is kept. Prints `<name>: removed`
  per file.
- `lukd storage retention --storage NAME [--json]`: the retention plan
  (see `retention`), read only. Per series, in order of pipeline, origin
  and file name, a line naming the series and the rule that applies,
  then its files newest first as aligned columns `NAME`, `RECEIVED`,
  `ACTION` (`KEEP` or `PRUNE`) and `REASONS` (`last`, `within`, `daily
  2026-10-04`, `weekly 2026-W40`, `monthly 2026-10`, `yearly 2026`;
  `no rule` for every file of a series no rule matches, `received
  unreadable`; `-` for a pruned file). An empty pipeline or origin shows
  as `-`.

  ```
  series pipeline=nightly origin=db1-prod file=db.sql: rule 1 (origin db1-prod,*-prod; keep last 1, daily 2)
    NAME                        RECEIVED              ACTION  REASONS
    db1-prod/db.sql             2026-10-04T18:00:00Z  KEEP    last, daily 2026-10-04
    db1-prod/db.sql.1759550400  2026-10-04T06:00:00Z  PRUNE   -
    db1-prod/db.sql.1759464000  2026-10-03T06:00:00Z  KEEP    daily 2026-10-03

  series pipeline=nightly origin=db1-stage file=db.sql: no rule
    NAME              RECEIVED              ACTION  REASONS
    db1-stage/db.sql  2026-10-04T06:00:00Z  KEEP    no rule
  ```

  `--json` prints an array of the series: `pipeline`, `origin`, `file`,
  `rule` (1-based, omitted for none), `keep` (the counts of the rule,
  `within` as in the configuration, `"2d"`) and
  `files`, each with `name`, `id`, `received`, `keep` (true or false) and
  `reasons`. Sidecars that cannot be read are reported after the plan
  (exit 1).
- `lukd storage permanent --storage NAME [--json]`: the permanent
  names of the storage (the directories of `.db/permanent/`), read only,
  by key: aligned columns `PATH` and `NAME` (as published; the key when
  nothing can be read), `CURRENT` (the stored name of the current
  version), `RECEIVED` and `EXPIRES` (of that
  version, `never` without an expiry) and `ORPHAN` (`ORPHAN` for a name
  the configuration does not allocate, see Permanent names, else `-`).
  An empty name (its version gone) shows `-` as `CURRENT`, `RECEIVED`
  and `EXPIRES`. `--json` prints an array of `key`, `path`, `name`,
  `current`, `id`, `received`, `expires` (the last four omitted when
  empty) and `orphan`.
  `--prune [--yes]` removes the directories of the orphans and of the
  empty names (allocated, an empty directory) under the base lock, each
  only while it is
  still an orphan or empty, printing
  `<path>/<name>: removed` per name; without `--yes` it lists them on
  stderr with their current versions and asks on a terminal (`[y/N]`),
  and refuses when stdin is not one. The versions stay: they are
  ordinary stored files that expire, are pruned by retention or removed
  with `lukd storage rm`. Neither role ever removes an orphan.
- `lukd storage watch --storage NAME [--json] [--suggest]`: the
  evaluation of the watch rules (see `watch`) now, read only. First the
  rules (`rule <i>: <globs>: <checks>`), then, per series in order of
  pipeline, origin and file name, aligned columns `STORAGE`, `SERIES`
  (`<origin>/<file>`), `PIPELINE`, `RULE`, `STATE`, `NEWEST` (received
  of the newest copy), `SIZE` (its size), `COPIES` and `MESSAGE`; a
  series no rule matches shows `-` as rule and state and `not watched`,
  a rule no series matches follows with `-` as series. `--suggest` adds
  a table of hints, clearly labelled as such: values observed on the
  newest 30 copies of each series (`COPIES`, `NEWEST SIZE`, `MIN SIZE`,
  `MAX SIZE`, `MAX STEP` between neighbours, the median `INTERVAL`
  between copies with `MIN INTERVAL` and `MAX INTERVAL`, and `SAME`, the
  newest copies with the content of the newest). They help to choose
  thresholds; lukd never uses them as thresholds.

  ```
  rule 1: origin db1-prod; file db.sql*: every 26h, size.min 2G, size.step 500M
  rule 2: origin *-dev: same 2

  STORAGE  SERIES           PIPELINE  RULE  STATE  NEWEST                SIZE  COPIES  MESSAGE
  archive  db1-prod/db.sql  nightly   1     CRIT   2026-10-03T05:00:00Z  980M  3       db1-prod/db.sql: 980M below min 2G; last copy 31h ago (every 26h); shrank by 2G to 980M (step 500M)
  archive  web1/db.sql      nightly   -     -      2026-10-04T11:00:00Z  1M    1       not watched
  archive  -                -         2     WARN   -                     -     0       rule 2 (origin *-dev): no series matches

  HINTS: observed on the newest 30 copies of each series; not thresholds
  SERIES           PIPELINE  COPIES  NEWEST SIZE  MIN SIZE  MAX SIZE  MAX STEP  INTERVAL  MIN INTERVAL  MAX INTERVAL  SAME
  db1-prod/db.sql  nightly   3       980M         980M      2.9G      2G        24h       24h           24h           1
  web1/db.sql      nightly   1       1M           1M        1M        0         -         -             -             1
  ```

  `--json` prints an array of the rows: the fields of a `watch` record of
  `status.json` (`state` empty and `rule` 0 for a series no rule
  matches) and, with `--suggest`, `hints` (`copies`, `newest_size`,
  `min_size`, `max_size`, `max_step`, `interval`, `min_interval`,
  `max_interval`, `same`). Sidecars that cannot be read are reported
  after the rows (exit 1).

## Expose

- `GET <url><name>`; `auth` optional (none = anonymous, `basic` = htpasswd
  bcrypt, `ssh` = signed `luk-get@v1` requests for private files, see
  Private files; `basic` and `ssh` together = either, see Signed
  expose). The bcrypt checks of `basic` run at most one per CPU
  at once; a request waits for its turn, so wrong passwords cost the
  server no more than its CPUs.
- `--once`: on the first download lukd renames the file to "claimed"
  atomically before serving it; a concurrent second download gets 404.
- Portal (`portal` `reveal` or `download` in the meta; `direct` serves the
  content on `<url><name>`): `<url><name>` never serves the content but
  an HTML landing page, so link previews do not consume a `--once` upload;
  only the button request counts as the download.
  - `reveal` (`--secret`): the landing page has a "reveal" button that
    shows the content on the same page (a `fetch` of `<url><name>/reveal`
    asking for `text/plain`); without script it posts to
    `<url><name>/reveal`, which answers an HTML page with the content and
    a copy-to-clipboard button. Its metadata shows the type as `secret`
    and no sha256: a short secret could be found from its hash by anyone
    who sees the landing page, without opening it.
  - `download` (`--portal`): the landing page shows the metadata (name,
    content type, size, sha256, published, expiry) and a "download" button;
    `<url><name>/download` answers the content with the download headers
    below.
  - `<url><name>/get` answers the raw content of either portal for
    scripts and terminals (Phase 6).
  What the content is (plain or encrypted by kufer) is not lukd's concern.
- TTL and retention belong to the storage (`storage.<n>.ttl`,
  `storage.<n>.cleanup.age`, see Storage); an expose only serves the
  files until the janitor removes them. An expired file not removed yet
  answers 404.
- `GET` and `HEAD` on `<url><path>/<name>`, `<path>` being the
  `permanent.path` of an endpoint storing into the storage, serve the
  current version of that permanent name (see Permanent names).
- `GET` and `HEAD` on `<url><name>`: `<url>x` is `<base>/file/x`, so
  `<name>` may contain `/` (archive trees) and dot names (`.bashrc`) and
  never reaches `.db/`; an empty, `.` or `..` element is 404. `Range` is
  supported, except for `once` uploads.
- Directory listing (`expose.<n>.index: true`): `GET` and `HEAD` on a
  directory URL (`<url>` and `<url><dir>/`) answer an HTML page built
  from the disk on every request (it does not use the `catalog`); a
  directory URL without its slash (`<url>` without it too) redirects
  `301` to the slash form, with a relative `Location` (`./<dir>/`).
  An expose with `index` never serves a storage with `shard` (a config
  error, see Server configuration).
  Without `index` a directory URL is 404, as before.
  - Lines: `../` in a subdirectory, then the directories, then the
    files, each sorted by name ignoring case (`B` between `a` and `c`;
    names equal but for case in byte order, `Readme` before `readme`).
    Columns: the name (a link, each name URL-escaped and relative,
    `./<name>`, `./<dir>/`), the size (`512 bytes`, `1.5 MiB`) and the stored time (the `received`
    time in UTC to the minute, turned into the viewer's local time by
    the page script as on the portal pages); a directory has neither.
  - Listed: exactly the names a `GET` serves as a file, less the ones
    the catalog leaves out: never `once`, portal (`reveal`,
    `download`) or private (`access`) uploads, expired files, claimed
    files, files without a sidecar, symlinks, `catalog.json` (with
    `catalog`) and the directories of nested exposes. Dot names are
    listed like any other (the listing reads `file/` only). A directory
    is listed only when it holds a listed file at any depth; one without
    (missing, empty) is 404 like a missing name, `<url>` itself
    answers an empty listing.
  - The page is a portal page: the same look, favicon, footer and
    headers (`Content-Security-Policy`, `noindex`, `no-store`,
    `no-referrer`); names are HTML-escaped. `POST` is 405.
  - Cost: a listing reads the sidecars of its files and, for each
    subdirectory, walks it until a listed file is found.
- Download headers, from the sidecar:
  - `Content-Disposition: attachment; filename="<file>"` (the stored
    name when `file` is empty);
  - `Content-Type`: `type` from the meta when given, else by the
    extension of `file` (`mime.TypeByExtension`), else
    `application/octet-stream`. The content is never sniffed;
  - `X-Content-Type-Options: nosniff` and
    `Content-Security-Policy: sandbox`.
  The content comes from the uploader and is served from lukd's own
  domain, so a browser must never render it there (an uploaded
  `text/html` would run in the same origin as the portal). Only the
  portal pages render HTML, and they are lukd's own templates.

## Listeners

Intake and download are separated by named listeners. An upload endpoint
and an expose each name the listener they live on, so every pipeline can
publish under its own path or its own domain, and uploads and downloads
can use different addresses.

```yaml
listen:
  intake:
    addr: 0.0.0.0:8443
    host: [lukd.vm]
    tls: {mode: self, cert: tls/tls.crt, key: tls/tls.key, host: lukd.vm}
  drop:
    addr: 0.0.0.0:443
    host: [drop.luk.vm]
    tls: {mode: self, algorithm: ecdsa-p256, cert: tls/drop.crt, key: tls/drop.key, host: drop.luk.vm}
  proxied:
    addr: 127.0.0.1:8081        # plain HTTP behind traefik
    host: [drop.backup.example.net]
    public: https://drop.backup.example.net

endpoint:
  drop:
    listen: intake              # uploads to /drop only on lukd.vm
    endpoint: /drop

expose:
  drop:
    listen: [drop, proxied]     # GET /<name> on drop.luk.vm and via traefik
    path: /
```

- `listen` is a map of named listeners: `addr`, `host` (the names it
  answers for; required when several listeners share an address), `tls`
  (optional), `public` (optional base URL for answers when the listener
  sits behind a proxy; an `http(s)` URL without a path; default
  `https://<first host>[:port]`, or `http://` without `tls`, without the
  default port of the scheme; without `host` the name is `tls.host`,
  else the address host unless it is unspecified, when an endpoint
  answering URLs through it needs `public` or `host`).
- Several listeners may share one address: TLS listeners on it are
  chosen by SNI (each has its own certificate; a client without SNI or
  with an unknown name gets the certificate of the first listener of the
  address by name), and every request is
  routed by its `Host` header (port ignored, case-insensitive) to the
  listener that lists the name. A request for an unknown host is 421.
  Plain listeners sharing an address are routed by `Host` only.
- `endpoint.<n>.listen` and `expose.<n>.listen` name one or more
  listeners (a string or a list). Paths are unique per listener only: an
  expose may use `/` on a listener that carries no upload endpoint.
  Exposes of one listener may nest (`/` and `/volatile/`), never share a
  path, and never overlap an endpoint path: a request goes to the expose
  with the longest path it starts with, the nested path without its
  slash (`/volatile`) to the nested one. The storage of the outer expose
  never holds a name under a nested path (`volatile` and `volatile/...`
  in the storage of `/`, as seen from its `expose` and its `protect` on
  any listener they share with the nested one): a path template or an
  alias rendering to one fails like `catalog.json` (422 before the body,
  naming the storage), and a request for one is 404 on every listener
  of the outer expose. Link URLs (`luk link`, `link ls`) resolve by the
  same longest path (see Links).
  Listeners sharing an address must all be TLS or all plain, with
  disjoint `host` lists. `limits.conn.max` applies per address.
- `/.well-known/luk/endpoints` is the endpoint listing on every listener
  (see Endpoint listing), routed before the endpoints and the exposes.
- A channel request (`POST` with the channel content type, see Channel)
  is routed to the channel before the path is looked at: its handshake
  takes only an endpoint path of the listener and the listing.
- On a listener without upload endpoints nothing is an upload: `GET` and
  `HEAD` go to its exposes, `POST` only to the portal actions
  (`<name>/reveal`, `<name>/download`, `<name>/get`). Any other method,
  or a `POST` to any other path, is 405 with `Allow: GET, HEAD`
  (`GET, HEAD, POST` on an action path), decided by the path alone,
  before the expose and the file are looked up. On a listener with upload
  endpoints, a request other than `GET`, `HEAD` and `POST` to a path that
  is no endpoint is 404 (`no endpoint`). On an endpoint path every
  request outside the channel is 400 (see Carrier). Inside the channel,
  an OP with `Luk-Link` or `Luk-Link-Action` is a link request (see
  Links); without them, any method but `PUT` is 405 with `Allow: PUT`.
- Logging: an unknown host (421), a 404 of an expose and a 405 of a
  listener without endpoints (`method not allowed`) are logged at DEBUG
  (remote, host, method, path). `upload rejected` is logged only on
  listeners with upload endpoints, at INFO, except an unsigned request
  (none of the `Luk-*` signature headers) to a path that is no endpoint,
  which is logged at DEBUG. The HTTP server's own errors (a failed TLS
  handshake, a malformed request) are logged at DEBUG, a handler panic
  at ERROR.
- A signed operation whose host (the host of its session) is not in its
  listener's `host` list is rejected (401) before the body. With the
  session hash in every signed text a signature never verifies outside
  its session anyway; the host check stays as the rule of every signed
  request. A listener without `host` accepts any host (development).
- `expose.url` is replaced by `listen` + `path`; the URL answered for
  `respond: url` is `<public of the first listener of the expose><path><name>`.
- Behind a proxy the proxy must pass the original `Host`; lukd does not
  trust `X-Forwarded-*` headers.
- `tls.mode: acme` listeners get certificates from an ACME CA for the
  names of their `host` list and route by SNI and `Host` like the other
  TLS listeners. HTTP-01 needs a plain listener with `acme: true` (see
  TLS, ACME).

Intake on a self-signed certificate (clients pin the lukd key), downloads for
browsers on a Let's Encrypt certificate:

```yaml
listen:
  intake:
    addr: 0.0.0.0:8443
    host: [lukd.example.com]
    tls: {mode: self, cert: tls/tls.crt, key: tls/tls.key, host: lukd.example.com}
  download:
    addr: 0.0.0.0:443
    host: [drop.example.com]
    tls: {mode: acme, email: ops@example.com}
  http:
    addr: 0.0.0.0:80
    acme: true

endpoint:
  drop: {listen: intake, endpoint: /drop, ...}
expose:
  drop: {listen: download, path: /}
```

`luk` clients of `intake` pin the lukd key (`luk scan --pin
https://lukd.example.com:8443/`, compared with `lukd key`) and do not
verify its certificate; browsers and `curl` reach
`https://drop.example.com/<name>` with normal CA verification.

Endpoints and exposes may share a listener. Its clients then hold two
kinds of pins, never in the same place: the endpoint URL in the luk
config carries the lukd key (see Pins), and the download links of a
`self` or `files` listener carry the SPKI pin of its certificate (see
TLS, Private files).

## Status

The status directory `<root>/data/status/` has one directory per role; each
file has exactly one writer, its role:

```
<root>/data/status/
  receive/alive.json     # receive role
  process/alive.json     # process role
  process/status.json    # process role
```

Each role creates its directory at start (with `status/`, mode 0750,
owned by the service user, checked for writing like the other lukd
directories). A `<root>/data/status.json` of an older release is ignored and
can be deleted.

### Liveness

At start, after it took its lock (see Service), a role writes
`alive.json` once, atomically (temporary file in the same directory,
fsync, rename, fsync of the directory), mode 0640:

```json
{
  "role": "process",
  "started": "2026-10-05T12:00:00Z",
  "version": "0.9.0"
}
```

The mtime of `alive.json` is the heartbeat: the janitor loop of the
role touches it (mtime set to now, content not rewritten) after every
pass and every 30 seconds between passes. That loop does the periodic
work of the role (receive: the expiry pass; process: failure record
expiry, failed counts, queue pickup, storage maintenance, watch
evaluation), so a pass that hangs stops the heartbeat. A file deleted
while the role runs is written again at the next touch.

Contract for readers (monitoring), with age = now - mtime:

- fresh: the role runs.
- stale: the role is dead or stuck.
- missing: the role has not started since the directory was created.

The reader picks the stale threshold: a few heartbeat intervals plus
the longest janitor pass it accepts (the touch waits for a running
pass).

lukd does not interpret the liveness files: no command reads them.

### status.json

The process role writes `status/process/status.json` atomically (and
may serve it as `GET /status` behind auth): an object with
`pipelines`, one entry per
(pipeline, sender), `watch`, the evaluation of the watch rules of
the storages (see `watch` under Storage and catalog), one record per
watched series and per rule no series matches, `units`, the run steps
and lukd run, `queue`, the uploads not processed yet, and `workspaces`,
the leftover workspaces of lukd run:

```json
{
  "pipelines": [
    {"pipeline": "devdb", "sender": "hosts:replica.aws.example.net",
     "tags": ["prod", "devdump"], "last_id": "...", "last_received": "...",
     "last_accepted": 1791100800123456789, "last_success": "...", "last_failure": "...", "failed_step": 2,
     "error": "dbdump exit 1", "size": 314572800, "failed": 0,
     "older_skipped": 0}
  ],
  "watch": [
    {"storage": "archive", "rule": 1, "pipeline": "nightly",
     "origin": "db1-prod", "file": "db.sql", "state": "CRIT",
     "message": "db1-prod/db.sql: 980M below min 2G; last copy 31h ago (every 26h)",
     "newest_received": "2026-10-03T05:00:00Z", "size": 1027604480,
     "copies": 3, "evaluated": "2026-10-04T12:00:00Z"},
    {"storage": "archive", "rule": 2, "pipeline": "", "origin": "",
     "file": "", "state": "WARN",
     "message": "rule 2 (origin *-stage): no series matches",
     "size": 0, "copies": 0, "evaluated": "2026-10-04T12:00:00Z"}
  ],
  "units": {"running": 3, "waiting": 2, "oldest_wait": 140},
  "queue": {"entries": 7, "oldest_id": "20261004T115500Z-0a1b2c3d",
            "oldest_received": "2026-10-04T11:55:00Z", "oldest_age": 300},
  "workspaces": {"leftover": 0, "updated": "2026-10-04T12:00:00Z"}
}
```

`last_id`, `last_received` and `last_accepted` (with `last_accepted_seq`
when not 0) are of the upload accepted last (see Acceptance order); an
entry or result without an acceptance order compares by
`last_received`. `older_skipped` counts the stores of the pipeline and
sender skipped under `conflict: replace` because the stored file was
accepted later (`store: older upload skipped`): uploads that overlap
make a few; a count that keeps growing means new uploads are not kept
(an acceptance order gone wrong, see Acceptance order). It only grows.

A watch record holds `storage`, `rule` (1-based), the series
(`pipeline`, `origin`, `file`; empty for a rule no series matches),
`state` (`OK`, `WARN`, `CRIT`), `message`, `newest_received` and `size`
of the newest copy (`newest_received` omitted without one), `copies`
and `evaluated` (when the process role evaluated it, about every
minute). The `watch` section is replaced by each evaluation; a storage
without rules has no records. lukd reads a `status.json` of an older
release (an array of pipeline entries) and writes the object from then
on.

`units` and `queue` are written with every `status.json` and at least
on every janitor pass (about every minute):

- `units`: `running` the step units of lukd run that started (the `s`
  frame) and did not end, `waiting` the steps waiting for a unit slot of
  lukd run (connected, no `s` frame yet; see `limits.units.max` under
  Jobs with other users), `oldest_wait` the seconds the longest of them
  has waited so far (0 without one). Nested jobs are not counted.
- `queue`: `entries` the committed queue entries whose pipelines have
  not all ended, over every queue directory; `oldest_id`,
  `oldest_received` and `oldest_age` (seconds since its `received`) of
  the oldest of them by acceptance order, omitted without one.
  `oldest_age` is how long files wait unprocessed: the basis of an
  alert on a queue that grows faster than lukd processes it.

`workspaces` repeats `/run/luk/workspaces/count.json` (see Jobs with other
users, Workspace), read on every janitor pass: `leftover` the
workspaces lukd run could not remove, `updated` when the count last
changed; absent while the file does not exist. A file that exists but
cannot be read or parsed gives `leftover` 0, an empty `updated` and
`error` with the reason (logged as WARN), never a silent 0. Any `leftover` above 0
is meant to alert at once: in a healthy pipeline it never happens (a
stuck job or an escaped container).

For the pipelines lukd reports facts only. Their thresholds ("expect
every 24h, at least 300M") live in the checkmk check, generated by
host-policy. The thresholds of the watch rules are the `watch`
configuration of the storages.

## TLS

`listen.<n>.tls.mode: self` - a self-signed certificate with a stable key;
downloads (`luk get`) trust it by SPKI pin, not by a CA. Pin format (as in
DLG): `sha256//<base64 of sha256 over the DER SubjectPublicKeyInfo>`.
Endpoints do not use TLS for trust: luk authenticates lukd by the
channel and takes any certificate there (see Channel).

`listen.<n>.tls.algorithm` selects the key: `ed25519` (default) or
`ecdsa-p256`. Browsers (Chrome) do not support Ed25519 in TLS and fail with
`ERR_SSL_VERSION_OR_CIPHER_MISMATCH`, so a listener that browsers open (for
example one serving `expose` downloads) uses `ecdsa-p256`; `luk` works
with either. Changing the algorithm means a new key and a new
pin. `lukd receive` loads whatever key type the files hold.

Bootstrap:

```sh
runuser -u luk -- lukd tls generate          # writes missing cert + key, prints the pins
lukd tls pin                                 # prints the pin of the existing cert
luk scan --pin https://host:8443/ # client side: the lukd key, and "download pin: sha256//..." on stderr (TOFU)
```

`lukd receive` does not generate certificates; a missing cert is an error
that names `lukd tls generate`. `acme` listeners are described below.

`lukd tls generate` runs as the service user (`luk`), so the files are
readable by the server; it creates missing parent directories. Per listener
it generates only when both cert and key are missing; when both exist it
prints the existing pin marked `(exists)`; when exactly one exists it fails
for that listener and never overwrites. Output is one line per listener,
in name order: `<name> <addr> <pin>[ (exists)]` (`lukd tls pin`:
`<name> <addr> <pin>`).

`listen.<n>.tls.mode: files` - the certificate (with its chain) and key
come from an external tool (acme.sh, certbot, host-policy); lukd only
reads them. `cert` and `key` are required (relative paths resolve against
`root`), `host` is optional and `algorithm` does not apply. The files
must be readable by `luk` (the unit hides `/home`, `ProtectHome`; `/etc`
stays readable). lukd never creates, writes or generates them: `lukd tls
generate` skips files listeners, `lukd tls pin` prints their pin too.
Clients of a files listener use normal CA verification: the pin changes
whenever the key changes, which a renewal does unless the tool reuses the
key.

```yaml
listen:
  public:
    addr: 0.0.0.0:443
    host: [drop.example.com]
    tls: {mode: files, cert: /etc/site/lukd/tls/fullchain.pem, key: /etc/site/lukd/tls/key.pem}
```

Reload: on `SIGHUP` (`systemctl reload lukd`) lukd reads the certificate
and key of every TLS listener (self and files) again and serves the new
pair to new connections. A listener whose new pair fails to load keeps
its current certificate and the error is logged; a successful load logs
the new pin and expiry. The certificates are re-read even when the
configuration reload of the same `SIGHUP` fails or is refused (see
Reload); the `tls` settings themselves (mode, paths, host) need a
restart. After a renewal the external tool runs the reload, for
example:

```sh
acme.sh --install-cert -d drop.example.com \
  --fullchain-file /etc/site/lukd/tls/fullchain.pem \
  --key-file /etc/site/lukd/tls/key.pem \
  --reloadcmd "systemctl reload lukd"
```

### ACME

`listen.<n>.tls.mode: acme` - lukd obtains and renews the certificates
itself, from an ACME CA (Let's Encrypt by default) with the HTTP-01
challenge, one certificate (ECDSA P-256) per name of the listener's
`host` list.

```yaml
listen:
  download:
    addr: 0.0.0.0:443
    host: [drop.example.com, get.example.com]
    tls:
      mode: acme
      email: ops@example.com                  # optional: the CA's notices (expiry, problems)
      directory: https://acme-v02.api.letsencrypt.org/directory   # the default
      eab: {kid: KEY_ID, key: B64URL_HMAC_KEY} # optional external account binding
  http:
    addr: 0.0.0.0:80
    acme: true
```

- `host` is required and lists the certificate names: plain DNS names,
  no wildcard, no IP address. `cert`, `key`, `tls.host` and `algorithm`
  do not apply. `email`, `directory` and `eab` apply to mode acme only.
- `directory` is an `https` URL. For tests use the Let's Encrypt staging
  directory `https://acme-staging-v02.api.letsencrypt.org/directory`
  (untrusted certificates, much higher rate limits) and switch to
  production when it works.
- `eab` (CAs that require an external account binding, for example
  ZeroSSL, Google): `kid` and the HMAC key, base64url as the CA prints
  it (standard base64 is accepted), either inline as `key` or in
  `key_file` (one line; a relative path resolves against `<root>/data`; read
  at load, so it must be readable by `luk`, like the configuration).
  The running file keeps the key's sha256, never the key.
- One account per directory: the account key is created on first use
  and shared by every acme listener with that `directory`, which must
  therefore agree on `email` and `eab` (a validation error otherwise).
  Different directories (staging next to production) are independent.
- Cache: `<root>/data/acme/<directory host and path>/` (for example
  `/var/lib/luk/data/acme/acme-v02.api.letsencrypt.org_directory/`), created
  by the receive role with mode 0700: `account.key` and `<name>.pem`
  (key and chain), files 0600. Staging and production never mix. Keep
  the cache across reinstalls: an empty cache means a new account and
  new certificates, which counts against the CA's rate limits.
- A plain listener (no `tls`) speaks HTTP/1.1 and HTTP/2 with prior
  knowledge (h2c): a proxy that ends TLS on a TCP route (Traefik `tcp`
  router with `tls`) passes on the HTTP/2 the client chose by ALPN.
- `acme: true` makes a plain listener (no `tls`) the HTTP-01 responder:
  it answers `/.well-known/acme-challenge/<token>` for the names of
  every acme listener and redirects any other request for them with 308
  to `https://<name>[:port]<path>` (the port of the acme listener's
  `public`, none for 443). A request for any other host is 421. It
  carries no endpoints and no exposes (a validation error). Acme
  listeners without an `acme: true` listener, or one without acme
  listeners, are a validation error. The CA connects to port 80: an
  `acme: true` listener on another port is a warning and needs a port
  forward from 80.
- At start, once the listeners are open, the receive role obtains every
  missing certificate in the background and logs each name (`acme
  certificate` with pin and expiry, `acme certificate obtained`, or
  `acme certificate not obtained` with the error); a failure never stops
  lukd. A handshake for a name without a certificate yet waits for it
  (one issuance per name at a time; after a failure handshakes fail for
  a minute before the next try). Every hour each certificate is checked
  and renewed within 30 days of its end (a third of its lifetime for
  short-lived ones); a failed renewal is retried the next hour while the
  current certificate is served.
- Without SNI or for an unknown name the address serves its first
  listener's certificate, as for other modes; for an acme listener that
  is the certificate of its first host.
- `SIGHUP` does not touch acme certificates and is never needed for them:
  lukd swaps a new certificate into the live TLS configuration itself (the
  next handshake gets it), after a renewal or a `lukd tls acme renew`.
  `SIGHUP` only logs `tls acme` with the pin and expiry of each name (or
  `no certificate yet`).
- Downloads of an acme listener verify the certificate against the
  system CAs and need no pin: the key changes with every renewal. `luk
  scan` prints no download pin for a chain that verifies; `lukd tls pin`
  and `lukd tls generate` skip acme listeners.
- All `tls` settings and `acme` are restart-only (see Reload).
- `status.json` in each cache directory, written by the receive role
  (atomically, 0600) at start and after every issuance attempt and
  renewal request: `directory` (URL), `written`, `hosts` with per name
  `last_attempt`, `last_success`, `last_error`, `next_retry` (the next
  hourly check after a failure) and the `serial` (hex) and `not_after` of
  the certificate in memory, and `requests`: the results of the last 32
  renewal requests keyed by their nonce (`host`, `requested`, `done`,
  `serial` and `not_after`, or `error`).
- Renewal requests: `<name>.renew` in the cache directory, written
  atomically (temporary file and rename) with `{"requested": <RFC 3339>,
  "nonce": <hex>}`. The receive role watches each cache directory with
  inotify (without inotify it looks every 10s) and also looks on every
  hourly check and at start. It removes the file, renews the name at once
  regardless of its expiry, serves the new certificate from the next
  handshake and records the result under the nonce in `status.json`. A
  file without a valid body renews all the same, without a result; a name
  the directory does not manage gets an error result.
- Network: ports 80 and 443 (or the acme listener's port) open from the
  internet, and the receive role reaches the directory over outbound
  HTTPS. The receive unit restricts neither (no `IPAddressDeny`, no
  `RestrictAddressFamilies`); binding 80 and 443 uses its
  `CAP_NET_BIND_SERVICE`.

#### `lukd tls acme`

The commands work on the cache directories under `<root>/data/acme/` and talk
to the running receive role only through files there (no socket, no
signal). Run as root they run again as the owner of `<root>/data/acme` (the
service user), as `lukd queue` does for root; any other user gets `lukd
tls acme must run as root or as <owner> (owner of <root>/data/acme)`. Both
`lukd tls acme ...` as root and `runuser -u luk -- lukd tls acme ...` work.
`<root>/data/acme` is a directory of the service user (see Service, State),
so a symlink there is refused (`lukd tls acme: <root>/data/acme is a
symlink`), never followed. While `<root>/data/acme` does not exist they run
again as the owner of `<root>/data` instead: root never creates or
writes a cache file itself in a directory the service user could replace
meanwhile.

- `lukd tls acme ls [--json]`: every certificate of every cache
  directory: name, the listeners using it per the current configuration
  (`unused` when no acme listener of that directory lists the name), the
  directory by its URL host (`acme-staging-v02.api.letsencrypt.org` for
  staging; from the configuration or `status.json`, else the cache
  directory name up to its first `_`), issuer CN, not before, not after,
  days left, next renewal (`RENEW AT`, see the hourly check above), and
  the last error and next retry from `status.json`. Works without a
  running receive role; the status columns are `-` then (a `status.json`
  left by a stopped lukd is ignored). `--json` prints the same per
  certificate, with the file, the serial and the full daemon state of the
  name (`daemon`).
- `lukd tls acme renew --host NAME [--timeout 2m]`: writes a renewal
  request into the cache directory of the acme listener serving NAME (the
  first by name that lists it) and waits until `status.json` holds the
  result of its nonce: prints `NAME: renewed, serial <hex>, not after
  <time>`, or fails (exit 1) with the error or after the timeout (an
  untaken request is removed then). Fails with `lukd receive is not
  running` when no lukd holds the receive role lock (as `lukd check`
  probes it); no request is written then.
- `lukd tls acme prune [--dry-run]`: removes the certificates `ls` shows
  as `unused` and prints each (`removed <file>`, `would remove <file>`
  with `--dry-run`, `nothing to prune`). Account keys, `status.json`,
  certificates in use and files that do not load as a certificate with its
  key (`unreadable` in `ls`) are kept. Works without the daemon.
- `lukd tls acme revoke --host NAME [--reason R] [--yes] [--timeout 2m]`:
  revokes the cached certificate of NAME at the CA, signed with the
  account key of the cache (`reason`: `unspecified` (default),
  `keyCompromise`, `affiliationChanged`, `superseded`,
  `cessationOfOperation`), removes it from the cache and, when the
  receive role runs, requests a renewal as `renew` does, so the running
  lukd obtains and serves a new certificate at once (otherwise its next
  start obtains one). Without `--yes` it asks for confirmation on a
  terminal and refuses when stdin is not one.

### Service

lukd runs as the system user `luk` under systemd, as two roles of the
same binary with the same config, each in its own unit. `lukd.service`
groups them: it pulls in both role units (`Wants=`), and they are
`PartOf=` it and take its reload (`ReloadPropagatedFrom=`), so `systemctl
start|stop|restart|reload lukd` acts on both roles, while
`lukd-receive.service` and `lukd-process.service` can still be restarted
or reloaded one by one. Install the three units and enable the group:

```sh
systemctl enable --now lukd
```

- `lukd receive` (`deploy/lukd-receive.service`): the listeners, the
  channel sessions (it reads the identity key), verification, queue
  writes (reserve, 507), downloads, portals, once
  claims, the catalog read, and the expiry part of the janitor on every
  local storage (ttl, `cleanup.age`, stale claimed files). It removes half-received queue
  entries at start, before the listeners open: directories of a queue
  directory named like an upload id (`YYYYMMDDTHHMMSSZ-<8 hex digits>`)
  without `meta.json`; anything else there is left alone. `SIGHUP` reloads the
  configuration and re-reads the TLS certificates (see Reload). It never runs pipelines and does not write `status.json`:
  an upload is accepted once its queue entry is committed (`meta.json`).
- `lukd process` (`deploy/lukd-process.service`): no listener. At start it
  submits the committed queue entries, then picks up new ones at once:
  inotify on every queue directory wakes it when `meta.json` is renamed
  into an entry. A poll every 5
  seconds is the fallback (lost events, queue overflow, inotify not
  available); an entry already running is skipped. It runs the pipelines
  (run and store steps), keeps the failure records and `status/process/status.json` (loaded at
  start, results, failed counts, watch evaluations) and does the storage
  maintenance of the janitor (retention, aliases, catalog rebuild,
  content objects, crash leftovers, old work directories), followed by
  the evaluation of the watch rules. `SIGHUP` reloads the configuration (see Reload); the
  queue directories of new endpoints are watched from then on.

Both roles write their liveness file `<root>/data/status/<role>/alive.json`
(see Status).

Each role runs once per `root`: `lukd receive` holds a `flock` on
`<root>/data/receive.lock`, `lukd process` on
`<root>/data/process.lock`, for its lifetime; a second instance
refuses to start (`another lukd runs the <role> role on <root>`).

Both roles touch the storages: receive claims once files and removes
expired ones (and rebuilds the catalog after an expiry pass that removed
something), process stores, removes and rebuilds the catalog. Every
mutation of a local base holds an exclusive `flock` on `<base>/.db/lock`
(any lukd process, any command); the size of that file is the generation
of the base, which lets a download open a file and its sidecar without
the lock and a process notice changes made by the other one. A mutation
grows the file by one byte when it starts (odd: in progress) and by one
more when it ends (even), with `ftruncate`, so the file is sparse: its
apparent size grows by 2 bytes per mutation while it uses no disk blocks
(`ls -s` shows 0); copy a base with sparse-aware tools (`rsync -S`,
`tar --sparse`). The file must never be removed while any lukd process
or command runs on the base: a mutation that opens a new file would lock
another inode than one holding the old file, and both would mutate at
once. With lukd stopped a removal is harmless (the generation restarts
at 0 and every catalog is rebuilt). A base must be on a local filesystem
(no NFS, no CIFS: `flock` and the atomic size are not reliable there).

- Config: `/etc/site/lukd/config.yaml` and `config.d/*.yaml`, owned
  `root:luk`, mode 0640; `ssh.d/` and `ssh.d/ca/{,host/,user/}` owned
  `root:luk`, mode 0750, their `*.pub` files 0640 (never writable by group
  or others); `identity.key` owned `root:luk`, mode 0640, created by the
  package (see Identity key); `password.d/` owned `root:luk`, mode 0750,
  its files 0640 (see Encryption).
- State: the `root` (default `/var/lib/luk`), shared by both role units.
  It must lie on btrfs: both roles check `statfs` of `<root>`
  (`BTRFS_SUPER_MAGIC`) and refuse to start otherwise (`root <root>: not
  a btrfs filesystem`), and `lukd check` reports it; the inputs and
  results of the run steps are clones (`FICLONE`) on it. tmpfiles.d
  (`deploy/luk.tmpfiles.conf`, installed as `/etc/tmpfiles.d/luk.conf`)
  creates the root and its two entries, nothing else:

  ```
  /var/lib/luk/      root:luk   0750  the root
    data/            luk:luk    0750  everything lukd writes
    root/            root:root  0711  root's: the workspaces of lukd run (root/job/)
  ```

  The service user is the owner of `<root>/data`: lukd run, the commands
  that run again as the service user (`lukd queue`, `lukd check` as
  root, `lukd tls acme`) and the checks of the configuration take it
  from there. `<root>` is root's, so the service user can neither rename
  nor replace `<root>/root`. A `root` other than the default needs the
  same three lines in a tmpfiles.d snippet with its path.
  `lukd` creates what it writes below `<root>/data` itself, as it needs
  it: the locks and running files of the roles (`<role>.lock`,
  `<role>.running.json`), `accepted.json` and `quota.json` directly in
  it, and the directories `status/<role>`, `work/`, `tls/`, `gpg-cache/`,
  `acme/<directory>` (mode 0700), `queue/<endpoint>` and
  `storage/<name>` with its `.db/` and `file/` (for the relative paths
  of the configuration), secret queues with mode 0700. It refuses to
  start when one is not writable, or when a storage base holds anything
  else (see Layout under Storage). `/run/luk/volatile` of the volatile secrets comes from
  tmpfiles.d too; both role units have it in `ReadWritePaths` (see
  Volatile secrets). So does `/run/luk/nonces` (`luk:luk`, 0700) of the
  nonce cache (`auth.nonces`), in `ReadWritePaths=-/run/luk/nonces` of
  the receive unit only.
- Port 443 and other privileged ports: `CAP_NET_BIND_SERVICE`, in the
  receive unit only; the process unit has no capability.
- `systemctl reload lukd` (or one role unit; `ExecReload`: `lukd check`,
  then `SIGHUP`) reloads the configuration and re-reads the
  TLS certificates and keys (see Reload, TLS); a change of a restart-only
  setting fails the reload and needs a restart of both roles.
- Storage outside `root` (default `/var/lib/luk`): the base directory must
  be owned by `luk` and added to `ReadWritePaths` in a drop-in (below);
  `/run/luk/volatile` (volatile secrets) is in the shipped units already.

Drop-ins by unit:

| grant | lukd-receive | lukd-process |
|---|---|---|
| storage base or secret queue outside `/var/lib/luk` and `/run/luk/volatile` (`ReadWritePaths`) | yes | yes |
| resource limits of the process role (`MemoryMax`, `CPUQuota`, `TasksMax`) | | yes |

#### Sandbox of lukd process

`lukd process` runs the store and encrypt steps itself; `run` programs
and jobs never run inside it: each runs in a transient unit of its own,
as another user, through `lukd run` (see Jobs with other users). The unit
of the process role decides what lukd itself may do:

- user `luk` and its groups only; `NoNewPrivileges=yes` makes `sudo` and
  setuid binaries fail;
- `ProtectSystem=strict`: the whole file system is read-only except the
  `ReadWritePaths` (`/var/lib/luk` and `/run/luk/volatile` by default),
  `/dev`, `/proc`, `/sys`;
- `ProtectHome=read-only`: `/home`, `/root`, `/run/user` are read-only;
- `PrivateTmp=yes`: `/tmp` is private to the service;
- no capability (`CapabilityBoundingSet=`);
- the keys of the receive role are out of reach although both roles run
  as `luk`: `InaccessiblePaths=` hides `<root>/data/tls`, `<root>/data/acme` and
  `/run/luk/nonces` (default paths; another `root` or tls files elsewhere
  need theirs in a drop-in), `SystemCallFilter=~@debug` forbids ptrace and
  `process_vm_readv`, and `PrivatePIDs=yes` (systemd 257) gives the role
  its own PID namespace, so `lukd receive` is not even visible; `lukd
  receive` itself is non-dumpable (`PR_SET_DUMPABLE` 0), so no other
  process of `luk` may attach to it or read its memory;
- network access is not restricted;
- CPU, memory and task limits of the unit apply to the process role; the
  units of the run steps run in `system.slice`, outside them.

Anything more is granted explicitly in a drop-in (examples in
`deploy/lukd-process.service.d/`), never by changing the shipped unit. A
drop-in lives in `/etc/systemd/system/lukd-process.service.d/` (storage
bases also in `lukd-receive.service.d/`) and is applied with `systemctl
daemon-reload && systemctl restart lukd`. Examples:

```ini
# /etc/systemd/system/lukd-process.service.d/storage.conf
# A storage base (also in lukd-receive.service.d/) outside /var/lib/luk.
# The directory must exist and be writable by luk:
#   install -d -o luk -g luk -m 0750 /storage
[Service]
ReadWritePaths=/storage
```

```ini
# /etc/systemd/system/lukd-process.service.d/limits.conf
# Keep heavy store and encrypt steps from starving uploads and downloads.
[Service]
MemoryMax=4G
CPUQuota=200%
TasksMax=512
```

Check the effective sandbox with `systemctl cat lukd-process` and
`systemd-analyze security lukd-process`. Heavy work belongs in a `run`
step, work that needs credentials or another user in a job of run.d,
work that needs root in a separate service a job talks to; never in the
lukd units.

#### Jobs with other users (lukd run)

Every `run` step and every job runs through `lukd run`, a small root
helper, as a transient unit with a workspace of its own: a `run` program
as a dynamic user, a job the admin allowlisted (the job of a `run: {job}`
step, of a `relay` step, or a nested job of `luk-job run`) as the user
the admin chose. A job may need what `luk` must not have: credentials of
a bucket, a user with access to a backup host, a group that owns a
target directory. Files reach a unit and leave it as open descriptors;
the unit never sees anything of lukd but its workspace. No polkit and no
sudo are involved.

- Units: `deploy/lukd-run.socket` (`ListenStream=/run/luk/run.sock`,
  `root:luk` 0660, `Accept=yes`, `MaxConnections=1024` as a backstop; the
  limit of running units is `limits.units.max` of `run.yaml`, below) and
  `deploy/lukd-run@.service` (root, one instance per connection, the
  connection on stdin and stdout, stderr to the journal,
  `ExecStart=/usr/bin/lukd run`, sandboxed: read-only file system,
  `AF_UNIX` only, no capability (`CapabilityBoundingSet=`; `systemd-run`
  needs none, and the workspaces are made and removed by helper units,
  see Workspace),
  `ProtectProc=invisible` (processes of other users hidden),
  `RuntimeDirectory=lukd-run` 0700 with `RuntimeDirectoryPreserve=yes`
  for the locks, see below; `MemoryMax=128M`, `TasksMax=64` and
  `RuntimeMaxSec=15d` as a backstop: they bound the helper, not the unit
  it starts, which systemd-run starts as a transient unit of its own in
  `system.slice`). `/run/luk` comes from tmpfiles.d
  (`deploy/luk.tmpfiles.conf`, `root:luk` 0750). Enable with `systemctl
  enable --now lukd-run.socket`. `deploy/lukd-run-prune.service` and
  `deploy/lukd-run-prune.timer` remove leftover workspaces (see
  Workspace below).
- `lukd-process` (and `lukd`) need no drop-in: `ProtectSystem=strict`
  leaves `/run` read-only, and connecting to a socket is not a write to
  the file system. `lukd-receive` never runs units and has
  `InaccessiblePaths=-/run/luk/run.sock`.
- `lukd-receive` and `lukd-run@` hide the passwords of the encrypt steps
  (`InaccessiblePaths=-/etc/site/lukd/password.d`, see Encryption).
- Global settings, optional: `/etc/site/lukd/run.yaml`
  (`deploy/run.yaml.example`), owned `root:root`, mode 0600:
  - `root`: the lukd root; default `/var/lib/luk`. It must be the same
    path as the lukd `root` (every unit gets it as an empty tmpfs, see
    Sandbox of a unit); `lukd check` run as root warns when it is not.
    The workspaces live in `<root>/root/job`: the create helper of lukd run makes `job/`
    itself on demand (`root:root` 0711). `<root>/root` and `job/` must
    pass the rule of the directories above run.d (below): every directory
    from `/` down to them owned by root and not writable by group or
    others (`<root>` itself is `root:luk` 0750, `<root>/root` `root:root`
    0711 from tmpfiles.d).
  - The only user allowed to connect (`SO_PEERCRED` of the connection)
    is the service user, the owner of `<root>/data`; there is no setting
    for it. When `<root>/data` is owned by root or is a symlink (checked
    with `lstat`), lukd run closes every connection without an answer
    and logs the reason.
  - `config`: the main file of the lukd configuration, an absolute
    path; default `/etc/site/lukd/config.yaml`. It decides what each
    step runs (see What a step runs below) and names the paths a unit
    must not see (see Sandbox of a unit); `lukd check` run as root
    warns when it is not the checked file, and when it is but lukd run
    would refuse it.
  - `hide`: absolute paths, further ones a unit must not see (see
    Sandbox of a unit); default none.
  - `limits.units.max`: the units of steps (`run`, `run: {job}`,
    `relay`) running at once, at least 1, default 16. Each step holds
    its connection for its whole run. A step request over the limit
    waits in lukd run for a free slot (an exclusive `flock` on one of
    `/run/lukd-run/.slot/<n>.lock`, `<n>` from 1 to the limit, polled),
    its unit not yet started, without a limit, as an upload waits for
    `queue.concurrency`: the wait does not count toward the pipeline
    `timeout`, which measures work only and starts when the unit starts
    (the `s` frame, see Frames). A burst of uploads so lengthens the
    queue instead of losing uploads; the waiting steps and the age of
    the oldest unprocessed upload show in `status.json` (see Status),
    and the operator decides (a higher `limits.units.max`, another
    `queue.concurrency`), knowing that files wait unprocessed longer.
    When lukd process closes the connection meanwhile (a stop of lukd),
    lukd run gives up without starting the unit. A nested job takes no
    slot: it runs inside a step that holds one, one at a time, so at
    most twice the limit of units run, and a step never waits for a slot
    its own nested job needs. `lukd check` warns when the sum of
    `queue.concurrency` of the pipelines with a `run` or `relay` step
    exceeds `limits.units.max` (it reads `run.yaml` only when run as
    root): steps would then wait in lukd run rather than in the queue.
- Jobs: `/etc/site/lukd/run.d/<job>.yaml`, one job per file
  (`deploy/run.d/s3-upload.yaml.example`). The job name is the file base
  name, `[a-z0-9][a-z0-9._-]*`. Files not ending in `.yaml`, dotfiles and
  leftovers (`*~`, `*.dpkg-*`, `*.swp`) are ignored. The directory and
  the files must be owned by root and not writable by group or others (a
  file must be regular, not a symlink); otherwise the directory, or that
  file, is refused. So must every directory above `run.yaml` and run.d,
  from `/` down (`/etc`, `/etc/site`, `/etc/site/lukd`): a directory,
  not a symlink, owned by root, not writable by group or others (read
  access for the group `luk`, as the package sets up, is fine).
  Otherwise nobody but root could be trusted not to swap the files
  below: a bad directory above `run.yaml` makes lukd run close every
  connection without an answer (logged), one above run.d refuses every
  job as unavailable (logged). The directory is read per connection:
  adding or removing a file needs no reload. A malformed or refused file
  disables only its job: a request for it is refused and the reason is
  logged.
  Keys of a job:
  - `user` (optional): the account of the job (`systemd-run --uid`).
    Without `user` the job runs as a dynamic user (`-p DynamicUser=yes
    -p User=<name>`, see below).
  - `group` (optional, needs `user`): replaces the primary group of the
    user (`--gid`).
  - `groups` (optional): extra supplementary groups
    (`-p SupplementaryGroups=`, duplicates dropped). The user keeps its
    own primary and supplementary groups. A unit gets no group of the
    peer: its workspace is its own.
  - `command` (required): a clean absolute path; it gets the workspace
    as its only argument, in `LUK_WORK` and as its current directory.
  - `credentials`: `name: path` entries passed as systemd
    `LoadCredential=name:path`; the job reads them from
    `$CREDENTIALS_DIRECTORY/<name>`, the files themselves stay root-only.
  - `timeout`: `RuntimeMaxSec` of the job, at least `1s` and under 7
    days (no step waits longer, see the pipeline `timeout`); default
    `1h`. The step of a `run: {job}` or `relay` step also ends at the
    pipeline `timeout`, whichever comes first.
  - `env`: fixed environment. Every `LUK_*` name is reserved (a
    config error): lukd run sets them, see Environment and state below.
  - `pipelines`: removed, a config error of the job (`pipelines:
    removed: list the job in jobs of the run step of the lukd
    configuration, a relay step allows its own job`); the steps that may
    run a job come from the lukd configuration (see What a step runs).
  - `state` (optional): `locked` or `shared`, a state directory kept
    between runs, one per job and pipeline; absent means none. See
    Environment and state below.
  - `privileged` (optional, needs `user`): `true` runs the job without
    `NoNewPrivileges=yes`, for the setuid `newuidmap` of rootless podman
    (see Containers). Every setuid binary of the host then works in that
    job (`sudo` as far as the sudoers allow the job user, `su`,
    `newuidmap`). Every other unit has `NoNewPrivileges=yes`:
    `privileged` on a job without `user` is a config error of the job
    (`privileged needs user`), and a `run` program never gets it.
- What a step runs: the `run` program of a `run: <program>` step, the job
  of a `run: {job}` or `relay` step, and as nested jobs the jobs listed
  in `jobs` of a `run: <program>` step. lukd run reads them per
  connection, and only when the request gets that far, from the `config`
  of `run.yaml` and the `*.yaml` of `config.d` next to it (dotfiles left
  out), parsing only `pipeline.<name>.timeout` and
  `pipeline.<name>.steps[]` (`run`, `env`, `relay`, `jobs`) and nothing
  the files name (keys, passwords); the rest of the configuration is
  lukd's to validate. A step request for a step that is neither a `run`
  nor a `relay` step (`pipeline <p> step <n>: not a run or relay step`)
  and a nested job its step does not list in `jobs` (`job <job>: not
  allowed for pipeline <p> step <n>`) are refused before any slot, lock,
  workspace, state directory or dynamic user exists for it, so `luk`
  cannot make root create them for names of its choosing. A `run`
  program must be a clean absolute path with the path rules of
  `command` (see Sandbox of a unit). The files are read as the run.d
  files are: owned by root, not writable by group or others, regular
  (opened with `O_NOFOLLOW|O_NONBLOCK`, so a symlink or a FIFO is
  refused), at most 1 MiB each, at most 256 snippets, `config.d` a
  directory (not a symlink) with the same owner and mode rules, and
  every directory from `/` down to it as above `run.d`. A missing main
  file (or a missing directory above it) allows no step. A refused file,
  a malformed one (YAML that does not parse, a `run`, `relay`, `env` or
  `jobs` of the wrong type, a second document), a step with both `run`
  and `relay` or a pipeline defined in two files refuses the whole
  configuration: no step may run, and the reason goes to the journal;
  `lukd check` run as root reports it as a warning. The files are the
  ones on disk, not the configuration lukd runs with: an edit counts at
  the next connection, before a reload of lukd.
- Request flow: lukd process connects and sends one JSON line, with the
  channel of the unit attached to it (`SCM_RIGHTS`, exactly one
  descriptor, a Unix socket; see Channel of a unit). A step:
  `{"pipeline": P, "step": N, "id": ID, "env": {NAME: value, ...}}`; a
  nested job of that step adds `"job": NAME`. Valid UTF-8, at most 32
  KiB with the newline, exactly one flat object (`pipeline` and `id`
  strings and `step` a number, all required, `job` an optional string,
  `env` an optional object of at most 16 string values; an unknown or
  repeated key, a nested or non-string value, data after the object and
  a request without its one descriptor make it malformed). There is no
  path in the request. `lukd run` refuses a peer other than the service
  user (closing without an answer), then a request that is malformed, whose
  `pipeline` is not a valid pipeline name (`[A-Za-z0-9_.-]`, not
  starting with a dot or a dash, at most 128 bytes), whose `step` is not
  a number from 1, whose `id` is not a queue entry id
  (`YYYYMMDDTHHMMSSZ-<8 hex digits>`), that the configuration does not
  allow (above), or that names an unknown or disabled job. The program
  of a `run` step comes from the configuration, never from the request.
  It runs the unit as `systemd-run --wait --collect --pipe --quiet
  --expand-environment=no --unit=<unit>
  (--uid=<user> | -p DynamicUser=yes -p User=<dynamic user>)
  --working-directory=<workspace> [--gid=<group>]
  [-p SupplementaryGroups=<groups>] [-p NoNewPrivileges=yes]
  -p PrivateTmp=yes -p ProtectProc=invisible -p PrivatePIDs=yes
  -p InaccessiblePaths=-<config dir> -p InaccessiblePaths=-/run/luk
  [-p InaccessiblePaths=-<path> ...] -p TemporaryFileSystem=<root>:ro
  -p BindPaths=<workspace>:<workspace>:norbind
  -p ExecStartPre=+<lukd> run workspace own <unit>
  [-p StateDirectory=lukd-run/<job>/<pipeline> -p StateDirectoryMode=0700]
  [-p LoadCredential=...] -p RuntimeMaxSec=<timeout> [--setenv=K=V ...]
  --setenv=LUK_WORK=<workspace> ... --setenv=LUK_ORIGIN=<origin>
  --setenv=TMPDIR=<workspace>/tmp [--setenv=LUK_JOB=<job>]
  [--setenv=LUK_STATE=/var/lib/lukd-run/<job>/<pipeline>]
  <lukd> run workspace run <workspace> -- <command> <workspace>`, with
  the channel as its stdin (`--expand-environment=no` needs systemd 254
  or later; the lukd package requires systemd 257 for `PrivatePIDs=`), a
  transient unit outside both the lukd and the lukd run sandbox, and
  streams the unit's stdout and stderr back. lukd run never reads from
  the channel. `<unit>` is `lukd-run-<job>-<random>` for a job and
  `lukd-step-<pipeline>-<step>-<random>` for a `run` program (lowercase,
  every character outside `[a-z0-9-]` replaced by `-`, `<random>` 12 hex
  digits); `<workspace>` is `<root>/root/job/<unit>`; `<command>` is the
  `run` program or the `command` of the job; `<timeout>` is the pipeline
  `timeout` for a `run` program and the job `timeout` for a job;
  `NoNewPrivileges=yes` is left out only for a job with
  `privileged`.
- Workspace: a btrfs subvolume per unit, `<root>/root/job/<unit>`, owned
  by the user of the unit, mode 0700. Every btrfs operation is an ioctl
  or system call of lukd itself (`statfs` for the magic,
  `BTRFS_IOC_SUBVOL_CREATE_V2`, `BTRFS_IOC_TREE_SEARCH`,
  `BTRFS_IOC_SNAP_DESTROY_V2`, `FICLONE`): no btrfs-progs, and root runs
  no external program for it. lukd run itself has no capability and
  touches no workspace: one-purpose helper units make and remove them.
  - The workspace must exist before the job unit starts: a `BindPaths=`
    whose source is missing fails every process of the unit (at the step
    `NAMESPACE`, even with `-`), and every command of the unit, `+` ones
    included, runs in its mount namespace, where `<root>` is the empty
    tmpfs. So creation and removal happen outside the job unit.
  - The helpers `<lukd> run workspace create <unit>`, `<lukd> run
    workspace remove <unit>` and `<lukd> run workspace own <unit>` take
    one argument, a unit name, never a path. It must match
    `lukd-run-<name>-<random>` or `lukd-step-<name>-<step>-<random>`:
    only `[a-z0-9-]`, `<random>` exactly 12 lowercase hex digits at the
    end, at most 240 bytes (so no `/`, no `.`, no `..`); anything else is
    refused (`workspace: invalid unit name`, exit 1). Each helper builds
    the path itself: `root` of `run.yaml` (root-owned, read with the
    rules of Jobs above) plus `root/job/<unit>`. Nothing of the path
    comes from `luk` or from lukd run, and no helper reads any data of
    `luk`.
  - Create: lukd run starts, once the step holds its slot and before the
    job unit, `systemd-run --wait --collect --quiet
    --unit=lukd-workspace-<random> <properties> <lukd> run workspace
    create <unit>`. The helper opens `<root>/root` element by element from
    `/` with `O_DIRECTORY|O_NOFOLLOW` and checks the chain rule (every
    directory owned by root, not writable by group or others, no
    symlink), creates `job/` below it when missing (`mkdirat`,
    `root:root` 0711) and opens and checks it the same way, checks with
    `statfs` that it lies on btrfs, and creates the subvolume `<unit>`
    relative to that descriptor (`BTRFS_IOC_SUBVOL_CREATE_V2` with the
    parent descriptor and the name), `root:root` 0700, empty. A failure
    fails the step before the job unit starts: lukd run answers with the
    refusal `lukd run: workspace not created`, the reason in the journal
    of the helper unit.
  - Own: `ExecStartPre=+<lukd> run workspace own <unit>` of the job unit
    (root, in the namespace of the unit, before the main process)
    validates the name the same way, reads the UID and GID systemd
    allocated to that unit (`systemctl show -p UID -p GID --value
    <unit>`, never the environment; a dynamic user exists from the start
    of its unit, before `ExecStartPre`) and sets them as owner of the
    workspace of that name through the bind (the same inode; opened with
    `O_DIRECTORY|O_NOFOLLOW`, `fchown`), mode 0700, nothing else: the
    wrapper creates what lies inside, as the user of the unit. A failure
    ends the unit before its command starts, with the reason in the
    journal of the unit.
  - Remove: after `systemd-run --wait` of the job unit returned, or after
    a closed peer once the job unit is inactive (see Frames), also after
    a failure or a timeout kill, lukd run starts the helper `<lukd> run
    workspace remove <unit>` the same way. systemd ends a unit only after
    every process of its cgroup ended (the stop sequence `stop`,
    `stop-sigterm`, `stop-sigkill`, with `KillMode=control-group`), so its
    mount namespace, the only place the workspace is bound, is gone by
    then: a requirement of the job unit, which therefore keeps
    `KillMode=control-group`. The helper opens `<root>/root/job` with the
    chain rule, then the name with `O_DIRECTORY|O_NOFOLLOW` (`openat`:
    the seccomp filter of `RestrictSUIDSGID=yes` refuses `openat2`),
    requires it on the mount of `job/` (the mount ids of `statx`
    `STATX_MNT_ID` equal, else `EXDEV`), verifies that it is a subvolume
    (inode 256 on btrfs), and refuses while the job
    unit of that name is still active (`systemctl show -p ActiveState
    --value <unit>.service` is neither `inactive` nor `failed`, and the
    unit is loaded). It deletes every subvolume the job created inside
    the workspace first, leaves first, then the workspace itself: only
    subvolumes whose chain of `ROOT_REF` parents (`BTRFS_IOC_TREE_SEARCH`
    in the tree of tree roots) leads to the id of that workspace, each
    deleted by its id (`BTRFS_IOC_SNAP_DESTROY_V2` with
    `BTRFS_SUBVOL_SPEC_BY_ID`). No file is read and no tree of the job is
    walked. btrfs frees the space of a deleted subvolume asynchronously, a
    moment later. A lukd run that ends before the remove (a crash, its
    `RuntimeMaxSec`) leaves the workspace to prune.
  - Sandbox of the helper units (create, remove; prune as well):
    `ProtectSystem=strict` with `ReadWritePaths=<root>/root/job`
    (`<root>/root` for create, which may make `job/`) and, for remove
    and prune, `/run/luk/workspaces` (the count, below);
    `CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE
    CAP_DAC_READ_SEARCH CAP_FOWNER` (the kernel requires `CAP_SYS_ADMIN`
    for `BTRFS_IOC_TREE_SEARCH` and destroy by id; the workspace and what
    the job made in it belong to the job user, mode 0700, so root needs
    the DAC capabilities to reach a nested subvolume and `CAP_FOWNER` to
    delete it from a directory the job made sticky), `PrivateNetwork=yes`,
    `RestrictAddressFamilies=AF_UNIX` (`systemctl show`),
    `NoNewPrivileges=yes`, `ProtectHome=yes`, `PrivateTmp=yes`,
    `PrivateDevices=yes`, `ProtectKernelTunables=yes`,
    `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`,
    `ProtectControlGroups=yes`, `ProtectProc=invisible`,
    `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`,
    `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`,
    `SystemCallArchitectures=native`, `UMask=0077`. lukd run passes this
    fixed set; nothing of it comes from a request. The create and remove
    helpers also get `RuntimeMaxSec=5min`, and lukd run gives up on one
    a minute after that (a create counts as failed, `workspace not
    created`; a remove as `workspace not removed`), so a helper that hangs
    (btrfs I/O stuck) cannot hold the slot of a step.
  - Worst case of a bug in lukd run or a compromised lukd run, through
    the helpers: a workspace of another valid name in `<root>/root/job`
    created, or removed while its unit is not active (and the count
    raised). Never anything outside `job/`: the helpers take no path,
    open everything by descriptor without following a symlink, and
    destroy only subvolumes below the workspace of that name.
  - A subvolume that is still mounted cannot be deleted (`EBUSY`): a
    process stuck in uninterruptible I/O (state D) keeps the namespace of
    the unit alive, and a job of the group `docker` may have bound its
    workspace into a container that lives in the cgroup of the daemon.
    The remove helper then logs `workspace not removed` (WARN, with the
    unit and the error), leaves the subvolume, raises the count of
    leftover workspaces at once (below) and exits 1; lukd run logs it
    and the step result is not changed by it.
  - Prune: `<lukd> run workspace prune` (its own unit,
    `lukd-run-prune.service` with the sandbox of the helpers, pulled in
    by `lukd.service` at start and run every 15 minutes by
    `lukd-run-prune.timer`; it talks to nobody) removes, with the code of
    the remove helper, every workspace of `<root>/root/job` named like a
    unit (the pattern above) whose unit is not active; any other entry is
    logged and left alone. lukd run holds an exclusive `flock` on
    `/run/lukd-run/.ws/<unit>.lock` (root, 0600, removed on release) from
    before the create helper until after the remove helper, and prune
    skips a workspace whose lock is held, so it never removes one that is
    being set up or in use.
  - The count of leftover workspaces lives in
    `/run/luk/workspaces/count.json` (the directory `root:luk` 2750 from
    tmpfiles.d, setgid so the file gets the group `luk` without
    `CAP_CHOWN` in the helpers, the file 0640, `{"leftover": N,
    "updated": "<UTC time>"}`, replaced atomically under an exclusive `flock` on
    `/run/luk/workspaces/lock`): a failed remove adds one at once, and
    prune writes the number it still could not remove, so only prune
    lowers it, when it cleans up. lukd process reports it in
    `status.json` (`workspaces`, see Status). Any value above 0 is meant
    to alert at once: in a healthy pipeline it never happens (a stuck job
    or an escaped container).
- Channel of a unit: lukd process creates it with
  `socketpair(AF_UNIX, SOCK_SEQPACKET)`, sends one end with the request
  and keeps the other; the unit gets it as the stdin of its main process,
  the wrapper. Each packet is one JSON object ending in a newline (a JSON
  line), at most 64 KiB, with at most one descriptor (`SCM_RIGHTS`),
  present only on a frame that carries a file:
  - lukd process to the wrapper: `{"t": "meta"}` with `meta.json`, then
    `{"t": "in", "name": <name>}` with each file of the set and each
    per-file meta file, then `{"t": "go"}`.
  - The wrapper to lukd process, once the command ended: `{"t":
    "status", "status": N, "fail": <text>}` (the exit status and the text
    of `fail`, empty when none), then `{"t": "out", "name": <name>}` with
    each top-level entry of `out/`, or a `{"t": "refuse", "name": <name>,
    "reason": <reason>}` and no further result, then `{"t": "end"}`.
  - A nested job (`luk-job run`): the wrapper sends `{"t": "job", "job":
    NAME}`, `{"t": "in", "name": <name>}` with each `--file` and `{"t":
    "go"}`; lukd process answers with `{"t": "o", "data": <base64>}` and
    `{"t": "e", "data": <base64>}` for the output of the job, `{"t":
    "out", "name": <name>}` with each of its results, and `{"t": "exit",
    "status": N}`, or `{"t": "refused", "reason": <reason>}`. lukd
    process asks lukd run for the job over a connection of its own, with
    a channel of its own to the job's wrapper, and passes the
    descriptors on in both directions without reading them. When luk-job
    closed its connection before the answer, the wrapper sends `{"t":
    "stop"}`; lukd process then stops the job and answers `exit`.
  - Limits: names follow the `out/` rules; at most 1024 `in` and 1024
    `out` frames per run; lukd process checks every received descriptor
    with `fstat` (a regular file) and its name before it clones it.
    After the `status` frame the wrapper only opens and sends, so every
    further frame must come within 1 minute of the one before (`run
    <program>: no result for 1m`); the pipeline `timeout` holds
    throughout. A channel that ends before `end` fails the step (`run
    <program>: channel closed before the results`).
  - A received descriptor stays valid after the unit ended and after its
    file was deleted with the workspace: the wrapper exits after `end`
    without waiting for an answer, a helper unit of lukd run removes the workspace once
    the unit is gone, and
    lukd process clones the results at its own pace. Both sides clone a
    received file (`FICLONE`), or copy it with `copy_file_range` on
    `EXDEV`, `EOPNOTSUPP` or `EINVAL`, decided per file at runtime (an
    input from a storage on another filesystem than the root), under a
    temporary name, and rename it once complete.
- The wrapper, `<lukd> run workspace run <workspace> -- <command>
  <workspace>`, is the main process of the unit and runs as its user, in
  its sandbox: it creates `in/`, `out/`, `tmp/` (0700) and `.luk/` (0700,
  the socket `run.sock` of `luk-job run` in it), receives `meta.json` and
  the inputs and clones them into the workspace (mode 0400), then starts
  the command as a child (not with `exec`) with stdin `/dev/null` and its
  own stdout and stderr, relays the requests of `luk-job run` (one at a
  time) while it waits, and sends the results once the command ended.
  An error before the command starts (an input it cannot clone) goes to
  stderr as `lukd: job not started: <reason>`, reaches lukd process as
  output of the unit, and the wrapper exits 1. The job can interfere
  with its wrapper, which runs as the same user: that changes nothing,
  since whatever the wrapper sends is what the job could have put in
  `out/`, and lukd process validates all of it.
- Sandbox of a unit: a unit runs as another user, with credentials of
  its own, and must see nothing of lukd but its workspace:
  - `<config dir>`, the directory of `config` of `run.yaml` (default
    `/etc/site/lukd`), is inaccessible as a whole: the identity key,
    `password.d`, `gpg.d`, `ssh.d`, `config.yaml` and `config.d`,
    `run.yaml` and run.d, and every other file there. `LoadCredential=`
    still reads a credential from it, since systemd reads the
    credentials as root before it sets up the namespace of the unit.
  - `/run/luk` is inaccessible: the socket of lukd run, the nonce cache,
    the volatile secrets and the count of leftover workspaces.
  - `<root>` is an empty read-only tmpfs (the TLS and ACME keys, the
    WKD key cache, the status, the storages, the queues, the work
    directories and the other workspaces are gone) with only
    `<workspace>` bound back (non-recursively), read-write and at the
    same path, so `LUK_WORK`, `LUK_IN`, `LUK_OUT`, `LUK_META`, `LUK_TMP`,
    the argument and the current directory stay valid.
  - Every other path of the lukd configuration that holds data or
    secrets is inaccessible as well, read per connection with the
    pipelines (`config` and its `config.d`, see What a step runs): its
    `root` (default `/var/lib/luk`) and, when absolute, `auth.nonces`,
    `gpg.keys`, the `tls.cert`, `tls.key` and `tls.eab.key_file` of
    every listener, the `path` and `secret.path` of every endpoint and
    the `base` of every storage (a relative one lies under `<root>/data`).
    So are the paths of `hide` in `run.yaml` (absolute, for anything
    the configuration does not name). A path under `<root>`, `<config
    dir>`, `/run/luk` or another hidden path adds nothing.
  - `<root>/root/job` and the workspace are root's to create and remove,
    and the parent is root's: the user of the unit cannot rename or swap
    them (it owns its workspace but not its parent), so nothing is
    checked again inside the unit.
  - `ProtectProc=invisible`: the processes of other users (lukd, other
    units) are hidden in `/proc`.
  - `PrivatePIDs=yes`: the unit has a PID namespace and a `/proc` of its
    own, the wrapper is its PID 1. Units of the same user (concurrent
    runs of one step or one job share a dynamic user, jobs share a
    static `user`) would otherwise reach each other's workspace and
    `.luk/run.sock` through `/proc/<pid>/root` and `/proc/<pid>/cwd`.
  - `NoNewPrivileges=yes` on every unit (`sudo` and setuid binaries
    fail), except a job with `privileged`.
  - The `-` of `InaccessiblePaths=` skips a missing path; a missing
    source of `BindPaths=` fails the unit even with `-`, so lukd run
    creates the workspace before the unit (see Workspace).
  - The unit sees the rest of the system as its user and groups allow,
    `/tmp` and `/var/tmp` private (`PrivateTmp=yes`), and its state
    directory. It gets no group of the peer.
  - Not confined: a job whose groups reach a service that acts for it
    on the host. The sandbox does not hold for a job in the group
    `docker`: through the daemon it can bind any host path into a
    container, its workspace or not, root-equivalent.
  - `command`, a `run` program, the state directory and `<lukd>` must
    lie outside every hidden path (`<workspace>` is the one exception
    under `<root>`); `<root>`, `<config dir>`, `<workspace>`, `<lukd>`
    and every hidden path that adds a property must be clean absolute
    paths other than `/` without white space, a control character, a
    quote, a backslash, a colon, `$` or `%` (systemd-run splits,
    unquotes or expands them in a property); `<root>`, `<config dir>`
    and a hidden path that adds a property must not be a system
    directory (`/etc`, `/usr`, `/var`, `/var/lib`, `/run`, `/srv`,
    `/opt`, `/home`, `/tmp` and the like), which the unit cannot do
    without. Otherwise the request is refused as `job <job>:
    unavailable` (`pipeline <p> step <n>: unavailable` for a `run`
    program), the reason in the journal.
- Deadlines: the request must arrive, and a refusal be read, within 5
  seconds of the connection; a peer that sends nothing, half a line or
  does not read the refusal is cut off then. A step waiting for a slot
  or a job waiting for its state lock has no deadline (the peer may
  close). Once the unit starts, the whole exchange (its output and the
  exit frame) must end within its `RuntimeMaxSec` plus 2 minutes: a peer
  that stops reading makes the writes fail by then, which counts as a
  closed peer (the unit is stopped, see below), so it cannot hold a
  connection.
- Frames: 1 byte type (`s` started, `o` stdout, `e` stderr, `x` exit),
  4 byte big-endian payload length, the payload (at most 1 MiB; `s` is
  empty and comes once, when a step holds its slot (a nested job: once
  its request is accepted), before a state lock and the start of the
  unit; the pipeline `timeout` of the step counts from it; the `x`
  payload is the decimal exit status of the unit and ends the
  exchange). A
  refusal is an `e` frame `lukd run: <reason>` and `x` 1. When the peer
  closes the connection before the exit frame (step timeout, stop of
  lukd), `lukd run` stops the transient unit (`systemctl stop`), kills
  `systemd-run`, stops the unit again when the first stop failed (the
  unit not loaded yet), and ends only once the unit is inactive with no
  job pending (`systemctl show -p ActiveState -p Job`), polled for at
  most its `RuntimeMaxSec` plus 2 minutes (`RuntimeMaxSec` ends the unit
  by then).
- The boundary: `luk` picks only a pipeline, a step, an upload id, a
  nested job of that step, the values of the free-form metadata variables
  (`LUK_SENDER`, `LUK_ENDPOINT`, `LUK_FILE`, `LUK_NAME`, `LUK_TAGS`,
  `LUK_HOSTNAME`, `LUK_ORIGIN`, filtered as in Step environment) and the
  files it sends over the channel. The program, the command, the user,
  the group, the credentials, the rest of the environment and the
  timeout come from root's files. A unit treats its inputs and those
  metadata values as untrusted input: `luk` writes them (they normally
  repeat the upload's meta, but nothing but the filter holds `luk` to
  that; `LUK_FILE` always names a file of `<workspace>/in/`, not
  necessarily an existing one).
- A dynamic user is allocated by systemd for the run of the unit and
  released after it. Its name is fixed per job and pipeline,
  `lukd-<job>-<pipeline>-<hash>`, and per step of a `run` program,
  `lukd-<pipeline>-<step>-<hash>`: the readable part (`<job>-<pipeline>`
  or `<pipeline>-<step>`) lowercased, every run of characters outside
  `[a-z0-9_-]` replaced by `_` and cut so the name stays within 31
  characters, `<hash>` the first 8 hex digits of sha256 of
  `<job>/<pipeline>` or of `step:<pipeline>/<step>` (the hash keeps names
  apart that the readable part would merge, such as job `a-b` on
  pipeline `c` and job `a` on pipeline `b-c`, or job `p` on pipeline `1`
  and step 1 of pipeline `p`; a job name has no colon). systemd derives
  the UID from the name and first tries the UID that owns the existing
  state directory, so the runs of one job and pipeline normally get the
  same UID and the state directory needs no recursive chown; two of
  them never share a user. `DynamicUser=yes` implies
  `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`,
  `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` and `RemoveIPC=yes`: the
  unit reads the system (as hidden by the sandbox above) but writes only
  its workspace, its own `/tmp` and `/var/tmp`, which are removed with
  the unit, and its state directory. That fits `run` programs and jobs
  that deliver the inputs elsewhere (an upload to S3, rsync to another
  host, a notification); a job that writes other local files needs a
  `user`.

Environment and state of every unit, reserved like `LUK_WORK` (an `env`
key `LUK_*` is a config error):

- The metadata variables of the Step environment (`LUK_WORK` to
  `LUK_ORIGIN`): the workspace-bound ones set by lukd run from the
  workspace (also the argument and the current directory), the
  step-bound ones from the checked request, the free-form ones from the
  request after the filter; a name lukd run derives or sets itself is
  never taken from the request. They come after the job's or step's
  `env`. `TMPDIR` equals `LUK_TMP`. Every unit gets `-p PrivateTmp=yes`
  (implied for a dynamic user, explicit with `user`): `/tmp` and
  `/var/tmp` are private to the unit and removed when it ends.
- `LUK_JOB`: the job name (jobs only).
- `LUK_STATE`: only for a job with `state`:
  `/var/lib/lukd-run/<job>/<pipeline>`, from
  `StateDirectory=lukd-run/<job>/<pipeline>` (`StateDirectoryMode=0700`).
  systemd creates it, owned by the job user, before the job starts and
  keeps it after the job ends; `LUK_STATE` equals the `$STATE_DIRECTORY`
  systemd sets. With a dynamic user the directory lives in
  `/var/lib/private/lukd-run/<job>/<pipeline>` (`/var/lib/private` is
  0700, closed to other users) and `/var/lib/lukd-run/<job>/<pipeline>`
  is a symlink to it, reachable inside the unit; systemd moves the
  directory when the job switches between a dynamic user and `user`.
  Removing a job leaves its state directories; the admin deletes them.
- `state: locked`: lukd run holds an exclusive `flock` on
  `/run/lukd-run/<job>/<pipeline>.lock` for the whole run of the job, so
  two runs of the same job on the same pipeline never use the state at
  once. A second request waits for the lock (polling, the job not yet
  started); when its peer closes the connection meanwhile (step timeout,
  stop of lukd), lukd run gives up without starting the job. A run whose
  peer closes keeps the lock until its unit is inactive (see Frames),
  not only until `systemd-run` ends. The lock goes with the process of
  the connection, also on a crash.
  `/run/lukd-run` is the `RuntimeDirectory=` of `lukd-run@.service`
  (root, 0700), writable despite `ProtectSystem=strict`; with
  `RuntimeDirectoryPreserve=yes` it stays when an instance stops, since
  the instances (one per connection) share it and its slot locks, and a
  reboot empties it.
- `state: shared`: no lock; concurrent runs share the directory and the
  job handles that itself.
- The `job start` line of the journal names the job (none for a `run`
  program), unit, user (the dynamic user name without `user`),
  workspace, pipeline and step, and `state=locked|shared` when the job
  has `state`.

Containers. The order of preference for work that needs a container
runtime:

1. None: a plain command in the unit, when no runtime is needed.
2. Rootless podman, the supported container runtime of jobs: a job of
   run.d with a static `user` that has a home and subuid and subgid
   ranges (`/etc/subuid`, `/etc/subgid`), `state: shared` holding the
   podman storage so images persist between runs, and `privileged:
   true` (the setuid `newuidmap` fails under `NoNewPrivileges=yes` with
   `write to uid_map failed`); the host needs the packages `podman`,
   `uidmap` and `passt`. Images come from a registry (the unit has
   network). The job uses `podman run` and `podman exec` with the
   workspace as a volume; the root of the container maps to the job
   user, so what the container writes into the workspace is the job
   user's and travels back like any result. Binding a hidden path into
   a container fails. Not for a dynamic user (no subuid range, no home)
   nor for a `run` program.
3. `groups: [docker]`: possible by configuration, the worst case and not
   recommended: root-equivalent through the daemon, not confined (see
   Sandbox of a unit).

Example: an upload to S3 with credentials `luk` never sees.

```yaml
# /etc/site/lukd/run.d/s3-upload.yaml
user: luk-s3
command: /opt/luk/s3-upload
credentials:
  s3: /etc/site/lukd/s3.credentials
timeout: 1h
env:
  BUCKET: example-backup
```

The job (`contrib/examples/s3-upload.sh`, installed as
`/opt/luk/s3-upload`):

```bash
#!/bin/bash
set -eufo pipefail
IFS=$'\t\n'

work=$1
creds=$CREDENTIALS_DIRECTORY/s3
bucket=$BUCKET

for f in $(luk-job inputs --work "$work"); do
  name=${f##*/}
  # Placeholder for the real upload (aws s3 cp, rclone, s5cmd).
  printf 'upload %s to s3://%s/%s with %s\n' "$f" "$bucket" "$name" "$creds"
done
```

The `run` step that lists the job:

```yaml
pipeline:
  offsite:
    endpoint: [backup]
    steps:
      - run: /opt/luk/offsite
        jobs: [s3-upload]
```

Its program (`/opt/luk/offsite`):

```bash
#!/bin/bash
set -eufo pipefail
IFS=$'\t\n'

luk-job run --job s3-upload
luk-job output --file "$(luk-job input)"
```

A pipeline that only hands its set to a job needs no program: a `relay`
step makes lukd itself ask `lukd run` for the job.

```yaml
pipeline:
  offsite:
    endpoint: [backup]
    steps:
      - relay: s3-upload     # lukd asks lukd run to run job s3-upload as this step
      - store: archive       # gets the same input
```

- lukd prepares the step work directory exactly as for a `run` step
  (`in/`, an empty `out/`, `meta.json`, owned by `luk`), connects to
  `/run/luk/run.sock` and sends the step request with the channel
  (`{"pipeline": <p>, "step": <n>, "id": <id>, "env": {<metadata>}}`,
  see Request flow), the metadata being the free-form variables a `run`
  step there would get; the job gets the set in its workspace. A relay
  step takes no `env` (the environment of the job comes from its run.d
  file and the Step environment) and no `tee` (it always passes its set
  on).
- The next step gets the input set of the relay step unchanged (the
  files and their per-file meta, the upload itself when it is the first
  step), as after a `tee` run step; it may be the last step. Any entry in
  the job's `out/` fails the step (`relay <job>: relay step wrote
  out/<name>`).
- The job's stdout and stderr are the step output, kept like the output
  of a `run` program (`<work>/log`, at most 1 MiB; the last 4 KiB in the
  step error and the log): logged with the failure when the step fails,
  at debug level (`step output`) when it succeeds.
- A non-zero exit status (`relay <job>: exit status N`; a refusal is exit
  status 1 with `lukd run: <reason>` in the output) and a connection or
  protocol error (`relay <job>: dial unix ...`, `relay <job>: connection
  closed before the exit status`) fail the step, with the output tail.
  A job that writes `<workspace>/fail` and exits non-zero fails the step
  with that text as the step error, as a `run` program does.
  The pipeline `timeout` (`relay <job>: timeout after <d>`) and a stop of
  lukd close the connection, so `lukd run` stops the job; the step fails
  or is interrupted as a `run` step is.
- For the rules about steps a relay step is a `tee` run step: it passes
  the upload on (a store after it still counts for `links.max`, and the
  names stay those of the steps before it), but a link replace and the
  transfer dedup (store steps only) exclude it, since a delivery cannot
  be undone.

A job that produces the set of the next step runs as a `run: {job}`
step, for example a database dump job with credentials of its own that
writes the dump into its `out/`:

```yaml
pipeline:
  devdb:
    endpoint: [backup]
    steps:
      - run: {job: db-dump}  # the job's out/ becomes the set of the next step
      - store: publish
```

The step is a `run` step in every rule (the Step contract, `out/`
validation, a link replace, the transfer dedup); its errors name the job
(`run job <job>: exit status N`).

- `lukd check` warns about a job of a `relay` or `run: {job}` step or in
  `jobs` of a `run` step without a file in `/etc/site/lukd/run.d` when it
  can read that directory, about one whose file it can read but that
  does not load (with the reason, e.g. `pipelines: removed`), about a
  valid job that no step names (`unused`) and about any other readable
  job file that does not load. It never requires any of them: run.d is
  root's and changes without a reload. Run as root it also warns when
  the sum of `queue.concurrency` of the pipelines with a `run` or
  `relay` step exceeds `limits.units.max` of `run.yaml` (`queue.concurrency
  of run steps <sum> exceeds limits.units.max <max>: steps wait in lukd
  run`).

`luk-job run` (a nested job) stays for a `run` program that needs
another user's job in the middle of its work, like the program above
that passes its input on with `luk-job output` after the job.

## Client

```
luk send [flags]      (aliases: put, push)

  -f, --file PATH           file to upload; a pipe, FIFO, device or
                            /dev/fd/N is streamed like --stdin
      --stdin               stream standard input
                            (exactly one of --file, --stdin, or a bare --secret)

  -e, --endpoint NAME|URL   endpoint name from the config, or a full URL
                            (URL may carry the lukd pins: "#PIN[,PIN...]",
                            see Pins); default: config "default"
  -k, --key PATH|SHA256:FP  private key file (signs locally; uses
                            PATH-cert.pub when present), a .pub file
                            (selects that key in the SSH agent), or a
                            SHA256:... fingerprint (selects the agent key
                            with that fingerprint); default: the "key" of
                            the endpoint, else config "key", else the first
                            agent key
  -t, --tag TAG             repeatable
      --backup              add backup meta (hostname, absolute path, mtime);
                            regular --file only
      --ttl DURATION|max    lifetime (with --once: the latest moment of the one
                            download); counts where the storage has ttl.user,
                            within its ttl.min and ttl.max; max asks for the
                            longest the storage allows (its ttl.max, else
                            no expiry)
      --once                delete after the first download
      --secret              secret with a reveal page (portal "reveal");
                            alone it reads the content from the terminal
                            twice (both entries must match),
                            masked, sent as a blob with a signed size and
                            sha256, and must be valid UTF-8 (else a usage
                            error); with --stdin or --file the secret comes
                            from there, unchecked; without --type the type
                            is text/plain; charset=utf-8
      --portal              download page with the metadata and a Download
                            button (portal "download"); exclusive with
                            --secret
      --name NAME           file name in the meta (default: base name of a
                            regular --file; none for a stream)
      --type TYPE           Content-Type for downloads (default: with
                            --secret text/plain; charset=utf-8, else by the
                            extension of the name, else octet-stream)
      --pretty-url          ask for a pronounceable name in the URL (a
                            proquint, lusab-babad-gutih-tugad); the
                            endpoint must offer it to the signer
                            (pretty.allow), else 422
      --no-owner            hide the sender on the portal landing page,
                            shown by default: the key name, or host or
                            user for a certificate (meta no_owner)
      --mutable             the content may be replaced later with luk
                            link --file (meta mutable); the endpoint must
                            allow it to the signer (link.replace), else 422
      --private             only the uploading identity downloads it, with
                            luk get, from the luk:// URL answered (meta
                            access private); the endpoint must accept it
                            from the signer (private.owner), else 422;
                            exclusive with
                            --secret and --portal
      --any                 with --private: every identity lukd knows (and
                            the protect expose allows) downloads it (meta
                            access any; private.any); a usage error
                            without --private
      --dry-run             every check on the server up to the body;
                            no body is sent, nothing is stored or run
      --links N             upload N times (default 1, at most 25) with
                            the same options, one link each (see below);
                            a usage error with --dry-run
      --permanent NAME      publish as a new version of the permanent
                            name NAME of the endpoint (meta permanent, see
                            Permanent names); the URL printed is the
                            permanent URL, --json adds version_url; a
                            usage error with --once, --secret, --portal,
                            --private, --mutable, --pretty-url, --links
                            above 1, or an invalid NAME
      --progress            progress on stderr (only when it is a terminal)
      --bwlimit RATE        limit the upload rate, bytes per second with
                            K, M, G, T suffix (10M = 10 MiB/s); 0 or unset
                            = unlimited
      --parallel N          parts in flight at once, 1 to 64 (default 1),
                            at most what the endpoint offers
                            (parts.parallel, see Uploads in parts)
      --json                print the server answer as JSON (exclusive
                            with --quiet)
  -q, --quiet               print only the URL, nothing for an endpoint
                            without one (with --dry-run: the would-be
                            URL); the upload id is in --json

luk get URL (-o|--output FILE [--force] [--inplace] | -O|--remote-name
        [-J|--remote-header-name] [--force] [--inplace] | -c|--stdout | --head [--json])
        [-k|--key PATH|SHA256:FP] [--progress] [--bwlimit RATE] [-q]
                                 download a private file (see Private
                                 files), or a file of a signed expose,
                                 with a signed request (luk-get@v1);
                                 --head prints what the server announces
                                 without downloading
luk get URL/ [-r] [--json] | URL/ -o DIR/ [--force] [-q] [--parallel N]
        [-k|--key PATH|SHA256:FP] [--progress] [--bwlimit RATE]
                                 list a directory of a signed expose (see
                                 Signed expose), or download every file
                                 below it into DIR

luk link URL (--rm | --ttl DURATION|max | -f|--file PATH | --stdin)
         [-e|--endpoint NAME|URL] [-k|--key PATH|SHA256:FP] [--json]
         [--progress] [--bwlimit RATE]
                                 manage a link as its owner (see Links):
                                 --rm removes it, --ttl sets its lifetime
                                 from now (max: the ttl.max of the storage,
                                 else no expiry), --file or --stdin
                                 replaces its content (mutable uploads);
                                 exactly one; --progress and --bwlimit as
                                 for send, with --file or --stdin only
luk link ls [-e|--endpoint NAME|URL] [-k|--key PATH|SHA256:FP] [--json]
            [--any] [--limit N] [--after CURSOR] [--all] [--cursor]
            [-q|--quiet]
                                 list your links on the endpoint (see
                                 Links, list), a page of --limit (default
                                 100, 1 to 1000) after --after, or every
                                 page with --all; --any adds the shared
                                 files (private.list): NAME, SIZE, SENT,
                                 EXPIRES, FLAGS, URL (and CURSOR with
                                 --cursor), then a block per permanent
                                 name; --json: {"links", "permanent",
                                 "next"}

luk config show [--layer global|user]   merged config with the source of
                                 each value and both layer paths; --layer
                                 prints one raw layer
luk config endpoint ls [--layer global|user] [--pin-format words|key]
                                 merged endpoints, one per line: name, URL,
                                 pins (comma separated, words by default)
                                 or -, key or -, source,
                                 * marks the default; the source of an
                                 endpoint with a user key overlay is
                                 global,key:user; --layer lists one raw
                                 layer (an overlay shows - as URL)
luk config endpoint show -e|--endpoint NAME   one merged endpoint: name, url,
                                 pins as stored, key, source, whether it is
                                 the default; with pins, the line under url
                                 is the URL with #<pins>, as endpoint add
                                 takes it; the source of an overlaid
                                 endpoint is "global, key: user"
luk config endpoint add -e|--endpoint NAME --url URL[#PIN[,PIN...]]
                                 [--pin PIN]... [-k|--key PATH|SHA256:FP]
                                 PIN: a lukd key, words or key form (see
                                 Pins); the pins of the URL fragment and of
                                 --pin must agree when both are given
luk config endpoint rm -e|--endpoint NAME   (removing the default clears it)
luk config endpoint key -e|--endpoint NAME (-k|--key PATH|SHA256:FP | --clear)
                                 set or clear the key of one endpoint;
                                 without --global in the user layer: the
                                 key of the user's own entry when it has a
                                 url, else a key overlay on the global
                                 endpoint; --clear removes the overlay (or
                                 the key of the own entry); with --global
                                 the key of the global entry; NAME must be
                                 in the merged config (in the global layer
                                 with --global)
luk config default -e|--endpoint NAME
luk config key (-k|--key PATH|SHA256:FP | --clear)   set or clear the
                                 default key
luk config link ls               merged link hosts, one per line: host,
                                 endpoint, source
luk config link add --url URL -e|--endpoint NAME   use the endpoint for the
                                 links of the host of URL (http, https or luk;
                                 the host is kept lowercase, without the
                                 port); the endpoint must exist in the
                                 merged config
luk config link rm --host HOST
luk config check [--file PATH]   validate config files: with --file that one
                                 file alone (no other layer is read), else
                                 each existing layer and the merged result;
                                 prints ok, or every problem and exit 1
  (all config edits take --global to write the global layer)
  (`endpoint add` moves a pin fragment of the URL into `pin`)
luk scan URL [--pin] [--endpoints] [--print] [--json] [--pin-format words|key]
        [-k|--key PATH|SHA256:FP]
                                 the lukd key of the server and the
                                 endpoints it offers the key (see Endpoint
                                 listing); neither flag: both
luk alias ls                     merged aliases, one per line: name,
                                 expansion (shell-quoted), source
luk alias add --alias NAME -- ARGS...   add or replace an alias; everything
                                 after -- is the expansion
luk alias rm --alias NAME
  (alias edits take --global to write the global layer)
luk NAME [ARGS...]               run an alias: luk EXPANSION... ARGS...
luk version
luk completion bash|zsh|fish|powershell
luk --version
```

`luk link` sends one link request (see Links) to the endpoint given by
`--endpoint` (a name or a URL), else to the endpoint the `link` map of the
config names for the host of the link (lowercase, port ignored), else to
the default endpoint; with none of them it fails with `no endpoint for
host <host>; add one with luk config link add --url LINK -e NAME` (exit 1).
The signing key is chosen as for `send`, for that endpoint. Output on stdout: nothing for
`--rm`; the new expiry (RFC 3339) for `--ttl` (nothing when `--ttl max`
cleared it), with the `ttl_note` line of `send` on stderr; the URL for a
replace; `--json` prints the server answer instead. Every link request
goes through the channel with the pins of its endpoint, as `send`. A
replace sends its content in parts as `send` does (`--stdin` and
non-regular files as a stream), and compares the sha256 of the answer
with its own (exit 4 on a mismatch). Exit codes are those of `send`; a link that is
not there or not the signer's is a 404 (exit 2).

`luk get` sends one signed `GET` (`luk-get@v1`, see Private files) for
URL, or one signed `HEAD` with `--head`: a `luk://` URL (fetched over
https) as `luk send --private` printed it, or the `https://` URL of the
same expose; any other scheme is a usage error. The server is trusted by
the pin of the URL fragment (`#sha256//...` or `#pin=sha256//...`;
another fragment is a usage error) when there is one, else by the system
CAs. The signing key is the first set of: `--key`, the `key` of the
endpoint the `link` map of the config names for the host of the URL
(lowercase, port ignored), the top-level `key`, else the first key of the
SSH agent (the hint of `send` applies to a 401 `unknown key`).

A download needs `--output FILE`, or `-c`/`--stdout` (the same as
`--output -`) for stdout; `-c` with `-o` is a usage error; without either
and without `--head` it is a usage error (`luk get needs -o FILE, -c for
stdout, or --head`, exit 1). The server never names
the local file (its `Content-Disposition` is not used for that), except
with `-J` below. An
existing FILE (a dangling symlink too) is refused unless `--force`
(exit 1, `FILE exists; pass --force to overwrite it`), checked before the
request: on any usage error nothing is sent, so a `once` file is never
claimed by a download that cannot be written. The content streams into a
temporary file in the directory of FILE (`.<name>.luk-*`, created with
mode 0666 less the umask, so FILE gets the mode of any new file), which is
synced, checked and then renamed over FILE with `--force` or hard-linked
to it without (so a file created meanwhile is never replaced); any
failure removes it and leaves nothing. When the answer carries an `ETag`
of a sha256 (lukd's direct downloads do), the content is compared with
it: a mismatch is exit 4 (`sha256 mismatch, nothing written (got <hex>,
want <hex>)`; with `-o -` the content is already written).

`--inplace` writes into FILE itself, without a temporary file or a
rename: an existing FILE keeps its inode (permissions, owner, ACLs, hard
links), and a character or block device, a FIFO or a file on another file
system works. An existing regular FILE still needs `--force` (refused
before the request as above); a device or FIFO (also behind a symlink)
does not. FILE is opened only after a `200` answer, so a refused or
failed request leaves it untouched: a regular file is truncated then, a
missing one created (mode 0666 less the umask; without `--force` never
over a file created meanwhile), a device or FIFO opened without
truncating. FILE is synced before the success exit (`EINVAL` of a device
or FIFO is ignored). A failure leaves FILE as written: a mismatch is
`sha256 mismatch, FILE kept as written (got <hex>, want <hex>)` (exit 4),
a transfer that breaks off adds `; FILE is partial` to its message
(`interrupted after 1.2 MiB of 8.0 MiB; FILE is partial`, exit 130 or
3). `--inplace` with `-o -`, `-c` or `--head` is a usage error (`--inplace
takes no --head, -o - or -c`, exit 1). On success FILE is printed on stdout
(nothing with `-o -`). `--progress` and `--bwlimit` as for `send`, on the
download.

`--head` downloads nothing and never claims a `once` file. It prints what
the server announces, one `key: value` per line, each only when
announced: `name` (the file name of `Content-Disposition`), `size`
(`Content-Length`, in bytes), `content_type` (`Content-Type`), `sha256`
(the sha256 of the `ETag`), `expires` (`Luk-Expires`, RFC 3339 in UTC),
`once` (`true`, from `Luk-Once`). `--json` prints the same as a JSON
object (`{"name": ..., "size": ..., "content_type": ..., "sha256": ...,
"expires": ..., "once": true}`, absent fields left out); `--json` without
`--head`, and `--head` with `--output`, are usage errors. The values of
the lines are escaped as every server text is (see Client), so a file
name with a newline stays on its `name` line; `--json` carries them as
sent.

Exit codes those of `send`: a file that is not there or not the signer's
is a 404 (exit 2), an unknown key or a bad signature a 401 (exit 2).
`-q`/`--quiet` leaves out the FILE line of a download.

`-O`/`--remote-name` (as in curl) stands for `-o FILE` with FILE in the
current directory, named after the last segment of the path of the URL,
percent-decoded (`luk://h/d/my%20file.txt` writes `my file.txt`);
`--force`, `--progress`, `--bwlimit` and `-q` work as with `-o FILE`
(with `--force` an existing FILE, a symlink too, is replaced, never
written through), and the existing-file check still comes before the request.
`-O` with `-o` or `-c` is a usage error (`-O excludes -o and -c`), as
is `-O` with `--head` (`--head takes no -O`) and with a directory URL
(`-O takes no directory URL; use -o DIR/`) and with `--inplace`
(`--inplace takes no -O`: FILE would be opened as it is, a symlink
followed, at a name the URL or the server chooses). The name must be a
bare file name: not empty, not `.` or `..`, at most 236 bytes (so its
temporary file `.<name>.luk-*` fits the 255 bytes of a directory entry;
`longer than 236 bytes`), valid UTF-8, without `/` or `\`
and without the characters the text output escapes (control characters
and NUL among them); anything else is a usage error before any request
(`unsafe file name "a/b" in the URL: a path separator; pass -o FILE`,
exit 1).

`-J`/`--remote-header-name` (only with `-O`; alone a usage error, `-J
needs -O`) names FILE after the file name the server announces, the
`name` of `--head` (the `filename` of `Content-Disposition`; lukd
announces the file name sent, so a drop link with a random name is
saved under its original name). luk sends a signed `HEAD` first (it
never claims a `once` file), so the name is checked and an existing
FILE is refused (unless `--force`) before the `GET`; when the server
announces no name, the URL segment is used as with `-O` alone. An
announced name gets the same checks as the URL segment; one that fails
them is never written anywhere (`unsafe file name "../x" announced by
the server: a path separator; nothing downloaded`, exit 3).

```
$ luk get 'luk://secure.box.example.com/x7Kq...#sha256//Xk9...' -O -J
report.pdf
```

A URL whose path ends with a slash names a directory (the rsync
convention), served by a signed expose (see Signed expose); a URL
without it is a file, as above. `luk get URL/` without `-o` sends a
signed listing and prints it as columns `NAME`, `SIZE` (`512 B`,
`1.5 MiB`), `RECEIVED` (local time, to the minute) and `SHA256` (the
first 12 characters), `-` for what a directory has not; nothing for an
empty directory. `-r` asks for the recursive listing (every file below,
relative names); `--json` prints the entries as a JSON array (`name`,
`dir`, `size`, `received`, `sha256` in full), as the server sent them.
Names are escaped as every server text is (see Client).

```
$ luk get luk://secure.box.example.com/v/
NAME       SIZE     RECEIVED          SHA256
2026/      -        -                 -
db.sql.gz  1.0 MiB  2026-10-03 12:00  9f86d081884c
```

`luk get URL/ -o DIR/` downloads every file of the recursive listing
into DIR, which must end with a slash or be an existing directory (an
existing non-directory, or a missing path without the slash, is a usage
error); a missing DIR is created (mode 0777 less the umask, as are its
subdirectories). Before anything is written every name of the listing
is checked: relative, valid UTF-8, without empty, `.` or `..` elements
and without the characters the text output escapes (control characters
among them), and no name twice; one unsafe name stops the run (`unsafe
name "../x" in the listing: path element ..; nothing downloaded`, exit
3). Then, per file, in the order of the listing:

- the subdirectories are created inside DIR; an element that exists as
  anything but a directory (a symlink to a directory too) fails the
  file: no symlink inside DIR is ever followed (DIR itself may be one);
- a regular file already there is hashed: the same sha256 as the
  listing is `skip NAME`; a different one fails the file (`exists and
  differs; pass --force to overwrite it`) unless `--force`; a symlink,
  directory, device or FIFO there fails the file even with `--force`;
- the file is fetched with its own signed `GET` (the directory URL plus
  the name, each element escaped) through the safe path of a single
  download: a temporary file `.<name>.luk-*` next to it, sha256 checked
  against the `ETag`, synced, then renamed over the old file with
  `--force` or hard-linked without; `get NAME  SIZE  TIME` on success
  (`get 2026/10/db.sql.gz  45.0 MiB  3.0s`: the bytes written and the
  time from the request to the file in place). `--bwlimit` applies to
  each file; without `--parallel` the files are fetched one at a time,
  so the run stays under the rate.

`--parallel N` (1 to 32, default 1; outside a usage error, `--parallel
must be 1 to 32`) downloads up to N files at once, each exactly as
above, with its own signed `GET`; the run stays under N times
`--bwlimit`. The `get` and `skip` lines and the errors then come in the
order the files end, not in the order of the listing; the summary and
the exit code are as without it (that of the failure first in the order
of the listing). Ctrl-C ends every download in flight
and starts no other (exit 130). `--parallel` with a file URL is a usage
error (`--parallel needs a directory URL (ending with a slash) and -o
DIR/`), as is `--parallel` on a directory URL without `-o`.

`--progress`, when stderr is a terminal, keeps one live line on stderr,
redrawn in place at most five times a second:

```
[ 7/20] 2026/10/04/test-149.bin  12.0/45.0 MiB  15.1 MiB/s   total 120.4/248.0 MiB  ETA 0:08
```

`[n/N]` is the place of the current file among all the files of the
listing (skipped and failed files count); with `--parallel` it is the
first of the files in flight, followed by the number of the others
(`[ 7/20 +3]`), and the line is drawn again after every line of the
output while any file is in flight; then the bytes of the current
file against its size (the bytes alone when neither the listing nor the
answer gives one), in the unit of the size, and its rate; then `total`,
the bytes transferred in the run against the bytes to transfer: the
sizes of all the files, less those of skipped files once they are
known to be the same and less what a failed file did not transfer. The
ETA follows from the rate of the whole run, once it has downloaded for
3 seconds. A name too long for the terminal width (80 when unknown) is
cut in the middle (`2026/1...49.bin`). The line is cleared before every
line of the output and every error, so they never mix; without a
terminal there is no live line, and the output is the same with or
without `--progress`. A single file download keeps its own progress
line.

A failed file is reported on stderr (`luk: NAME: <error>`) and the run
goes on with the others; Ctrl-C ends it at once (exit 130). At the end
a summary goes to stdout: `3 downloaded, 2 skipped, 1.2 MiB in 4.1s,
300.0 KiB/s` (with `, N failed` before the size when any failed): the
bytes written, the time of the run after the listing (`2m5.3s` from a
minute) and their rate. `-q` prints only errors. When
any file failed, the last line on stderr is `luk: N of M files failed`
and the exit code is that of the first failure (2 for a 404, 3 for a
transfer, 4 for a sha256 mismatch, 1 for a local conflict). `-c`/`-o -`,
`-O`, `--inplace` and `--head` with a directory URL are usage errors, as are
`--json` with `-o`, `--force`, `--progress`, `--bwlimit` or `--parallel`
without `-o`, and `-r` or `--parallel` with a file URL. A second run of the same command
downloads only what changed.

```
$ luk get luk://secure.box.example.com/v/ -o backups/
get 2026/10/db.sql.gz  1.0 MiB  0.2s
get db.sql.gz  1.0 MiB  0.2s
2 downloaded, 0 skipped, 2.0 MiB in 0.5s, 4.0 MiB/s
$ luk get luk://secure.box.example.com/v/ -o backups/
skip 2026/10/db.sql.gz
skip db.sql.gz
0 downloaded, 2 skipped, 0 B in 0.1s, 0 B/s
```

`luk link ls` sends a link `list` request to `--endpoint`, else to the
default endpoint (none: `no endpoint: pass --endpoint or set default in
the config`, exit 1), signed with the key chosen as for `send`. It asks
for one page of `--limit` links (default 100; outside 1 to 1000 a usage
error `--limit: want 1 to 1000`, exit 1), from the newest, or after the
link of `--after CURSOR` (the cursor of a link, or the `next` of a
page, see Links, list; a malformed one is the 400 of lukd). `--any` asks
for the shared files too (`any` in the meta: the files of access `any`
others sent that the signer may download, when `private.list` admits
it; else just its own links, no error). `--all` follows the pages: it
asks again after the `next` of each page, one request (and one channel
session) per page with the same `--limit` and `--any`, from `--after`
when given, until a page without `next`, and prints all of them as one
list; a `next` that is not the cursor of the last link of its page, a
`next` already followed, a page with `next` but no links, or more than
1000000 links in all is an error (exit 1, the list would not end).

Output: aligned columns `NAME` (the file name sent, `-` without one), `SIZE`
(binary units: `512 B`, `1.5 KiB`), `SENT` and `EXPIRES` (local time
`2006-01-02 15:04`; `never` without an expiry), `FLAGS` (`once`, `mutable`,
then `reveal` or `download`, then `private` or `any`, then `shared` (a
file of another identity listed through `--any` and `private.list`,
read-only), then `permanent`, comma separated; `-` for none), `URL` (the
`luk://` URL of a private file) and, with `--cursor`, `CURSOR` (the
cursor of the link), newest first, under a header line; nothing at all
for no links (exit 0). The current version of a permanent name is a row of its own
with the flag `permanent` and its version URL, which is unique. After
the table, one block per permanent name whose current version is a row
of the table, by name,
each after a blank line: `permanent <name>`, then `  url      <permanent
URL>` and `  version  <version URL>` (exactly the `URL` of its row, the
join key); no block when there is none. A page shows the blocks of the
names whose current version is on that page, so every name is shown on
exactly one page of a walk; with `--all` all blocks follow the whole
list. When more links follow the page (not with `--all`), the command of
the next page goes to stderr after the table (none with `-q`/`--quiet`):
`more: luk link ls -e <endpoint> [-k <key>] [--any] [--limit <n>] --after
<next>`, with the endpoint as given or the default of the config, and
`-k`, `--any` and `--limit` when given, each word quoted for a POSIX shell when
needed; exit 0. The texts are escaped as every server text is
(see Client).

```
$ luk link ls
NAME       SIZE      SENT              EXPIRES  FLAGS      URL
README.md  160 B     2026-10-05 14:04  never    permanent  https://drop.example.com/d/raFvNMX3MD4AVzybvdaHe5N6wBbstByy
data.bin   20.0 MiB  2026-10-05 14:04  never    -          https://drop.example.com/d/Knpa3tPvfh6SDH9suyN93yXP79F7Yzha

permanent example.txt
  url      https://drop.example.com/d/permanent/example.txt
  version  https://drop.example.com/d/raFvNMX3MD4AVzybvdaHe5N6wBbstByy
$ luk link ls --limit 1
NAME       SIZE   SENT              EXPIRES  FLAGS      URL
README.md  160 B  2026-10-05 14:04  never    permanent  https://drop.example.com/d/raFvNMX3MD4AVzybvdaHe5N6wBbstByy

permanent example.txt
  url      https://drop.example.com/d/permanent/example.txt
  version  https://drop.example.com/d/raFvNMX3MD4AVzybvdaHe5N6wBbstByy
more: luk link ls -e drop --limit 1 --after MTc5MTIwMTg0MDAwMDAwMDAwMC4wLjE4OTYzYzEwYTlmMjA4YzNkNjllOTk3MzYzMDBkNzRhLjMyMzAzMjM2MzEzMDMwMzU1NDMxMzIzMDM0MzAzMDVhMmQzMDYxMzE2MjMyNjMzMzY0
```

`--json` prints one object, built by the client from the server answer:

```json
{
  "links": [
    {"name": "README.md", "size": 160, "sent": "2026-10-05T12:04:00Z",
     "flags": ["permanent"], "url": "https://drop.example.com/d/raFv...",
     "permanent": "example.txt", "cursor": "MTc5MTIwMTg0MDAwMDAwMDAwMC4w..."},
    {"name": "data.bin", "size": 20971520, "sent": "2026-10-05T12:04:00Z",
     "flags": [], "url": "https://drop.example.com/d/Knpa...",
     "cursor": "MTc5MTIwMTgzOTAwMDAwMDAwMC4w..."}
  ],
  "permanent": [
    {"name": "example.txt", "url": "https://drop.example.com/d/permanent/example.txt",
     "version_url": "https://drop.example.com/d/raFv..."}
  ]
}
```

`links` (newest first): `name` (omitted without one), `size`, `sent`
and `expires` (RFC 3339 as the server sends them; `expires` omitted
without an expiry), `updated` (the last replace, omitted when none),
`flags` (as the `FLAGS` column, `[]` for none), `url`, `permanent`
(the name the link is the current version of; omitted otherwise),
`shared` (`true` for a read-only file of another identity listed through
`--any` and `private.list`; omitted for an own link) and `cursor` (always).
`permanent` (by name, the names whose current version is in `links`):
`name`, `url` (the permanent URL) and `version_url` (the `url` of its
link). Both arrays are always present, `[]` when empty. `next` is the
cursor to pass to `--after` for the next page, present only when more
links follow (never with `--all`); `--json` prints no hint on stderr. A
permanent name joins its link by `version_url == url`:

```
luk link ls --all --json | jq -r '.permanent[] | "\(.name) \(.url)"'
luk link ls --all --json | jq -r '.permanent as $p | .links[] | select(.permanent) | .url as $u | "\(.name) \($p[] | select(.version_url == $u) | .url)"'
```

Exit codes as for `send`.

`luk send` output on stdout: for `respond: url` (201) the URL and a
newline (the `luk://` URL of a `--private` upload, the permanent URL of
a `--permanent` upload); for `respond:
accept` (202) nothing. `--json` prints the server
answer (the `201`/`202` object) as JSON. `--dry-run` prints the debug JSON
with or without `--json`. `-q` prints only the URL, and nothing for an
endpoint answering without one (`respond: accept`), never more than
without `-q`; with `--dry-run` the would-be URL instead of the debug JSON.
The upload id is in the `--json` answer. Errors go to stderr; `--progress` writes
to stderr. When the answer carries a `ttl_note`, `luk send` writes one line
on stderr, with or without `--json` and `-q`: `luk: ttl 60d capped to 21d
by the server`, `luk: ttl 1d raised to 3d by the server` or `luk: ttl
ignored by the server`. A capped or raised line ends with the range of
the answer when it carries one: `(allowed 1h to 7d)`, `(allowed up to
7d)` with only `ttl_max`, `(allowed from 1h)` with only `ttl_min`; the
ignored line has none. A 202 whose storages give different lifetimes
carries no note, so nothing is written.

`luk send --links N` (N from 1 to 25; above 25 a usage error `--links is
at most 25`) makes N uploads with the same
options, each a request of its own (signature, nonce, new name, new URL,
its own `once` and expiry), and prints the N URLs one per line as they
come (`-q`: the N URLs, nothing without URLs; `--json`: one JSON array of the N answers,
also with `--links 1`; without `--links` the single answer object). The
first upload goes as usual; the later ones carry in the meta the `size`
and `sha256` of the first answer (a stream had none, see Client meta), so
the server can answer them without the content (see Transfer dedup). When
the server answers with the parts offer instead, a regular `--file`
is read again from its start and sent; a stream (`--stdin`, `--file` on a
pipe, a prompted `--secret`) cannot be sent twice: the request is
abandoned and luk stops with `the server asked for the content again for
link <i>, and a stream cannot be sent twice; <n> of <N> links made` (exit
3), the URLs made so far already printed (with `--json` the array of the
answers so far). `--ttl` notes are written once, for the first answer;
`--progress` shows each upload that sends a body; a deduplicated one
prints nothing (`--json` carries `"deduplicated": true`). When the
server refuses one with 429 (the `links.max` of a storage, see Storage)
luk stops with `rejected (429 Too Many Requests): limit of <N> links to
the same content reached; <n> of <N> links made` (exit 2), the URLs made
so far already printed (with `--json` the array of the answers so far).
`--links` takes `--dry-run` as a usage error and works
with every other option and through aliases, as any flag.

`luk` alone prints help, with the aliases of the config in an "Aliases"
section after the commands. No command takes positional arguments, except
the link URL of `luk get` and `luk link` and the URL of `luk scan`, the
object of the command (exactly one; none or more is a usage error: `luk get
needs one link URL`, `luk link needs one link URL`, `luk scan needs one
URL`; `luk link ls` takes none), and the expansion after `--`
of `luk alias add`; a
missing required flag or a stray argument is a usage error (exit 1). The `config` commands validate their input (URL
is http or https with a host, a pin is a lukd key in key or words form,
`default` names an existing endpoint) and write the file
atomically. Each edit reads and writes only the chosen layer, never the
merged values.

`luk config check --file PATH` is strict (unknown keys and a second YAML
document are errors, an empty file is valid): endpoint URLs are http(s) with a host and no fragment, `pin`
is a list of lukd keys in key or words form (a `sha256//` pin is the
error `an endpoint pin is the lukd key: run luk scan URL`), `default` names an
endpoint of that file, `key` and `endpoint.<n>.key` are absolute, start
with `~/`, or are a fingerprint: `SHA256:` and 43 characters of unpadded
base64 of 32 bytes. A missing key file only warns on stderr; a fingerprint
is checked for its form only, not against the agent. For provisioning with Ansible use
`template: ... validate: "luk config check --file %s"`.

`luk scan URL` takes an origin (`https://host:8443`) or an endpoint URL
(`https://host:8443/drop`), `http` or `https`, or a config endpoint name
in place of the URL (its URL and pins); a pin fragment of the URL
(`#PIN[,PIN...]`) is a list of pins as in the config. Only the scheme,
host and port count. `--pin` and `--endpoints` select the parts, neither
is both:

- `--pin` runs the handshake of the channel on the endpoint listing path
  of the origin, without a pin, and prints the key lukd presents on
  stdout: its six words, or the full key with `--pin-format key`. It is
  trust on first use: compare it with `lukd key` on the server. When the
  config (an endpoint of the same origin) or the URL fragment has pins
  and the key matches none of them, the key is still printed, then the
  error `the lukd key <words> matches no pin of this endpoint`, exit 3.
  For an `https` URL whose certificate chain does not verify against the
  system CAs for the host, stderr also gets `download pin: sha256//...`:
  the SPKI pin of the certificate, the one the download links of that
  listener carry (`lukd tls pin`); none for a chain that verifies (an
  acme listener) or for `http`.
- `--endpoints` asks lukd for the endpoint listing (see Endpoint
  listing) in a new session that pins the key just scanned; a key that
  matches no configured pin gets no listing (the signed request is never
  sent to it). The key is `--key`, else the `key` of the config endpoint
  whose URL equals the URL (or that the name names), else the top-level
  `key`, else each key of the SSH agent in agent order, one session each,
  the next one tried only while the server answers 401 `unknown key`
  (all unknown: the error adds `none of the <n> agent keys is known`).

Output: the pin line, then the endpoints as aligned columns under a header
line, by name: `NAME`, `URL`, `RESPOND` (`url` or `accept`), `TTL` (the
`default` of the ttl policy, `never` without one, then the range of a
client ttl when the policy takes one: `(1h..7d)`, `(..7d)`, `(1h..)`,
`(any)`; `-` without a policy) and `FLAGS` (the capabilities granted to
the signing key, see Capabilities: `secret`, `pretty-url`, `private`,
`any`, `mutable` for `link.replace`, `link-rm`, `link-ttl`, `link-ls`,
`permanent`, and `backup-host:any`, `backup-host:principal` or `backup-host:none`
when the endpoint restricts the `--backup` hostname (`backup_hostname`),
comma separated; `-` for none), and when an endpoint has a
quota for the signer `QUOTA` (`10G/1d 50G (12.5G left)`: the rate, the
burst and what the bucket holds now, `, passive` added in passive mode;
`-` for an endpoint without one); no endpoint prints no table.
`--json` prints one object, `{"pin": ..., "download_pin": ...,
"endpoints": [...]}` with the entries of the listing answer, each key
only when asked for (`download_pin` only for a certificate that does
not verify). `--print` prints instead one command per endpoint, `luk
config endpoint add -e <name> --url '<url>#<pin>' [--key KEY]` (the key
scanned, in the `--pin-format`, for every scheme; `--key` the key the
listing was signed with: `--key` as given to scan, else the `key` of the
config endpoint, else `SHA256:<fingerprint>` of the agent key the server
knew; none for the top-level `key`), and the download pin line on
stderr; with `--pin` alone one command for the URL itself, named by its
last path segment, or by the first label of the host for an origin
(`NAME`, a placeholder to replace, for an IP address); a key that
matches no configured pin gets no commands. `--print` and `--json`
exclude each other. When the listing fails the pin is still printed,
then the error, `listing endpoints of <host>: ...`; the exit codes are
those of `send`.

Config has two layers, both YAML with the same schema:

- global: `/etc/site/luk/config.yaml` (`$LUK_GLOBAL_CONFIG` overrides the path)
- user: `~/.config/luk/config.yaml` via the user config dir (`$LUK_CONFIG`
  overrides the path)

Both are read, global first. A missing file is an empty layer; a malformed
one is a config error (exit 1) naming the file. The user layer overrides the
global one per key: `default` and `key` replace when set in the user layer;
`endpoint` merges by name: a user entry with a `url` replaces the global
entry of the same name entirely (URL, pin and key together, nothing is
inherited); a user entry without `url` is an overlay that sets only `key`
on the global endpoint of the same name (`url` and `pin` come from the
global entry):

```yaml
# user layer: sign for the global endpoint drop with another key
endpoint:
  drop:
    key: SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
```

An overlay must have a `key` and no `pin`, and only the user layer may have
one (an entry without `url` in the global layer, or in the one file of
`luk config check --file`, is an error). An overlay without a global
endpoint of its name is an error of `luk config check` and of every command
that loads the merged config (exit 1, naming the user file and the fix,
`luk config endpoint key -e NAME --clear`); config edits still work, so the
overlay can be removed. `alias` merges by name like a whole endpoint
entry, `link` by host. `send`, `link`, `scan` and alias expansion use the
merged result.

`link` maps the host of a link URL (lowercase, without the port) to the
endpoint `luk link` uses for it. `luk config check` checks each host and,
on the merged result (or the one file of `--file`), that each endpoint is
defined. `luk config link rm` without `--global` on a host that exists only
in the global layer fails with "link HOST is defined in the global config;
use --global".

The signing key of `send` is the first set of: `--key`, the `key` of the
endpoint (the one named by `--endpoint`, or `default`), the top-level `key`,
else the first key of the SSH agent. When `--endpoint` is a URL no endpoint
`key` applies. Every key value has the same forms: a private key file, a
`.pub` file of an agent key, or `SHA256:...`, the fingerprint
`ssh-add -l` prints, which selects that agent key (a certificate in the
agent matches by the fingerprint of the key it certifies; the first match in
agent order wins). A fingerprint not in the agent is a config error (exit 1)
naming it. When the server rejects with 401 `unknown key ...` and the key
was the first agent key taken by default while the agent holds more than
one, the error adds: `agent holds N keys; pick one with --key SHA256:... or
set key on the endpoint (luk config endpoint add -e NAME --url URL --key SHA256:...)`. Other keys of
the agent are not tried.

An upload over the quota of the signer is `luk: quota exceeded, try
again in <d>` (429, <d> from `Retry-After`) or `luk: upload exceeds the
quota of this endpoint` (413), both exit 2 (see Quota).

When the server rejects a request with 401 `timestamp outside the allowed
window`, luk also prints `luk: your clock differs from the server by
<d>; check NTP`, <d> being the local clock against the standard `Date`
header of that answer (the server sends no other clock information).

`luk config` edits write the user layer (directory 0700, file 0600). With
`--global` (a persistent flag of `luk config`) they write the global layer:
directory 0755, file 0644 when created; a permission error is a config
error (exit 1) with a hint that `--global` needs root. `endpoint rm` without
`--global` on an endpoint that exists only in the global layer fails with
"endpoint NAME is defined in the global config; use --global". `default`
accepts any endpoint name of the merged config. `key` and `endpoint key`
take exactly one of `--key` and `--clear`; an empty `--key` is a usage
error pointing to `--clear`. `endpoint key --clear` without `--global` on an
endpoint whose key comes from the global layer fails with "the key of
endpoint NAME is set in the global config; use --global".

`luk config show` prints both layer paths with whether each exists, then
the merged config with a `# global` or `# user` comment on every value; the
`key` of an overlaid endpoint has its own `# user` comment.

Aliases are git-style top-level commands. `alias` maps a name to an argv
list. When the first argument of `luk` is not a built-in command and names
an alias, the arguments become the expansion followed by the remaining user
arguments, which are then parsed as usual: `luk drop --file a.pdf` runs
`luk send --endpoint drop --file a.pdf`. Flags of the expansion are
defaults: a flag given in the user arguments removes the same flag (with
its value) from the expansion, so the call wins. Flags are matched by the
target command's flag set: the long and short forms are one flag (`-e`
overrides `--endpoint`), `--flag value` and `--flag=value` both count, and
the scan of either part stops at `--`. A bool flag of the expansion is
turned off with `--flag=false`. User values of a repeatable flag (`--tag`)
replace all of its values in the expansion. A single-valued flag repeated
within the user arguments is a repeated flag (usage error, exit 1), and
mutually exclusive flags (`--secret` in the expansion, `--portal` on the
call) still fail as usual. Rules, checked by `luk alias add`, `luk config
check` (also with `--file`) and when an alias is run:

- the name is not empty, does not start with `-` and has no spaces;
- the name is not a built-in command or command alias (`send`, `put`,
  `push`, `get`, `link`, `config`, `scan`, `alias`, `version`, `completion`, `help`, and
  any other command of the binary);
- the expansion is not empty and its first word is a built-in command or
  command alias, so an alias never expands to another alias;
- a single-valued flag appears at most once in the expansion.

A config that cannot be read only fails a run whose first argument is not a
built-in command; built-in commands (including `luk config check`) and the
help still work. Shell completion offers alias names as first words and
completes the rest of an alias as its expansion. Flags of the expansion
are defaults the call can replace, so completion still offers them and
completes their values; only flags already typed in the call are not
offered again. `--endpoint` completes the endpoint names of the merged
config (also for `luk link`, `luk config link add` and `luk config
endpoint add|show|rm`), `luk alias rm --alias` the alias names, `luk
config link rm --host` the link hosts, `--ttl` offers `max`, `1h`, `1d` and `7d`.
`luk alias rm` without `--global` on an alias that exists only in the
global layer fails with "alias NAME is defined in the global config; use
--global". `luk config show` lists the
merged aliases with their source.

Example:

```yaml
default: drop
key: ~/.ssh/id_ed25519.pub
endpoint:
  drop:
    url: https://lukd.vm:8443/drop
    pin: [lusab-babad-gutih-tugad-hajop-kizof]
  backup:
    url: http://lukd.vm:8080/backup
    pin: [lusab-babad-gutih-tugad-hajop-kizof]
    key: SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
link:
  drop.lukd.vm: drop
alias:
  drop: [send, --endpoint, drop]
  nightly: [send, --endpoint, backup, --tag, nightly, --ttl, 7d]
```

- One file per run. A regular file is hashed first (read twice) and its
  `size` and `sha256` go into the signed meta. `--stdin`, and `--file` on
  anything that is not a regular file (pipe, FIFO, device, process
  substitution), stream in parts without `size`/`sha256` and without a
  `file` name unless `--name` gives one. A directory is an error. A file named `-`
  is an ordinary path.
- An upload is one channel session (see Channel): the handshake (10s),
  the pin check, the signed OP, then the parts and the COMPLETE (see
  Uploads in parts). A refusal answers the OP, before any part. A `201`
  or `202` answer to the OP (or one with `"deduplicated": true`) is a
  success without the content (see Transfer dedup): its size and sha256
  are compared with the signed ones; `--progress` prints nothing for it
  and `--json` shows `"deduplicated": true`.
- A part attempt that makes no progress for 30s, in the sending or in the
  wait for its answer, is cut and sent again (see Uploads in parts). The
  answer to the OP (an upload, a link remove, ttl or list, the endpoint
  listing of `luk scan`) must come within 60s (`the server gave no
  answer within 60s`, exit 3); each attempt of a COMPLETE gets 2m and is
  then sent again. There is no limit on the whole transfer; a slow but
  progressing one is never cut. Only the server counts: time spent
  reading a slow source or pacing for `--bwlimit` never does.
- The signed GET and HEAD of `luk get` give up when the headers of the
  answer do not come within 60s (`the server gave no answer within
  60s`); then every wait for the server is limited to 2m without
  progress, between the bytes of the answer.
- `--progress` prints on stderr, refreshed about every 200ms on one line:
  sent bytes, total, percent, rate and ETA (only sent bytes and rate for a
  stream), then a summary line (bytes, duration, average rate). Bytes are
  counted as the parts are sent; a part sent again counts once. Nothing is
  printed when stderr is not a terminal.
- `--bwlimit` paces the reads of all the parts together to the given rate
  (burst of one read chunk) and stops at once when the upload is
  cancelled.
- The server's sha256 in the answer is compared with the client's own;
  a mismatch is an error.
- Exit codes: 0 ok, 1 usage/config, 2 rejected (401/403/413/422/429), 3 transfer
  or server error, 4 hash mismatch, 130 interrupted (Ctrl-C). A lukd key
  that matches no pin, an answer outside the channel and a result
  unknown (see Uploads in parts) are exit 3; an endpoint without a pin
  is exit 1.
- A request that ends in transit says why, with the bytes of the parts
  lukd verified (of the size, when known) instead of the raw transport
  error: `interrupted after 12.4 MiB of 2.1 GiB`, `no progress for 30s
  after 12.4 MiB of 2.1 GiB` (`no progress for 30s` with nothing to
  count), `connection closed after 12.4 MiB of 2.1 GiB: connection reset
  by peer`, `cannot reach HOST: connection refused` (before any byte);
  `luk get` reports the bytes received of the Content-Length the same
  way, with its `no progress for 120s` and `the server gave no answer
  within 60s`.
- Text from the server that `luk` prints as text (error messages after
  `rejected (...)`, the lines of `luk get --head`, the columns of `luk
  link ls`, `luk get URL/` and `luk scan`, the names of a directory
  download, URLs and expiry times printed on stdout) has every control character (C0,
  DEL, C1), line and paragraph separator (U+2028, U+2029) and
  bidirectional formatting character replaced by its Go escape (`\n`,
  `\x1b`, `\u2028`): a server or another identity can neither drive the
  terminal nor add a line to the output. A server error message is cut
  to 256 characters (ending in `...`). `--json` output is the server
  answer as JSON, unchanged.

## Phases

The delivery, phase by phase; the sections above are the reference.

### Phase 2 - queue, local storage, direct download

Goal: a usable drop (upload, get a URL, download) and archived backups on
disk. Test on lukd.vm / luk.vm.

- Queue as in "Pipelines" (streaming, atomic accept, free-space check
  with 507 and `limits.queue.reserve`); pipelines run asynchronously
  after the answer, `queue.concurrency` per pipeline; queue entries left from a
  previous run are processed at start, temporary files removed.
- Steps: `store` to `local` storage (path template, sidecars,
  `conflict`). A `run` step or an `s3` storage fails the pipeline with
  "not supported yet" (the steps before it stay done); failures are
  logged (status.json comes later).
- Answers 201/202 per `respond`; `dry_run` keeps the debug JSON but is
  answered before the body, which is never sent (no `size`/`sha256` in
  `server`); the client handles 201/202 (prints the URL or nothing, `--json` the
  answer, `-q` only the URL) and
  compares the sha256 from the answer (not for a dry run).
- Expose: `GET`/`HEAD` with the download headers, `Range`, `once`
  (claimed atomically, second download 404), TTL and `ttl.max`, janitor,
  `cleanup.age` (both under the storage), `auth.basic` (bcrypt). Portals `reveal`/`download` answer
  501 "portal not available yet" until phase 6.
- `lukd check` warns about an endpoint that no pipeline uses.

### Phase 3 - run steps

- Work directory `<root>/data/work/<id>/<pipeline>/<step>/` of lukd with
  `in/`, `out/`, `meta.json` (`{"server", "client", "pipeline", "step",
  "produced"}`) and `log`. `in/` holds the current file set: step 1 the
  upload payload named by `file` (the id when empty); later steps the
  previous `out/`. `in/<name>.meta.json` carries the per-file meta from
  the step that produced it.
- The program runs through `lukd run` in a transient unit, as a dynamic
  user, in a workspace of its own (`<root>/root/job/<unit>`, a btrfs
  subvolume) that gets `meta.json` and the files of `in/` as clones
  through descriptors and hands the files of its `out/` back the same
  way. Environment: `PATH` (system default), `LANG=C.UTF-8`, the step's
  `env`, then the `LUK_*` variables (last, so `env` cannot override
  them). Argument: the workspace. On `timeout` (pipeline key, default 1h,
  applied to each run step separately, must be under 7 days) lukd closes
  the connection to `lukd run`, which stops the unit; systemd kills
  every process of its cgroup, and a helper unit of lukd run removes the workspace. stdout and
  stderr go to `log` (capped at 1 MiB); the last 4 KiB go into the
  failure log line and status unless the program wrote a `fail` file.
  The `LUK_*` variables, the in/ and out/ rules, the exit status and the
  `fail` file are the Step contract (Pipelines); `luk-job` is the helper
  for programs; the unit, the workspace and the channel are Jobs with
  other users (Service).
- Stopping lukd (the unit uses `KillMode=mixed`) closes the connections
  of the running run steps, so `lukd run` stops their units, and leaves
  their uploads in the queue: the pipeline is interrupted, not
  failed, and runs again from its first step at the next start. A store
  retried that way is idempotent for the same file (same id, `produced`,
  size and sha256), also when the earlier try was rotated into a version
  since, placed the data without its sidecar, or stopped inside a
  `version` rotation; a program whose output differs between
  runs may store a duplicate version.
- `store` of a multi-file set stores every file: `.File` is the file's
  name, the sidecar keeps the upload's client and server meta and adds
  the file's pipeline meta under `meta`. For a file written by a run step
  the sidecar's `size` and `sha256` are the file's own and `produced`
  holds its name (absent for the uploaded payload); downloads use it as
  the file name.
- A pipeline removes its work directories when it ends, failed or not
  (see Failures); the failure record keeps the output tail. The janitor
  removes work directories without a queue entry after 7 days.

### Phase 4 - catalog and aliases

- `storage.<n>.catalog: true` enables `catalog.json` for a local storage:
  kept in `<base>/.db/catalog.json`, rebuilt atomically after every
  store and every removal, served by expose at `<url>catalog.json` (a
  reserved top-level name: a path template rendering to it fails).
  Format:

```json
{"version": 1, "generated": "...", "generation": 2,
 "files": [{"name": "...", "size": 1, "sha256": "...", "created": "...",
            "tags": ["..."], "meta": {}}],
 "latest": {"<alias>": "<name>"}}
```

- `alias` (a relative name, same rules as a stored path) in a file's
  pipeline meta: lukd keeps `<base>/file/<alias>` as a hardlink of the newest
  file (by acceptance order) declaring it, with its own sidecar marked
  `alias_of`; the catalog lists it under `latest`. When the target goes,
  the alias moves to the newest remaining file declaring it, or goes too.
- Details:
  - The catalog file is `<base>/.db/catalog.json` (outside the data
    tree); the storage `expose` (never a `protect`) maps `<url>catalog.json` to it and
    serves it with `Content-Type: application/json`,
    `Cache-Control: no-store` and `nosniff`. Without `catalog` the name
    is an ordinary file name.
  - The catalog is rebuilt under the base lock after every store, removal
    and `once` claim (temporary file, rename, fsync). `generation` is the
    generation of the base (see Service) the catalog is current at. The janitor's
    removals only mark it stale, and it is rebuilt once at the end of
    each pass; a failed rebuild is retried there too, and every process
    builds it once after start. Each rebuild reads every sidecar of the
    base, so `catalog` suits storages of moderate size. An unreadable
    sidecar leaves its file out of the catalog and is logged; it does not
    stop the rebuild, and the same bad entry does not force one again.
  - Reserved with `catalog` enabled: the top-level stored path
    `catalog.json`. A path template or an alias resolving to it fails.
  - `files` lists stored files only, sorted by `name`; aliases appear only
    under `latest`. `created` is `received`, `tags` the client tags,
    `meta` the pipeline meta (`{}` when none). `once` and portal
    (`reveal`, `download`) uploads are never listed.
  - Aliases work with or without `catalog`. Ties in acceptance order (the
    files of one upload) go to the greater id, then the greater name. An alias that is not a string, is invalid, names an
    existing stored (non-alias) file, or is declared by a `once` or
    portal upload fails the store before the file is placed; an alias
    equal to the file's own stored path is ignored, and so is, later, a
    declaration whose alias path another stored file holds (two
    versioned uploads of `x` both declaring `x`). A store to a path
    that is an alias fails. Replacing a target (`conflict: replace`)
    re-evaluates its alias.
  - An alias is not a stored file of its own: the janitor never expires it
    (its sidecar carries the target's `expires`, so it answers 404 with
    it); removing, expiring or claiming the target moves or removes it.
    Every janitor pass verifies each alias (target present, same id,
    still declaring it, the newest, same inode) and repairs what a crash
    left; the check runs without the lock, which is taken only to
    repair, and a storage without `catalog` and without aliases is
    skipped after the first pass. Downloads use the target's name.
  - The base lock is held only for short steps (on a `catalog` or alias
    base a store, claim or removal also rebuilds the catalog or walks
    the aliases under it, which is O(files)): a store stages its copy
    before taking it, the sweep of crash leftovers re-checks each
    candidate under it, and reading a file with its sidecar takes it
    only when a change of the base ran meanwhile. The file and sidecar
    read always match, and a `once` claim only takes the file that was
    opened.

### Phase 5 - status

- lukd keeps `<root>/data/status/process/status.json` (atomic writes, loaded at start), one
  entry per (pipeline, sender) under `pipelines`: `pipeline`, `sender`,
  `tags`, `last_id`, `last_received`, `last_accepted`, `last_success`, `last_failure`,
  `failed_step`, `error` (last failure, up to 4 KiB), `size`; and the
  watch evaluations under `watch` (see Status).
- `lukd status` prints it: a table of the pipelines and, when there are
  watch records, a table of them (`STORAGE`, `SERIES`, `PIPELINE`,
  `RULE`, `STATE`, `NEWEST`, `SIZE`, `COPIES`, `MESSAGE`); `--json`
  prints the file. checkmk reads the file (a local check).
- The checkmk check makes one service `luk <pipeline> <sender>` per
  pipeline entry, one `luk watch <storage> <pipeline> <origin>/<file>`
  per watched series (`-` for an empty pipeline) and one `luk watch
  <storage> rule <i>` per rule no series matches, with the state and
  message of the record (metrics `age` of the newest copy and `size`):

  ```
  2 "luk watch archive nightly db1-prod/db.sql" age=111600|size=1027604480 db1-prod/db.sql: 980M below min 2G; last copy 31h ago (every 26h)
  1 "luk watch archive rule 2" - rule 2 (origin *-stage): no series matches
  ```

  A record evaluated more than 10 minutes ago is UNKNOWN (`evaluated
  2h 5m ago, is lukd process running? last: ...`): the process role
  evaluates every minute.
- `failed` per entry is the number of failure records with that
  pipeline failed or not run. `contrib/checkmk/luk_status` is the checkmk local check (installed
  to `/usr/lib/check_mk_agent/local/`); its thresholds live in
  `/etc/site/luk/check.conf`.
- Failure records (see Failures). An upload whose pipelines all ended
  with one or more failures is deleted (its queue entry with the payload
  and its work directories) and leaves only its record in
  `<queue dir>/failed/<id>.json`; nothing runs it again, the sender
  sends it again. An upload with successes only is removed without a
  record; an interrupted one (shutdown) stays in the queue as before,
  keeping the results seen so far. Resume and the pickup ignore
  `failed/`.
- `limits.failed.age` (default `3d`, `0` never expires): the janitor
  removes a record written longer ago (`failed_at`), logged as `failure
  record expired`.
- `failed` in status.json is the number of records with that pipeline
  failed or not run and that sender. It is computed from the records at
  start, after each record written and on every janitor pass (every
  minute), so the commands below show up in status.json within a minute.
  `last_failure`, `failed_step` and `error` stay as history.
- Monitoring: `failed` > 0 is CRIT (the checkmk check shows the last error
  and points to `lukd queue ls / rm`). Only `rm` or expiry clears it.
- Commands (read the config given by `-c` for `root` and the queue
  directories, work on files and may run while lukd runs). The files must
  stay owned by the service user, so they run as the owner of
  `<root>/data` (the service user; `<root>` itself is root's): run as
  root, `lukd queue` runs itself again with the uid, the gid of
  `<root>/data` and the groups of that user (environment
  `LUKD_REEXEC=1` prevents a loop) and exits with its status; run as the
  owner it proceeds; any other user gets `lukd queue must run as root or
  as <owner> (owner of <root>/data)` and exit status 1; a `root` or
  `<root>/data` that is a symlink is refused. `lukd status` and `lukd check`
  only read and run as anyone who can read the files.
  - `lukd queue ls [--json]`: the records, oldest first, one row per
    pipeline: id, endpoint, sender, pipeline, state (`ok`, `failed`,
    `not_run`), step (of a failure, `-` otherwise), the time it ended
    and its age, and the detail: the error of a failure (first line,
    control characters escaped, as `lukd status`), the stored outputs of
    a pipeline that succeeded. `--json` prints the records as stored.
  - `lukd queue rm --id ID`: removes the record.
  - An unknown id exits with status 1.

### Phase 6 - portals

- `GET <url><name>` of a `reveal` or `download` upload answers an HTML
  landing page (lukd's own template): name, size, type (without its
  parameters: `text/plain` for `text/plain; charset=utf-8`; the response
  headers keep the full type), sha256, "Sent by"
  (the sidecar's `owner`, see Client meta; not with `no_owner`),
  published (the received time), updated (only after a replace through
  the link, see Links), expiry ("never" without a TTL) and a button. With `no_owner` nothing about the sender appears on the
  page; direct downloads never carry the owner (no header). The
  times are rendered by the server at request time, in UTC to the minute
  with the distance from now: `2026-10-02 17:40 UTC (12 min ago)`,
  `2026-10-03 17:40 UTC (in 23h 48m)`. A nonce'd page script replaces the
  UTC time with the viewer's local time and zone (`2026-10-02 19:40 CEST`);
  the UTC text stays as the tooltip and as the text without script. The
  distance shows the two
  largest units, truncated ("just now" or "in under a minute" below a
  minute, then `12 min`, `23h 48m`, `2d 5h`). The button submits `POST <url><name>/reveal` or
  `POST <url><name>/download`; it reads "Reveal" or "Download", and
  "Reveal and delete" or "Download and delete" for a `once` upload.
- `once` notices: the landing page of a `once` upload shows a notice box
  (accent border and background, light and dark) above the button:
  "**One-time secret.**" and, on the next line, "**It will be deleted as
  soon as it is revealed.**" (reveal), or "**One-time download.**" and
  "**It will be deleted as soon as it is downloaded.**" (download). After a `once` reveal (the in-page reveal and
  the reveal page) the same box reads "**Deleted.**" and, on the next
  line, "**This page is the only copy.**"
- Well-known contract of a `reveal` or `download` upload at `<url><name>`:
  - `<url><name>`: `GET` and `HEAD` answer the landing page (metadata
    and the button), never the content.
  - `<url><name>/reveal` (reveal portal) and `<url><name>/download`
    (download portal): `POST` only, sent by the page (the form or the page
    script); `GET` and `HEAD` are 405 with `Allow: POST`. `/reveal`
    answers the raw content (as `/get` does) when the `Accept` header
    ranks `text/plain` above `text/html` (each by its most specific
    matching range), else the HTML reveal page; either answer carries
    `Vary: Accept`. `/download` answers the content with the download
    headers.
  - `<url><name>/get` (both portals): `GET` and `POST` answer the raw
    content; `HEAD` answers the headers only and never claims a `once`
    upload. A reveal upload answers its bytes as text (below), a download
    upload with the download headers, as `/download` does. No page
    references it.
  - The content is read only through `/reveal`, `/download` and `/get`;
    the first `GET` or `POST` of any of them counts as the download for
    `once`. An expired or claimed upload is 404, a reveal content over
    64 KiB is 413 without being claimed, the 1024-byte body cap below
    applies to every `POST`, and every `POST` passes the cross-origin
    check (`GET` and `HEAD` are not subject to it).
  - On an upload without a portal (`direct`), `<name>/reveal`,
    `<name>/download` and `<name>/get` are 404 like any unknown path; a
    stored file literally named `.../reveal`, `.../download` or `.../get`
    is still served as itself. An action of the other portal
    (`/download` on a reveal upload and the reverse) is 404 too.
  - POST-only actions and `/get` are a convention against link previews
    and prefetchers, which only follow the URL they were given (the
    landing URL, content-free): appending `/get` is a deliberate act of
    whoever holds the link. They are not access control: lukd distributes
    whatever it is given to whoever has the link (and the expose `auth`),
    and protecting the content is the job of the content itself (for
    example kufer encryption).
- Reveal without navigation: on the landing page of a `reveal` portal the
  nonce'd page script intercepts the button and sends the same
  `POST <url><name>/reveal` with `fetch` (same origin, `credentials:
  same-origin`, no body, only the CORS-safelisted `Accept: text/plain`
  header, so the browser's `Sec-Fetch-Site: same-origin` passes the
  cross-origin check) and reads the raw answer as bytes. Content that is
  text (below) is shown on the same page as on the reveal page: a
  read-only text field, the copy button and the `once` notice. Other
  content shows a "Save binary" button and the
  base64 of the content in the read-only field (labeled "Base64") with
  the copy button. "Save binary" saves the bytes already fetched (a `Blob`,
  an object URL and an `<a download>`), never a second request, so it
  works for a `once` upload; the file name is the upload's file name,
  else the link name with `.bin`. The `blob:` URL is a download, not a
  fetch, so the CSP needs nothing for it. An error (404: already opened or expired,
  413, a network failure) is shown as a message on the page. The page
  does not navigate, so a refresh shows the landing page again, without
  a resubmit prompt. Without script the form posts to
  `<url><name>/reveal` and gets the HTML reveal page (the fallback). The
  `download` portal keeps its plain form POST (an attachment, no
  navigation either). The fetch and the action targets are relative URLs,
  so they follow whatever origin served the page.
- `reveal`: the content (at most 64 KiB; a larger `--secret` upload is
  refused with 422 at ingest) in a read-only text field with a
  copy-to-clipboard button. Content is text when it is valid UTF-8
  without control characters other than tab, newline and carriage return
  (the server and the page script decide the same way); other content is
  shown as its base64 (labeled "Base64") on
  the reveal page. `/get` and the `text/plain` answer of `/reveal` stay
  the raw bytes. `download`: the content with the download
  headers.
- Raw text of a reveal upload (`/get`, and `/reveal` asking for
  `text/plain`): 200 with exactly the stored bytes (nothing added, no
  trailing newline), `Content-Type: text/plain; charset=utf-8`,
  `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`,
  `Cache-Control: no-store`, `Referrer-Policy: no-referrer` and no
  `Content-Disposition`; content over 64 KiB is a plain-text 413.
- A `POST` to a portal action (`reveal`, `download`, `get`) announcing a
  body over 1024 bytes, or without a length (chunked), is 413 with
  `Connection: close`, logged at DEBUG. Nothing else is done before (no
  lookup, no claim of a `once` upload) and the body is never read; the
  button sends none.
- Portal pages: `Content-Security-Policy: default-src 'none';
  img-src data:; connect-src 'self'; style-src 'nonce-<n>';
  script-src 'nonce-<n>'; form-action 'self'; frame-ancestors 'none';
  base-uri 'none'` (`img-src data:` for the inline SVG favicon,
  `connect-src 'self'` for the reveal `fetch`; no inline handlers, only
  nonce'd scripts), `X-Robots-Tag: noindex`, `Cache-Control: no-store`,
  `Referrer-Policy: no-referrer`. The content is HTML-escaped.

### Later

S3 storage, kufer
integration (`kufer drop` / `kufer fetch`), packaging: client as a hopper
package (binaries built on GitHub), deb packages via `~/space/packages`.

## Open

- Limits: quota per identity, maximum TTL per endpoint.
- Hash of a stdin stream in the signature (HTTP trailer signed by an
  ephemeral key) - only if needed; trailers get lost in some proxies.
