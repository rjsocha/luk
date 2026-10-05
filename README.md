# luk - SSH-Authenticated Storage Server

luk is an SSH-authenticated storage server (`lukd`) and its client
(`luk`). One file per upload, every request signed with an SSH key: the
server decides by who signed it, not by a shared token. Uploads go through
pipelines that process them and store the results; stored files can be
served over HTTP.

Typical uses:

- **drop**: `luk send --file report.pdf` prints a URL; the file expires by itself.
- **secrets**: one-time links revealed in a browser page, kept in RAM only.
- **backups**: hosts push dumps that are archived, encrypted, transformed
  by scripts and published with a catalog.

## Features

- SSH signatures (SSHSIG) with plain keys, agent keys, hardware keys and
  OpenSSH certificates (host and user CAs).
- A Noise channel between `luk` and `lukd`: the client pins the lukd
  key (`luk scan`, `lukd key`), and HTTP, TLS and proxies only carry
  the encrypted requests.
- Uploads in parts: a failed part is sent again, not the whole file;
  `--parallel` parts at once. Every check (signature, identity, endpoint
  access, size, quota, disk space) runs before the first part.
- Pipelines selected by endpoint and tags: `store`, `encrypt` (OpenPGP, keys
  from files or WKD), `run` (any program), `relay` (an allowlisted job
  as another user, through a small root helper and systemd).
- Links with a TTL, one-time downloads, private files fetched by signed
  requests, mutable links, content deduplication.
- Portal pages for browsers (reveal or download, then delete).
- TLS for downloads: self-signed with pinning, own files, or ACME (HTTP-01).
- Per-identity upload quotas (token bucket), with a passive learning mode.
- Hot reload, `lukd check` before every reload, Checkmk check in
  `contrib/checkmk`.

## Install

Releases carry the `luk` client for Linux and macOS, and Debian packages
(amd64) of `luk` and `lukd`:

```sh
# client
curl -fLo luk https://github.com/rjsocha/luk/releases/latest/download/luk-linux-amd64
install -m 0755 luk /usr/local/bin/luk

# server (Debian 13, systemd 257 or later)
apt install ./lukd_<version>_amd64.deb
```

The `lukd` package installs the units (`lukd.service` groups
`lukd-receive.service` and `lukd-process.service`), creates the user
`luk`, `/etc/site/lukd/` and the identity key
(`/etc/site/lukd/identity.key`, kept on upgrades), and starts nothing.
Examples are in `/usr/share/doc/lukd/examples/`.

From source (Go):

```sh
make build        # luk, lukd, luk-job
```

## Quick start

Server, `/etc/site/lukd/config.yaml` (`root:luk`, `0640`):

```yaml
root: /var/lib/luk

listen:
  main:
    addr: 0.0.0.0:8443
    host: [lukd.example.com]
    tls:
      mode: self
      cert: tls/tls.crt
      key: tls/tls.key
      host: lukd.example.com

endpoint:
  drop:
    listen: main
    endpoint: /drop
    path: queue/drop
    allow: [alice]
    respond: url
    storage: drop

pipeline:
  drop:
    endpoint: [drop]
    steps:
      - store: drop

storage:
  drop:
    type: local
    base: storage/drop
    path: "{{ .Random }}"
    expose: drop
    ttl:
      user: true
      max: 7d

expose:
  drop:
    listen: main
    path: /d/
```

```sh
cp alice.pub /etc/site/lukd/ssh.d/alice.pub   # the identity "alice"
lukd key generate --if-missing                # the identity key (the package creates it)
lukd key                                      # its pin, the six words clients compare
lukd tls generate                             # self-signed certificate, for the download links
lukd check
systemctl enable --now lukd
```

Client (the key comes from the SSH agent):

```sh
luk scan --pin https://lukd.example.com:8443     # the lukd key: compare with lukd key
luk scan --print https://lukd.example.com:8443   # prints "luk config endpoint add ..." with the pin
luk scan --print https://lukd.example.com:8443 | sh
luk send --endpoint drop --ttl 1d --file report.pdf   # prints the URL
```

## Documentation

[doc/SPEC.md](doc/SPEC.md) is the full specification: protocol, server
configuration, pipelines, the `lukd run` helper, TLS, the client and every
command. `luk --help`, `lukd --help` and `luk-job --help` describe the
commands.

## License

Public domain ([Unlicense](LICENSE)).
