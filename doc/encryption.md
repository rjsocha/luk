# Decrypting files of the encrypt step

How a receiver opens the files that the pipeline step `encrypt` wrote. The
configuration of the step is in [SPEC.md](SPEC.md) (Pipelines, Encrypt).

## With an OpenPGP key (the normal case)

The step encrypts every file to the public keys of its recipients
(`key` and `wkd`). Any recipient opens a `.gpg` file with the secret key:

```
gpg --output f.txt --decrypt f.txt.gpg
```

In a script, when the step also has `insecure.symmetric` (below), gpg
tries the password first; tell it to skip the password and use the key:

```
gpg --batch --pinentry-mode cancel --output f.txt --decrypt f.txt.gpg
```

Without `--pinentry-mode cancel` gpg writes the right plaintext but exits
with status 2 (verified on GnuPG 2.4.7).

## Passwords: insecure, legacy only

> **Warning.** The options under `encrypt.insecure` are very insecure and
> exist only for receivers that cannot use an OpenPGP key (legacy
> processes). Do not use them for anything new.
>
> - The passwords sit on the server in `password.d`: anyone who can read
>   that directory, or the process role, decrypts every file.
> - A password is only as strong as it is long and random, and it travels
>   to the receiver by some other channel.
> - The `openssl` format has no integrity check at all.
>
> If a password is unavoidable, prefer `symmetric` (a password inside the
> `.gpg` file) over `openssl`: OpenPGP detects a changed or truncated file.

### `insecure.symmetric`: password inside the `.gpg` file

The same `.gpg` file opens with any recipient key or any of the
passwords. The password needs no gpg agent and no key ring:

```
gpg --no-autostart --batch --passphrase-file password.txt \
    --output f.txt --decrypt f.txt.gpg
```

`--no-autostart` keeps gpg from starting an agent; in batch mode gpg reads
the password straight from the file (only its first line). Verified on
GnuPG 2.4.7 with an empty home directory and no agent running.

### `insecure.openssl`: `.enc` files

Files that match `insecure.openssl.files` are written only as `<name>.enc`
in the format of `openssl enc -aes-256-cbc -pbkdf2 -salt` (OpenSSL 1.1.1
and 3.x):

```
openssl enc -d -aes-256-cbc -pbkdf2 \
    -in db-latest.sql.zst.enc -out db-latest.sql.zst -pass file:password.txt
```

The format has no integrity check: a changed or truncated file decrypts
to garbage, or fails only on the padding of the last block. Compare the
result with the plain `sha256` that lukd records for the file (`meta` of
the sidecar, `plain.sha256`).

The openssl command reads at most 1023 bytes of the password file, and
only its first line; lukd refuses longer or multi-line passwords.
