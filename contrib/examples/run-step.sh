#!/bin/bash
# Example lukd run step: one gzip dump in, the dump and its checksum out,
# each with meta for the catalog. Needs luk-job in PATH (/usr/bin with the lukd package).
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
