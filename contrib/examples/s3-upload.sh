#!/bin/bash
# Example lukd run job (/opt/luk/s3-upload, job file
# deploy/run.d/s3-upload.yaml.example): uploads the input files of a step
# with credentials only root and this job can read.
# Started by lukd run as user luk-s3 in a workspace of its own, which is
# the only argument and belongs to that user.
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
