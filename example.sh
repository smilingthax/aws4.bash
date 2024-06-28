#!/bin/bash

. aws4_lib.sh

AWS_REGION=eu-central-1
AWS_ACCESS_KEY=...
AWS_ACCESS_SECRET=...

S3_BUCKET=...

# uses AWS_REGION, AWS_ACCESS_KEY, AWS_ACCESS_SECRET
s3_get() { # bucket path [query=]
  local bucket=$1 path=$2 query=$3

  local host="${bucket:+$bucket.}s3.$AWS_REGION.amazonaws.com"
  local dateTime=$(_dateTime)

  local headers="Host: $host
x-amz-content-sha256: $(_sha256Str '')
x-amz-date: $dateTime"

  local fullHeaders=$(printf '' | aws4sign "GET" "$path" "$query" "$headers" "$AWS_REGION" "s3" "$AWS_ACCESS_KEY" "$AWS_ACCESS_SECRET" "$dateTime")

  printf '%s' "$fullHeaders" | curl -s -H "@-" "https://$host$path${query:+?$query}"
}

# list buckets
#s3_get "" "/"

s3_get "$S3_BUCKET" "/" "max-keys=10"

