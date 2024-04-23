#!/bin/bash
# aws4_lib.sh shell library to generate AWS Signature Version 4 (AWS4)
# (c) 2024 Tobias Hoffmann

# https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

_hmac() { # hexkey
  openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" -hex -r | cut -d" " -f 1
}

_hmacStr() { # hexkey data
  printf '%s' "$2" | _hmac "$1"
}

_sha256() {
  openssl dgst -sha256 -hex -r | cut -d" " -f 1
}

_sha256Str() { # data
  printf '%s' "$1" | _sha256
}

_hexStr() { # data
  printf '%s' "$1" | xxd -p -c 256
}

_dateTime() {
  date -u +'%Y%m%dT%H%M%SZ'
}

_signingKey() { # region service accessSecret date
  local region=$1 service=$2 accessSecret=$3 date=$4

  local key0=$(_hexStr "AWS4$accessSecret")
  local key1=$(_hmacStr "$key0" "$date")
  local key2=$(_hmacStr "$key1" "$region")
  local key3=$(_hmacStr "$key2" "$service")
  _hmacStr "$key3" "aws4_request"
}

# writes to $sortedHeaders, to preserve trailing newline
_sortedHeaders() { # headers
  local sortedSignedHeaders=$1
  printf -v sortedHeaders '%s\n' "${sortedSignedHeaders%$'\n'}"
}

_headerNames() { # sortedHeaders
  local key value sep=
  printf '%s' "$1" | while IFS=':' read -r key value; do
    printf '%s%s' "$sep" "$key"
    sep=';'
  done
}

_aws4signature() { # region service scope accessSecret dateTime date canonicalRequestHash
  local region=$1 service=$2 scope=$3 accessSecret=$4 dateTime=$5 date=$6 canonicalRequestHash=$7

  local stringToSign
  printf -v stringToSign 'AWS4-HMAC-SHA256\n%s\n%s\n%s' "$dateTime" "$scope" "$canonicalRequestHash"

  local signingKey=$(_signingKey "$region" "$service" "$accessSecret" "$date")
  _hmacStr "$signingKey" "$stringToSign"
}

_aws4request() { # method path sortedQuery sortedHeaders signedHeaders payloadHash
  local method=$1 path=$2 sortedQuery=$3 sortedHeaders=$4 signedHeaders=$5 payloadHash=$6

  printf '%s\n%s\n%s\n%s\n%s\n%s' "$method" "$path" "$sortedQuery" "$sortedHeaders" "$signedHeaders" "$payloadHash"
}

# (unused/debug)
# input: requestPayload
aws4request() { # method path sortedQuery sortedSignedHeaders
  local method=$1 path=$2 sortedQuery=$3 sortedSignedHeaders=$4

  # FIXME... also: sortedQuery is not just the input query, but (potentially) the X-Amz-* auth params...
  local sortedHeaders
  _sortedHeaders "$sortedSignedHeaders"
  local signedHeaders=$(_headerNames "$sortedHeaders")

  _aws4request "$method" "$path" "$sortedQuery" "$sortedHeaders" "$signedHeaders" "$(_sha256)"
}

_aws4sign() { # method path sortedQuery sortedSignedHeaders  region service accessKey accessSecret dateTime  payloadHash  [asQuery=0]
  local method=$1 path=$2 sortedQuery=$3 sortedSignedHeaders=$4
  local region=$5 service=$6 accessKey=$7 accessSecret=$8 dateTime=$9
  local payloadHash=${10} asQuery=${11:-0}

  local date=$(printf '%s' "$dateTime" | cut -d"T" -f 1)
  local scope="$date/$region/$service/aws4_request"
  local credential="$accessKey/$scope"

  local sortedHeaders
  _sortedHeaders "$sortedSignedHeaders"
  local signedHeaders=$(_headerNames "$sortedHeaders")

  local authquery= query
  if (( asQuery != 0 )); then
    printf -v authquery 'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s&X-Amz-Date=%s&X-Amz-SignedHeaders=%s' "${credential//\//%2F}" "$dateTime" "$signedHeaders"
  fi
  printf -v query '%s%s%s' "$authquery" "${sortedQuery:+&}" "$sortedQuery"

  local canonicalRequestHash=$(_aws4request "$method" "$path" "$query" "$sortedHeaders" "$signedHeaders" "$payloadHash" | _sha256)
  local signature=$(_aws4signature "$region" "$service" "$scope" "$accessSecret" "$dateTime" "$date" "$canonicalRequestHash")

  if (( asQuery != 0 )); then
    printf '%s&X-Amz-Signature=%s' "$query" "$signature"
  else
    printf "Authorization: AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s\n" "$credential" "$signedHeaders" "$signature"
    printf '%s' "$sortedSignedHeaders"
  fi
}

# input: requestPayload
# sortedQuery: "a=b&c=d&..."  (NOTE: should not contain any X-Amz-*, to not interfere with _prepended_ authquery [uppercase before lowercase!])
# sortedSignedHeaders: "k1:v1\nk2:v2\n..."  w/ lowercase keys and no spaces, sorted by key
# dateTime: "20240101T10:00:00Z"  (-> from $(_dateTime), also in date / x-amz-date header!)
aws4sign() { # method path sortedQuery sortedSignedHeaders  region service accessKey accessSecret dateTime [asQuery=0]
  local method=$1 path=$2 sortedQuery=$3 sortedSignedHeaders=$4
  local region=$5 service=$6 accessKey=$7 accessSecret=$8 dateTime=$9
  local asQuery=${10}

  local payloadHash=$(_sha256)
  _aws4sign "$method" "$path" "$sortedQuery" "$sortedSignedHeaders" "$region" "$service" "$accessKey" "$accessSecret" "$dateTime" "$payloadHash" "$asQuery"
}

