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

_trimStr() { # string
  local str=$1
  str="${str#"${str%%[![:space:]]*}"}"
  str="${str%"${str##*[![:space:]]}"}"
  printf '%s' "$str"
}

_lowercaseStr() { # string
  printf '%s' "$1" | tr "[:upper:]" "[:lower:]"
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

# query can be &-separate or \n-separated
_sortedQuery() { # query
  local query=$1

  # Trick: -u deduplicates empty lines to single one at the beginning. Also, $() removes trailing \n.
  local sorted_lines=$(printf '%s' "$query" | tr "&" "\n" | sort -u)
  printf '%s' "${sorted_lines#$'\n'}" | tr "\n" "&"
}

# writes to $sortedHeaders, to preserve trailing newline
_sortedHeaders() { # headers
  local headers=$1
  printf -v sortedHeaders '%s\n' "$(
    local key value
    printf '%s\n' "${headers%$'\n'}" | while IFS=':' read -r key value; do
      printf '%s:%s\n' "$(_lowercaseStr "$key")" "$(_trimStr "$value")"
    done | sort)"
}

_headerNames() { # sortedHeaders
  local IFS=$'\n'
  set -- $1
  IFS=$';'
  printf '%s' "${*/:*/}"
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
aws4request() { # method path query headers
  local method=$1 path=$2 query=$3 headers=$4

  # FIXME... also: sortedQuery is not just the input query, but (potentially) the X-Amz-* auth params...
  local sortedHeaders
  _sortedHeaders "$headers"
  local signedHeaders=$(_headerNames "$sortedHeaders")

  local sortedQuery=$(_sortedQuery "$query")

  _aws4request "$method" "$path" "$sortedQuery" "$sortedHeaders" "$signedHeaders" "$(_sha256)"
}

_aws4sign() { # method path query headers  region service accessKey accessSecret dateTime  payloadHash  [asQuery=0]
  local method=$1 path=$2 query=$3 headers=$4
  local region=$5 service=$6 accessKey=$7 accessSecret=$8 dateTime=$9
  local payloadHash=${10} asQuery=${11:-0}

  local date=$(printf '%s' "$dateTime" | cut -d"T" -f 1)
  local scope="$date/$region/$service/aws4_request"
  local credential="$accessKey/$scope"

  local sortedHeaders
  _sortedHeaders "$headers"
  local signedHeaders=$(_headerNames "$sortedHeaders")

  local authquery=
  if (( asQuery != 0 )); then
    printf -v authquery 'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s&X-Amz-Date=%s&X-Amz-SignedHeaders=%s' "${credential//\//%2F}" "$dateTime" "$signedHeaders"
  fi
  local sortedQuery=$(_sortedQuery "$authquery&$query")

  local canonicalRequestHash=$(_aws4request "$method" "$path" "$sortedQuery" "$sortedHeaders" "$signedHeaders" "$payloadHash" | _sha256)
  local signature=$(_aws4signature "$region" "$service" "$scope" "$accessSecret" "$dateTime" "$date" "$canonicalRequestHash")

  if (( asQuery != 0 )); then
    printf '%s&X-Amz-Signature=%s' "$sortedQuery" "$signature"
  else
    printf "Authorization: AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s\n" "$credential" "$signedHeaders" "$signature"
    printf '%s' "$headers"
  fi
}

# input: requestPayload
# query: "a=b&c=d&..." or "a=b\nc=d..."
# headers: "k1: v1\nk2: v2\n..."
# dateTime: "20240101T10:00:00Z"  (-> from $(_dateTime), also in date / x-amz-date header!)
aws4sign() { # method path query headers  region service accessKey accessSecret dateTime [asQuery=0]
  local method=$1 path=$2 query=$3 headers=$4
  local region=$5 service=$6 accessKey=$7 accessSecret=$8 dateTime=$9
  local asQuery=${10}

  local payloadHash=$(_sha256)
  _aws4sign "$method" "$path" "$query" "$headers" "$region" "$service" "$accessKey" "$accessSecret" "$dateTime" "$payloadHash" "$asQuery"
}

