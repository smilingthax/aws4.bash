# Bash library to generate AWS Signature Version 4

* Supports both `Authorization` Header signatures and Query String signatures

## Possible TODOs
* Support any posix shell (`/bin/sh`) w/ local, cut ?
* Better support for `AWS_SESSION_TOKEN`?  
  Currently, `X-Amz-Security-Token` must be set manually (headers/query)...

Requires:
* Bash 3
* date, cut
* sort, tr
* openssl
* xxd (could easily be replaced, e.g. by hexdump)
* (curl - or similar, to actually use the signature... [curl < 7.55 would not easily allow multiline headers, though ... --> MORE])

Copyright (c) 2024 Tobias Hoffmann

License: https://opensource.org/licenses/MIT
