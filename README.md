# Bash library to generate AWS Signature Version 4

* Supports both `Authorization` Header signatures and Query String signatures

## Possible TODOs
* Support any posix shell (`/bin/sh`) w/ local, cut ?
* lowercase/trim/sort headers, encode query strings ? (adds dependency: tr)

Requires:
* Bash 3
* date, cut
* openssl
* xxd (could easily be replaced)
* (curl - or similar, to actually use the signature...)

Copyright (c) 2024 Tobias Hoffmann

License: https://opensource.org/licenses/MIT
