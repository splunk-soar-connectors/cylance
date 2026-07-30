**Unreleased**

* Encoded device and zone identifiers before inserting them into Cylance API paths.
* Encrypted cached Cylance access tokens in connector state and discarded legacy cleartext tokens.
* Bounded pagination when actions do not specify a result limit.
* Restricted file downloads to the configured Cylance HTTPS host, rejected HTTP errors and redirects, safely extracted one archive member, and verified its SHA-256 before vaulting.
* Verified the actual Cylance global list before treating an already-present hash as successfully blocked.
