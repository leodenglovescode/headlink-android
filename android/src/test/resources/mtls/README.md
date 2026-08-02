# Throwaway test PKI

Generated once with `openssl` purely so the unit tests can perform a **real** TLS handshake that
requires a client certificate, mirroring the production lookup endpoint.

These keys are worthless. They protect nothing, are committed deliberately, and must never be used
anywhere outside `src/test`. The passphrase for both `.p12` bundles is `testpass`.

| File | Purpose |
| --- | --- |
| `ca.crt` / `ca.key` | Test root CA that signs both leaf certs |
| `server.crt` / `server.key` / `server.p12` | Identity for the in-test TLS listener (SAN: `localhost`, `127.0.0.1`) |
| `client.crt` / `client.key` / `client.p12` | Client identity the tests present for mTLS |

To regenerate, see the `openssl` invocation recorded in
`docs/private-headscale-ipv6-discovery.md`.
