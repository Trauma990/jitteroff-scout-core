# Threat model

Untrusted profile authors may attempt SSRF, metadata access, DNS rebinding, output injection or resource exhaustion. The public CLI rejects IP literals and unsupported fields, resolves every check independently, rejects **all** addresses if any answer is non-public, and passes only an approved `IPAddress` to the socket layer. A DNS name is never passed to `ConnectAsync`. Test-only loopback policy is not exposed by the CLI. DNS rebinding between checks is revalidated; a change after validation cannot redirect an in-flight socket.

The scope excludes private network diagnostics, authentication, custom headers/bodies, redirects, packet capture, automatic uploads and system configuration. HTTP headers are capped at 16 KiB, no response body is retained, and the run has strict limits. TLS name and chain errors fail closed. Revocation is explicitly not checked online.

Reports omit raw domains and IPs and use ephemeral HMAC address tokens, but public IDs and context can still identify a profile. Report renderers escape input and the static HTML has no JavaScript or external resources. Users must inspect a report before sharing it. This model does not claim complete anonymity or protection against a malicious binary or operating system.
