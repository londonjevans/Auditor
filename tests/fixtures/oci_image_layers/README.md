# Inert layer-byte controls

Tests package identity.txt into small, deterministic local tar/gzip byte streams.
These are not runnable images: there are no OS tools, executable files, credentials,
contracts, accounts or network routes. Nothing is extracted, imported or executed.

Valid controls are paired with altered digest/size, malformed gzip, truncated footer,
trailing data, bounded expansion, changing files and unsupported codec controls.
The invariant is exact stored and uncompressed byte identity within shared limits;
tar semantics, filesystem overlays and runtime/executable identity remain unproved.

References: [OCI diff IDs](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md),
[Python 3.12 bounded zlib decompression](https://docs.python.org/3.12/library/zlib.html),
[gzip member format](https://www.rfc-editor.org/rfc/rfc1952.html).
