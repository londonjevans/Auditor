# Synthetic offline metadata only

This config and its test-generated manifest/index are deliberately non-runnable.
Layer digests are synthetic and their tar blobs do not exist. There is no executable,
contract, credential, registry connection, runtime image or deployment here.

Tests pair valid metadata joins with altered pins, descriptors, platform selection,
encoding and unsafe local file variants. The invariant is that only the exact selected
metadata chain may be observed; no chain, including the valid control, grants image
content, execution, isolation or readiness authority.

Format references: OCI image-spec v1.1.1
[manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md),
[index](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md),
[config](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md),
[descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md).
