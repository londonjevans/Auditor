# Synthetic compiler input-closure control

Both abstract contracts are deliberately non-deployable local test data. The
negative Standard JSON request supplies only `MissingImport.sol`, while the
dependency exists on disk. The captured compiler must refuse that filesystem
import under its explicitly recorded `--no-import-callback` policy. There are no
network dependencies, secrets, funds, external targets, or audit-authority claims.
