# Local image file membership controls

The helper builds tiny in-memory archives from inert text placeholders and the
committed reporter source. No operating system, real tool binary, credentials,
funds, runtime, extraction, image build/import, or network is involved. Archive
executable bits are metadata under test, not executable host fixture files.

Valid controls are paired with deleted/replaced/mislinked paths, mismatched pins,
malformed records, unsupported metadata and bounded-resource refusals. The parser
implements a restricted [OCI v1.1.1 layer changeset](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md)
view. It uses only fixed-header parsing from the [Python 3.12 tarfile implementation](https://github.com/python/cpython/blob/3.12/Lib/tarfile.py);
it does not call TarFile to read extensions or extract members.

USTAR and bounded local PAX path/linkpath/size/numeric-owner/time/name records are
supported. Global PAX, GNU extensions, sparse files, devices, FIFOs, xattrs,
unknown PAX keys, duplicate names, nonzero padding, write-through-link parents,
and forward/lower-layer hardlinks refuse. This is not a general OCI conformance
claim. The fixed reporter image path is a new membership contract, not an observed
image or a verified launch argument. Versions, transitive dependencies, actual
binary architecture, runtime permissions and execution remain unproved.
