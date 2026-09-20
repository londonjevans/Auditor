# Offline OpenTimestamps replay and calendar wire data

`models.opentimestamps_replay.replay_detached_opentimestamps_proof` decodes a
bounded detached proof and calculates every admitted operation path. Its output
contains calculated commitments and **untrusted** attestation metadata, not a
verified publication, time, Bitcoin block, independent seal or release capability.
The ordinary dataclasses are constructible data and are not accepted as authority.

## Reference and provenance

The operator initially supplied seven ignored, untracked files under
`.mmaudit/operator-shared/opentimestamps-spec/`. `PINNED_COMMIT.txt` records
`python-opentimestamps` commit `3af46432efc4a4c4e7bba439c1f49bce808eb3e5`.
This is locally supplied provenance, not an independently authenticated upstream
checkout. All seven files were read; none was imported, executed, copied into
tracked files, or added as a package dependency. The staged LGPL-3.0-or-later
implementation remains a read-only format reference. The decoder and synthetic
fixtures were written independently from format facts, without vendoring upstream
code or its explanatory text. Ignore status was checked per file together with
absence from Git's index; ignoring a file alone is not a publication guarantee.

Local SHA-256 observations:

| Supplied file | SHA-256 |
| --- | --- |
| `PINNED_COMMIT.txt` | `fb03cde16a82b57ec6e1d6fbbe968f7cbed3dab88550133c54021f7af3e53f4d` |
| `opentimestamps_core_serialize.py` | `a572336d47c7e5a0b46af25583a040c0ca3816c9959ca8b459fb4de2430ffbf1` |
| `opentimestamps_core_op.py` | `a1159335fa7c558c93c6ff1dd40c872bcc8e0872d4de1a07f0ca23ed5719cf4b` |
| `opentimestamps_core_notary.py` | `71d0fcb7392af84afd55e31088c6828884c512894ee7954c3159ce4a0e0c6436` |
| `opentimestamps_core_timestamp.py` | `227e9a756099b8aeac15dfaa4fa7c03d01e4d076385e42d9cbec83f66605fc23` |
| `README.md` | `297044a0959f664b052d160247e2a9f193f6d5453185c6295f99d9f29b810e87` |
| `LICENSE` | `5218fc3db03e0f5ed0edec8912e124c493899e4be83a5bf60d9e5b1286f8f554` |

The local source corrects two details in the operator's 13:10 report. The detached
envelope writes one version byte, not two version fields. A Bitcoin attestation
stores a height; replay produces a commitment to compare with the Merkle root of
a separately sourced block header. The staged source does not establish that a
caller-provided header belongs to the accepted chain. The operator's broader
repository survey and claim of protocol suitability are not independently verified.
The frozen objective's actual authority/no-signer requirements remain in clause 2;
the report's clause numbering does not amend them.

The 2026-09-10T15:37Z operator entry expanded the supplied input set to 28 regular
files: two additional library modules, seven client files and twelve fixture/note
files. Every file was locally hashed and individually verified ignored and absent
from Git's index. The client pin is
`cd71c7609421bed2a07b9642a3c02a58c9fd2cdf`, also operator-supplied provenance, not an
independently authenticated checkout. The additional calendar and Bitcoin proof
construction modules were read in full, as were the client README and relevant
creation, upgrade, verification and common-option paths. Unused client paths were
not treated as reviewed. No reference code was executed or copied into the build;
the client licence body was compared with the already-read library licence.

Relevant new local source observations:

| Supplied file | SHA-256 |
| --- | --- |
| `opentimestamps_calendar.py` | `6061e5baf8da6840e12b8ca6a32cb1f57e644db3af54bd6877f28b2422c51c17` |
| `opentimestamps_bitcoin.py` | `37926b37c01338ef0d5eb166f2a5ab0d95142d25fd8730d43465c85f9ec39cf0` |
| `client/PINNED_COMMIT.txt` | `9b947f2d402b3a52f7ee791c464d9048703b97c94ca4f1e94c60064d0c97d5e3` |
| `client/README.md` | `458e56efdff99a4fbe1cd705a9c41f9a6e13673ed15dff7bfe27fde27a26ad2b` |
| `client/args.py` | `9e853680b40d1b5890e258a62ece167ca932e3dc72230de67dcf493ccdab1a0a` |
| `client/cmds.py` | `c20e8f770ae76e5d646d83ddf33c5c6edd15d12f07fd4610bc035b4601b53d25` |

The inspected verification path delegates block selection to Bitcoin Core through
`getblockcount`, `getblockhash(height)` and `getblockheader(hash)`, then compares
the calculated Merkle root and reads the header time. It is not a header-chain
consensus verifier. Neither that delegation nor the location of a node alone
establishes independently authenticated chain evidence. The reference's proof
"complete" predicate merely checks for a Bitcoin attestation; this project does
not adopt it as verification. Wallet, signing and broadcast paths are out of scope.

The [external seal acceptance review](remediation/v3/external_seal_verification_review.md)
separates checkpoint/history binding, chain authentication, pre-dispatch chronology
and independent rerun. Synthetic counterexamples show why the current subject-only
stamps cannot select between conflicting local log histories, even when each
history passes the original structural comparison. They do not demonstrate a gate
bypass: the recording and comparison outputs correctly remain nonauthorizing.

The separate [checkpoint publication adapter](calibration_checkpoint_publication.md)
now binds that exact checkpoint/history in a new versioned envelope using original
source custody and the shared once-only journal. A separate explicit checkpoint
controller now joins it to the actual registered/native batch lifecycle while
preserving old subject-only receipt meanings and entrypoint defaults.
Chain authentication, chronology, independent reproduction and seals remain gaps.

## Admitted wire subset

The reader requires the detached-file magic, version `1`, SHA-256 hash tag `0x08`,
and the exact expected 32-byte file digest. It supports SHA-256, append, prepend,
reverse and lower-case hexlify operations. It walks every branch using an explicit
stack; an unsupported operation anywhere refuses the whole proof. SHA1, RIPEMD160
and Keccak are unsupported, not silently treated as SHA-256 or SHA3. This is a
documented local subset, not a claim of complete OpenTimestamps compatibility.

Bitcoin payloads must contain only a minimally encoded height and attach to a
32-byte commitment. Pending payloads must contain only the bounded ASCII URI
encoding; URIs are neither returned nor followed. Other attestation tags are
retained as opaque metadata using their tag and payload hash, with no verification
credit. Pending-only and opaque-only proofs can be inspected successfully without
becoming completed Bitcoin evidence.

Local admission bounds are 1 MiB of proof bytes, 4096 total entries, 256 node levels,
1024 attestations, 4096 bytes per operation result and 8192 per attestation payload.
Pending URI bytes are limited to 1000; the claimed height is limited to unsigned
32 bits. Minimal unsigned LEB128 encoding is required, with at most five bytes.
The reference reader also accepts some redundant encodings; rejecting them and
duplicate node entries is an explicit local restriction. Empty binary arguments,
oversized intermediates, truncated continuations, trailing bytes, malformed known
payloads and duplicate entries refuse without returning a partial result.

`expected_file_sha256` is the exact digest stored in the detached envelope. No
automatic conversion equates a subject digest, the hash of its 32-byte binary
representation and the hash of its textual hex representation. Any future publisher
must bind its chosen file/digest convention explicitly to the existing
`calibration_publication_request` subject.

## Calendar wire boundary

`models.opentimestamps_calendar` prepares constructible request data and handles
caller-supplied complete reply bytes. It has no HTTP client, chosen origin,
credential, file access, entropy source or authority-bearing capability.

| Operation | Relative path / body | Admitted reply |
| --- | --- | --- |
| `SUBMIT` / POST | `digest` / raw 32-byte commitment | HTTP 200 and a complete raw timestamp tree |
| `LOOKUP` / GET | `timestamp/<commitment hex>` / empty body | HTTP 200 and a complete raw timestamp tree; HTTP 404 means unavailable |

Requests carry fixed public `Accept: application/vnd.opentimestamps.v1` and
`User-Agent` headers. The method, relative path, headers, body, operation and
commitment must exactly match their prepared wire contract at response admission;
arbitrary data objects, altered fields and scalar subclasses refuse. Lookup
commitments may contain 1–4096 immutable bytes; the local submission profile
requires 32. No pending URI is returned, followed or selected as an origin.
Non-200 replies, including redirects, do not produce replay results. A lookup 404
is neither success nor permanent irrecoverability; a submission 404 is an error.
Error bodies are bounded but not reflected in errors.

`replay_opentimestamps_calendar_proof` reuses the original all-branch walker at
the exact caller-supplied commitment. It accepts 1–10,000 bytes of raw tree data,
not a detached-file envelope. All original operation, message, payload, entry,
depth, duplicate and EOF restrictions remain. No unsupported cryptographic
algorithm has been enabled. The reference calendar reads at most 10,000 bytes
before checking whether it read more than 10,000; that cannot detect overflow.
This codec checks the whole byte string it receives, but cannot prove a caller
did not truncate a transport stream. The owned transport below supplies complete
HTTP-message consumption and rejects overflow; a caller invoking only the wire
codec still has to establish transport completeness separately. HTTP-stack
buffering and application proof retention are different bounds.

`prepare_opentimestamps_submission` calculates
`SHA256(bytes.fromhex(file_sha256) + nonce)` using the caller's exact 16-byte nonce.
It submits neither source bytes, the unmasked file digest nor textual digest hex.
Nonce freshness/unpredictability is not proved by a byte-length check; the fixed
synthetic test nonce is not a production entropy source. The caller/owner must
provide fresh entropy under a future selected publication profile.

`assemble_opentimestamps_submission_proof` requires the original matching
submission context and an admitted raw reply, adds the detached SHA-256 envelope
and nonce append/hash operations, then replays the entire assembled proof again.
That second replay counts the two added operations against the original depth
and entry bounds. It returns only bytes, even when the proof is pending-only or
claims a false Bitcoin height. A changed file or nonce against the original
request refuses. Coherently replacing the whole request/context, or supplying a
different syntactically valid raw tree, can calculate a different root without
proving it authentic. Original transport custody and independent anchoring remain
necessary; these constructible values are not a receipt or a release permission.

## Owned calendar transport

`orchestration.opentimestamps_calendar_transport` owns a fresh HTTP client for
each submission or lookup. There is no default calendar or public client/transport
injection parameter. `calendar_origin` must be an explicitly supplied canonical
HTTPS origin without a path, user information, query, fragment or encoding tricks.
`allow_calendar_contact` defaults to false and must be exactly true before entropy
or network work. This is up-front authorization for a future selected run, not a
mid-run confirmation prompt; no live origin has been selected by this work.

The client uses default certificate/hostname verification, disables ambient proxy
and certificate configuration, and follows no redirects. One connection, no
keepalive reuse, no shared cookie jar, no authentication and no automatic retries
are configured. Requests add `Accept-Encoding: identity` and `Connection: close`
to the existing fixed public protocol headers. Lookup uses only its explicit
origin and commitment, never a URI supplied by a pending attestation.

Replies are consumed as raw bytes, without decompression, until HTTP message
framing completes. A complete tree in an unfinished chunked message is not yet a
result. Compressed bodies, ambiguous transfer/length headers, oversized or invalid
declared lengths, more than 128 headers or 16,384 header name/value bytes, and any
body beyond 10,000 bytes refuse. EOF-delimited responses require EOF; declared
lengths are compared with the complete received body. Failed HTTP statuses do not
cause an error body to be consumed or reflected. Lookup 404 keeps the existing
unavailable result; all other failed statuses refuse.

The pinned HTTP stack (`httpx` 0.28.1, `httpcore` 1.0.9, `h11` 0.16.0) was inspected
locally. HTTPCore can buffer 64 KiB per socket read, and HTTP headers have already
been parsed before the application checks its header bound. Therefore this is a
10,000-byte retained-proof limit, not a claim that total network buffering or
socket reads are limited to 10,001 bytes. Oversized raw chunks are rejected before
copying them into the proof buffer or requesting another chunk. Framing completion
means end of this HTTP message, not proof that a peer sent no other TCP bytes.

The exchange has a cooperative aggregate timeout of 0.05–60 seconds, with bounded
per-operation HTTP timeouts. Response and client cleanup each have a separate
one-second bound; a failed close still attempts the other close, and no failed
cleanup can return an observation. Synchronous source validation, proof assembly,
OS/DNS work and process scheduling are not preemptively bounded by this coroutine
deadline. Original request method/URL/headers/body and response identity/status/
headers are checked across awaited processing and cleanup.

Submission generates its own 16-byte nonce with `secrets.token_bytes`, then uses
the existing wire preparation and full detached assembly recheck. A dispatched
POST failure may already have published a commitment. `CalendarTransportError`
retains that uncertainty and the exact original submission context; it never
silently resubmits. `CalendarSubmissionCancelled` remains an `asyncio.CancelledError`
and carries the original file digest, nonce, request and origin for its immediate
consumer. These bare transport APIs retain only in-memory recovery data. The
separate journal below persists preparation before dispatch; an exception is
never a successful receipt.

`submit_calibration_publication_calendar` consumes the existing
`calibration_publication_request(subject)` and explicitly treats its 32 binary
digest bytes as the timestamped file. Thus the detached file digest is
`SHA256(bytes.fromhex(subject.subject_sha256))`, and the posted commitment is
`SHA256(that_file_digest + nonce)`. Neither the full subject/journal/source/ledger,
the unmasked subject digest nor textual hex is sent. The exact subject is
revalidated after awaited transport; a changed or coherently replaced subject
refuses while retaining possible-publication uncertainty. This convention is
implemented but not adopted as the frozen objective's external publication policy.

Transport observations are ordinary constructible data, not authenticated
transport-source capabilities, Bitcoin-chain proofs, publication time, full
population provenance or qualification/release authority. Unit tests explicitly
substitute isolated streams. Real integration tests use a disposable numeric
loopback HTTP listener and a test-only transport mapping from a reserved `.invalid`
origin; they exercise HTTP framing and cleanup, **not** real-calendar TLS origin
authentication. No external calendar, node or provider was contacted. The initial
14 listener-denied skips were not counted as passes; all 14 subsequently passed
under permission scoped to that local test command.

## Durable request and lookup-only recovery journal

`orchestration.opentimestamps_calendar_journal` adds a separate local owner.
`prepare_calibration_calendar_journal` is an offline context manager: it creates
one new private directory, generates the original nonce and writes a canonical
`PREPARED` event. Its returned owner exposes the preparation hash before any
network call. Retain that pin, the original publication subject and exact origin
outside the journal for recovery. This offline preparation requires no contact
permission; `owner.submit` still requires explicit up-front contact authorization.

The owner exclusively creates 0600 event files, using the existing evidence
writer's complete writes, file/directory fsync and inode/readback checks. The
second event, `POST_STARTED`, is durably written before entering HTTP. The original
subject/file/nonce/origin/method/path/public headers/commitment/body are bound by
the preparation hash and repeated in every hash-linked event. The existing binary
subject-digest-file convention is unchanged. Completed exchanges are reassembled
against the original nonce; their event kind says `REPLAYED`, not verified.

A fresh owner admits at most one POST and must remain inside its context through
submission and scope exit. `load_calibration_calendar_journal` is offline;
`recover_calibration_calendar_journal` can only GET the original commitment from
the original origin. Reopening a preparation that never reached dispatch does
not permit POST. A missing POST outcome may be followed by a lookup intent without
erasing the missing outcome. Unavailable, failed and cancelled lookups each retain
their own attempt; even an interrupted lookup consumes one of the fixed 16 slots.
There are at most 35 events of 32,000 bytes each, with no more than 10,000 raw proof
bytes per replay. An outcome slot is reserved before starting each lookup.

The owner holds a nonblocking POSIX lock on the original directory descriptor,
not a replaceable lock file. Separate opens/processes refuse concurrent access;
an inherited or closed owner cannot dispatch. Unsupported local process exclusion
refuses, rather than silently using an unlocked fallback. The directory must be
0700 and owned by the current effective user; every event remains a private,
unlinked regular file. Ancestor/root/file identity, canonical bytes, in-memory
event bytes, exact names and the complete retained prefix are rechecked through
I/O and awaited HTTP. A failed scope close cannot complete the enclosing handoff.

Failures and cancellation retain original recovery context and report whether
their outcome could be written. An acknowledged intent without an outcome is not
success. The writer does not use atomic rename: an abrupt process loss can leave
a partial final file. Such tails, gaps, extras, conflicting context, replaced
inodes, links or malformed transitions refuse **without truncation or repair**.
No replayed prefix is returned as a substitute for that inconclusive history.

These guarantees cover tested process loss at acknowledged durable boundaries,
not machine power loss, a compromised filesystem or a coherent adversarial rewrite
or rollback of local history. Local ordering and self-hashes do not establish
external pre-dispatch chronology. All serialized authority flags remain false;
chain/header authentication, confirmation/reorganization policy, actual external
publication and full-population sealing are still required. The journal is not
yet wired into a complete pre-dispatch population controller or native release issuer. Tests
use independent synthetic data, fresh disposable processes and numeric-loopback
HTTP only; no real calendar, node, provider or upstream code is executed.

## Source-owned population publication handoff

`orchestration.calibration_calendar_publication` connects the existing full-population
subject producers to that journal. Registration preparation reads the original
single-event population journal. Measurement preparation requires the original
live measurement and ledger inside their owned scope, plus the exact earlier
registration descriptor. It preserves the entire original registration/population
join and the unchanged native policy proposal or numeric-support refusal.

The adapter creates one separate private output containing `subject.json`,
`publication.json` and the child `calendar/` journal. The descriptor binds the
canonical subject file, original registration event, predecessor descriptor (for
measurement), original calendar preparation and explicit binary-digest-file
convention. Both files are retained and synced before its prepared owner permits
POST. Callers can retain the descriptor's `publication_sha256` before dispatch;
the full private subject and unmasked digest are never sent to a calendar.

Original producer identities/code, population-file custody, original live field
and verification identities, and the exact ledger snapshot remain checked before
and after the HTTP await and through child-scope cleanup. An equivalent-looking
replacement proof is not the borrowed original. Subject/descriptor/preparation
file identities and exact private directory membership stay checked as well.
Callers must finish the enclosing prepared scope before treating a handoff as
completed. A child `REPLAYED` event can survive a later source-custody refusal;
that event remains data and does not imply a successful source-owned handoff.

Offline readback and explicitly authorized recovery consume only the externally
pinned descriptor and its retained subject. Recovery can GET the original
commitment after process loss or loss of the original source, but cannot recreate
native custody, repeat POST, repair partial files or grant authority. Measurement
descriptors cannot substitute for registration; local predecessor linkage alone
does not prove the registration was externally published before model execution.

The standalone preparers can still create a registration descriptor without any
submission; that is not an external pre-dispatch seal. The optional controller
below connects the handoff to the actual batch boundaries. Authenticated calendar/chain/header
evidence, actual externally anchored chronology/full-population seals, native
policy/release adoption and independent qualification remain required. Every
serialized authority flag remains false. Synthetic isolated native-protocol tests
exercise the handoff; the original production native verifier rejects those
fixtures. No real campaign, publication or qualified audit is inferred.

## Actual batch-boundary recording controller

`calibration_calendar_controller.execute_calendar_recorded_calibration_measurement`
adds an explicit two-phase recording path over the original registered batch and
native measurement owners. Existing no-calendar entrypoints retain their defaults.
The caller supplies separate new registration/measurement publication roots, the
original private population/measurement roots, a canonical HTTPS calendar origin
and exact `allow_calendar_contact=True`. No endpoint, paid permission or trust
profile is selected by default. One cooperative deadline includes both exchanges,
all original batch work, native disposal and final readback; original batch and
exchange deadlines remain enforced too.

The actual ownership sequence is:

1. The registered owner writes the full original population, then records one
   source-owned registration exchange before any preflight. Failed or cancelled
   exchange stops this path; no retry or shortened population is substituted.
2. Every available original preflight remains visible, including refusals when
   another slot is missing. Only the existing authenticated preflight/lineage/cost
   checks can admit runner work. The calendar response cannot supply permission.
3. The original native measurement owner records its complete measured population
   while the original proof is live, preserving either the unchanged policy
   proposal or its numeric-support refusal.
4. All native calibration, runner and accounting owners are disposed. The
   controller then returns detached observations joined to the original completion,
   after rechecking original phase files, native output/receipt files, population
   custody and the exact final ledger on both sides of calendar readback.

An internal task/process-bound, single-use handle controls these phases. It is not
constructible from disk, a generic caller callback, a native measurement proof or
an external-log capability. The controller retains the creator's original child
event inodes before journal close, not a new same-byte baseline after cleanup.
Registration files are rechecked at existing batch deadline checkpoints before
later preflights/runners. Concurrent GET history changes also refuse the current
handoff; after failure, the existing explicitly authorized GET-only recovery can
inspect retained data without resuming the batch or POST.

A fully parsed pending or opaque reply is still only a recorded observation.
Neither a successful return nor a `POST_REPLAYED` event authenticates a calendar,
Bitcoin chain/header, inclusion, append-only chronology or pre-dispatch seal.
Every serialized authority flag stays false; the controller does not qualify a
model, adopt P2/C2, complete J2 or authorize release. A native data receipt may
already exist when a later outer readback check refuses; its existence is not
evidence that this controller completed. External sealing and independent
reproduction remain necessary. No public service or paid run was exercised by
the synthetic local protocol/filesystem tests.

The separate `execute_checkpoint_recorded_calibration_measurement` entry follows
this same lifecycle with an explicit initial log/proof/pin, actual source-generated
phase extensions and complete original checkpoint/outcome custody. An explicit
fresh-log `None` pair or a caller-pinned initial tip is not authenticated accepted
history. See the [checkpoint profile](calibration_checkpoint_publication.md) for
the distinct result, unchanged bounds and retained security gates. Neither profile
supplies chain authentication, external chronology or independent reproduction.

The additional `checkpoint_calibration_completion_scope` retains exact original
live-native inputs before revocation and yields a task/process/deadline-bound
completion handle only after clean original terminal checks. Its observer and
successful scope exit recheck phase, result, receipt, journal and final-ledger
custody through consumer awaits and cleanup. Observed faults and every exit
invalidate the non-serializable handle; disk readers cannot recreate it. This is
original completion ownership, not a revived native proof or external seal. The
old execute APIs and all authority flags keep their existing meaning. See the
[scoped completion contract](calibration_checkpoint_publication.md#scoped-native-to-terminal-completion).

## Supplied proof diagnostics

The seven operator-supplied `.ots` files remain ignored local diagnostic inputs,
not vendored test fixtures. The original decoder was run only on their bytes;
no upstream parser, client, calendar, URI or node was executed or contacted.

| Supplied proof | Observed boundary |
| --- | --- |
| `gdp2q25-2nd.pdf.ots` | Data-only replay: 41 entries / depth 41; one claimed Bitcoin height 912095. PDF absent, so only its embedded digest was used. |
| `incomplete.txt.ots` | Supplied source hash matches; 7 entries / depth 7; pending-only commitment of 44 bytes. |
| `bad-stamp.txt.ots` | Supplied source hash matches; unsupported RIPEMD160 operation `0x03`. This is not detection of an invalid chain anchor. |
| `hello-world.txt.ots` | Supplied source hash matches; unsupported RIPEMD160 operation `0x03`. |
| `empty.ots` | Embedded digest equals SHA256(empty), but no empty source file is staged; unsupported RIPEMD160 operation `0x03`. |
| `different-blockchains.txt.ots` | Supplied source hash matches; unsupported Keccak operation `0x67`. |
| `bitcoin.pdf.ots` | Unsupported SHA1 detached-file tag `0x02`; PDF absent. |

This is two structural replays and five explicit unsupported-algorithm refusals,
not seven conformance passes or authenticated publications. No decoded-output
oracle is supplied: the GDP `.ots.txt` file is a provenance note. The reference
uses `hashlib` for RIPEMD160 and `Cryptodome` for Keccak, contrary to the operator
dependency note. Neither those diagnostic results nor the client source selects
a protocol/trust policy, changes a security gate or authorizes external execution.

## Evidence boundary and remaining integration

Normal-suite fixtures are independently authored, synthetic and local, with no
genuine chain proof, calendar or node. Positive results establish deterministic
wire parsing, request data, local file assembly/replay and disposable local HTTP
framing/cleanup only. The separate
supplied-proof observations above do not establish complete upstream compatibility
or differential reference-execution claims. An altered valid operation changes
the calculated commitment without necessarily making the proof malformed. A changed claimed height can likewise
remain well formed. Neither change can be authenticated from these bytes alone.

The external seal gate stays `MISSING`. Still required are an explicitly selected
protocol/trust profile, an independently authenticated block-header/chain source
and its confirmation/reorganization policy, an exact publication convention,
full-population binding, and a real pre-dispatch anchoring/independent-replay
workflow. Timestamp replay alone cannot prove wall-clock chronology, an append-only
history or a campaign's completeness. Native policy adoption and independent J2
remain separate mandatory gates. No service, node, public RPC, publication,
credential, provider call, paid run, signature, deployment or trust-root adoption
is selected by this implementation.
