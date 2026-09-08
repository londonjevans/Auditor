from __future__ import annotations

import tarfile
import time
from dataclasses import FrozenInstanceError, replace

import pytest

import mmaudit.orchestration.managed_image_files as files
import mmaudit.orchestration.managed_image_layers as layers
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from tests.oci_image_file_support import PATHS, Entry, default_entries, file_case

HARDHAT = ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT
REPORTER = ManagedToolchainRole.HARDHAT_REPORTER


def verify(case, **kwargs):
    return files.verify_managed_image_files(case.bundle, blob_root=case.root, **kwargs)


def repin(case, role, **changes):
    case.bundle = seal_managed_toolchain_bundle(
        members=tuple(
            member.model_copy(update=changes) if member.role == role else member
            for member in case.bundle.members
        ),
        target_platform=case.bundle.target_platform,
    )


@pytest.mark.parametrize("indexed", [False, True])
@pytest.mark.parametrize("codec", ["tar", "gzip"])
def test_all_four_exact_files_join_the_current_bundle_without_authority(tmp_path, indexed, codec):
    case = file_case(tmp_path / "blobs", indexed=indexed, codecs=(codec,))
    result = verify(case)
    assert tuple(item.role for item in result.files) == tuple(PATHS)
    assert [item.image_path for item in result.files] == ["/" + path for path in PATHS.values()]
    assert all(item.image_path == item.resolved_image_path for item in result.files)
    assert all(item.content_layer_index == 0 for item in result.files)
    assert all(not item.symlink_paths for item in result.files)
    assert result.layers.metadata.source_bundle_sha256 == case.bundle.bundle_sha256
    assert result.total_headers == 4
    for name in (
        "independently_trusted",
        "image_side_attestation_verified",
        "transitive_dependency_closure_verified",
        "execution_evidence_verified",
        "runtime_authority",
        "managed_run_ready",
    ):
        assert getattr(result, name) is False
    with pytest.raises(FrozenInstanceError):
        result.runtime_authority = True


@pytest.mark.parametrize("marker_last", [False, True])
@pytest.mark.parametrize("opaque", [False, True])
def test_whiteouts_only_remove_lower_entries_regardless_of_marker_order(
    tmp_path, marker_last, opaque
):
    entries = default_entries()
    base = tuple(replace(entry, content=b"wrong lower contents") for entry in entries[:3])
    base += entries[3:]
    marker = Entry("usr/local/bin/" + (".wh..wh..opq" if opaque else ".wh.hardhat"))
    additions = entries[:3]
    top = (*additions, marker) if marker_last else (marker, *additions)
    case = file_case(tmp_path / "blobs", changesets=(base, top))
    result = verify(case)
    assert [item.content_layer_index for item in result.files] == [1, 1, 1, 0]


@pytest.mark.parametrize(
    "marker",
    [
        "usr/local/bin/.wh.hardhat",
        "usr/local/.wh.bin",
        "usr/local/bin/.wh..wh..opq",
        "usr/.wh..wh..opq",
        ".wh..wh..opq",
    ],
)
def test_deleted_selected_files_and_subtrees_are_not_members(tmp_path, marker):
    case = file_case(tmp_path / "blobs", changesets=(default_entries(), (Entry(marker),)))
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


def test_delete_then_recreate_in_later_layer_retains_new_content_origin(tmp_path):
    entries = default_entries()
    case = file_case(
        tmp_path / "blobs",
        changesets=(entries, (Entry("usr/local/bin/.wh.hardhat"),), (entries[0],)),
    )
    assert verify(case).files[0].content_layer_index == 2


def test_directory_attribute_replacement_keeps_lower_children(tmp_path):
    case = file_case(
        tmp_path / "blobs",
        changesets=(
            default_entries(),
            (
                Entry("./", kind=tarfile.DIRTYPE),
                Entry("usr/local/bin/", kind=tarfile.DIRTYPE, mode=0o700),
            ),
        ),
    )
    assert all(item.content_layer_index == 0 for item in verify(case).files)


def test_file_to_directory_replacement_then_children_is_supported(tmp_path):
    entries = default_entries()
    case = file_case(
        tmp_path / "blobs",
        changesets=(
            (Entry("usr/local/bin", b"obsolete"), entries[3]),
            (Entry("usr/local/bin", kind=tarfile.DIRTYPE), *entries[:3]),
        ),
    )
    assert verify(case).files[0].content_layer_index == 1


@pytest.mark.parametrize(
    "replacement",
    [
        Entry("usr/local/bin", b"not a directory"),
        Entry("usr/local/bin/hardhat", b"different content"),
        Entry("usr/local/bin/hardhat", kind=tarfile.DIRTYPE),
    ],
)
def test_replaced_bytes_or_node_kinds_cannot_reuse_lower_file_pins(tmp_path, replacement):
    case = file_case(tmp_path / "blobs", changesets=(default_entries(), (replacement,)))
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


@pytest.mark.parametrize("target", ["../lib/hardhat/cli.js", "/usr/local/lib/hardhat/cli.js"])
def test_relative_and_image_root_absolute_symlinks_resolve_in_memory(tmp_path, target):
    entries = default_entries()
    actual = replace(entries[0], path="usr/local/lib/hardhat/cli.js")
    alias = Entry(entries[0].path, kind=tarfile.SYMTYPE, target=target)
    case = file_case(tmp_path / "blobs", changesets=((actual, alias, *entries[1:]),))
    observed = verify(case).files[0]
    assert observed.resolved_image_path == "/usr/local/lib/hardhat/cli.js"
    assert observed.symlink_paths == ("/usr/local/bin/hardhat",)


def test_symbolic_directory_prefix_resolves_selected_files_without_host_lookup(tmp_path):
    entries = default_entries()
    actual = tuple(
        replace(entry, path="payload/bin/" + entry.path.rsplit("/", 1)[-1]) for entry in entries[:3]
    )
    case = file_case(
        tmp_path / "blobs",
        changesets=(
            (
                *actual,
                Entry("usr/local/bin", kind=tarfile.SYMTYPE, target="/payload/bin"),
                entries[3],
            ),
        ),
    )
    assert all(
        item.resolved_image_path.startswith("/payload/bin/") for item in verify(case).files[:3]
    )


def test_hardlink_identity_survives_later_replacement_of_the_original_path(tmp_path):
    entries = default_entries()
    original = replace(entries[0], path="payload/original")
    alias = Entry(entries[0].path, kind=tarfile.LNKTYPE, target=original.path)
    case = file_case(
        tmp_path / "blobs",
        changesets=((original, alias, *entries[1:]), (replace(original, content=b"replacement"),)),
    )
    observed = verify(case).files[0]
    assert observed.content_layer_index == 0
    assert observed.resolved_image_path == "/" + entries[0].path


@pytest.mark.parametrize("variant", ["forward", "lower", "symlink", "directory", "attributes"])
def test_unmodeled_hardlink_semantics_refuse(tmp_path, variant):
    entries = default_entries()
    original = replace(entries[0], path="payload/original")
    alias = Entry(entries[0].path, kind=tarfile.LNKTYPE, target=original.path)
    first, second = (original, alias, *entries[1:]), ()
    if variant == "forward":
        first = (alias, original, *entries[1:])
    elif variant == "lower":
        first, second = (original, *entries[1:]), (alias,)
    elif variant == "symlink":
        first = (
            replace(original, content=b"", kind=tarfile.SYMTYPE, target="elsewhere"),
            alias,
            *entries[1:],
        )
    elif variant == "directory":
        first = (replace(original, content=b"", kind=tarfile.DIRTYPE), alias, *entries[1:])
    else:
        first = (original, replace(alias, uid=1), *entries[1:])
    case = file_case(tmp_path / "blobs", changesets=(first, second))
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


@pytest.mark.parametrize(
    "target",
    [
        "../../../../outside",
        "/../outside",
        "hardhat",
        "missing",
        "node/../hardhat",
        "node/",
        "node//",
        "/",
        "../..",
        "././node",
    ],
)
def test_missing_cyclic_escaping_or_wrong_symlink_targets_refuse(tmp_path, target):
    entries = default_entries()
    alias = Entry(entries[0].path, kind=tarfile.SYMTYPE, target=target)
    case = file_case(tmp_path / "blobs", changesets=((alias, *entries[1:]),))
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


@pytest.mark.parametrize("reverse", [False, True])
def test_same_layer_non_directory_ancestor_refuses_in_both_orders(tmp_path, reverse):
    additions = [Entry("unselected", b"not directory"), Entry("unselected/child", b"inert")]
    if reverse:
        additions.reverse()
    case = file_case(tmp_path / "blobs", changesets=((*default_entries(), *additions),))
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


@pytest.mark.parametrize("entry", [Entry("alias/child", b"inert"), Entry("alias/.wh.old")])
def test_writes_and_whiteouts_through_lower_symbolic_parents_refuse(tmp_path, entry):
    case = file_case(
        tmp_path / "blobs",
        changesets=(
            (*default_entries(), Entry("alias", kind=tarfile.SYMTYPE, target="usr")),
            (entry,),
        ),
    )
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


@pytest.mark.parametrize("mode", [0o444, 0o644, 0o777, 0o4755, 0o2755, 0o1755])
def test_selected_executable_permission_metadata_refuses_unsupported_bits(tmp_path, mode):
    entries = default_entries()
    case = file_case(
        tmp_path / "blobs", changesets=((replace(entries[0], mode=mode), *entries[1:]),)
    )
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


@pytest.mark.parametrize(
    "override",
    [
        {"max_total_headers": 3},
        {"max_total_metadata_bytes": 2},
        {"max_live_nodes": 3},
        {"max_live_path_bytes": 3},
    ],
)
def test_image_metadata_and_live_tree_allowances_refuse(tmp_path, override):
    case = file_case(tmp_path / "blobs")
    with pytest.raises(files.ManagedImageFileError):
        verify(case, limits=files.ManagedImageFileLimits(**override))


def test_repeated_layers_count_against_the_shared_tar_header_allowance(tmp_path):
    case = file_case(tmp_path / "blobs", changesets=(default_entries(), default_entries()))
    assert verify(case).total_headers == 8
    with pytest.raises(files.ManagedImageFileError):
        verify(case, limits=files.ManagedImageFileLimits(max_total_headers=7))


@pytest.mark.parametrize("changes", [{"sha256": "1" * 64}, {"version": "not-selected"}])
def test_reporter_contract_mismatch_refuses_before_any_blob_read(tmp_path, monkeypatch, changes):
    case = file_case(tmp_path / "blobs")
    repin(case, REPORTER, **changes)

    def refused(*args, **kwargs):
        pytest.fail("invariant: invalid reporter pin must refuse before layer I/O")

    monkeypatch.setattr(files, "_inspect_managed_image_layers", refused)
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


def test_tampered_limit_models_are_revalidated_before_consumption(tmp_path):
    case = file_case(tmp_path / "blobs")
    limits = files.ManagedImageFileLimits().model_copy(update={"max_live_nodes": -1})
    with pytest.raises(files.ManagedImageFileError):
        verify(case, limits=limits)
    object.__setattr__(case.bundle, "bundle_sha256", "0" * 64)
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


def test_layer_visitor_must_consume_complete_expanded_eof(tmp_path):
    case = file_case(tmp_path / "blobs")
    with pytest.raises(layers.ManagedImageLayerError, match="complete EOF"):
        layers._inspect_managed_image_layers(
            case.bundle, blob_root=case.root, consume_layer=lambda index, deadline, chunks: None
        )


def test_deadline_covers_final_file_resolution_not_just_byte_consumption(tmp_path, monkeypatch):
    case = file_case(tmp_path / "blobs")
    now = [1.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    actual = files._Filesystem.resolve

    def expired(self, path):
        result = actual(self, path)
        now[0] = self.deadline
        return result

    monkeypatch.setattr(files._Filesystem, "resolve", expired)
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


def test_dotdot_is_applied_after_symbolic_components_not_lexically_collapsed(tmp_path):
    entries = default_entries()
    case = file_case(
        tmp_path / "blobs",
        changesets=(
            (
                replace(entries[0], path="elsewhere/value"),
                Entry("elsewhere/deep", kind=tarfile.DIRTYPE),
                Entry("jump", kind=tarfile.SYMTYPE, target="/elsewhere/deep"),
                Entry(entries[0].path, kind=tarfile.SYMTYPE, target="/jump/../value"),
                Entry("value", b"incorrect lexical target"),
                *entries[1:],
            ),
        ),
    )
    result = verify(case).files[0]
    assert result.resolved_image_path == "/elsewhere/value"
    assert result.symlink_paths == ("/usr/local/bin/hardhat", "/jump")
    with pytest.raises(files.ManagedImageFileError):
        verify(case, limits=files.ManagedImageFileLimits(max_symlink_hops=1))


def test_long_pax_link_and_file_paths_join_the_same_content_pin(tmp_path):
    entries = default_entries()
    actual = replace(entries[0], path="payload/" + "long/" * 24 + "value")
    case = file_case(
        tmp_path / "blobs",
        formats=(tarfile.PAX_FORMAT,),
        changesets=(
            (
                actual,
                Entry(entries[0].path, kind=tarfile.SYMTYPE, target="/" + actual.path),
                *entries[1:],
            ),
        ),
    )
    assert verify(case).files[0].resolved_image_path == "/" + actual.path


def test_hardlinks_can_refer_to_an_earlier_same_layer_hardlink(tmp_path):
    entries = default_entries()
    case = file_case(
        tmp_path / "blobs",
        changesets=(
            (
                replace(entries[0], path="payload/original"),
                Entry("payload/alias", kind=tarfile.LNKTYPE, target="payload/original"),
                Entry(entries[0].path, kind=tarfile.LNKTYPE, target="payload/alias"),
                *entries[1:],
            ),
        ),
    )
    assert verify(case).files[0].content_layer_index == 0


@pytest.mark.parametrize("mode", [0o000, 0o111, 0o666])
def test_reporter_must_have_readable_nonshared_writable_metadata(tmp_path, mode):
    entries = default_entries()
    case = file_case(
        tmp_path / "blobs", changesets=((*entries[:3], replace(entries[3], mode=mode)),)
    )
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


@pytest.mark.parametrize("reverse", [False, True])
def test_unsupported_whiteout_parent_refusal_does_not_depend_on_whiteout_order(tmp_path, reverse):
    markers = [Entry(".wh.alias"), Entry("alias/.wh.child")]
    if reverse:
        markers.reverse()
    case = file_case(
        tmp_path / "blobs",
        changesets=(
            (*default_entries(), Entry("alias", kind=tarfile.SYMTYPE, target="usr")),
            tuple(markers),
        ),
    )
    with pytest.raises(files.ManagedImageFileError):
        verify(case)


def test_unresolved_required_pin_refuses_before_io(tmp_path, monkeypatch):
    from mmaudit.orchestration.managed_toolchain import ManagedToolchainDisposition

    case = file_case(tmp_path / "blobs")
    repin(
        case,
        HARDHAT,
        disposition=ManagedToolchainDisposition.UNRESOLVED,
        locator=None,
        version=None,
        sha256=None,
        parent_image_role=None,
        parent_image_sha256=None,
        parent_platform_manifest_sha256=None,
        limitation="Synthetic unavailable tool",
    )

    def refused(*args, **kwargs):
        pytest.fail("invariant: unresolved selected file must refuse before I/O")

    monkeypatch.setattr(files, "_inspect_managed_image_layers", refused)
    with pytest.raises(files.ManagedImageFileError):
        verify(case)
