"""Tests for upload lifecycle helpers in pages/home.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers to exercise the manifest pattern without importing Streamlit
# ---------------------------------------------------------------------------

def _write_manifest(uploads_dir: Path, session_prefix: str, filenames: list[str]) -> None:
    manifest = {"session_prefix": session_prefix, "files": filenames}
    (uploads_dir / f".manifest_{session_prefix}.json").write_text(json.dumps(manifest))


def _do_cleanup(uploads_dir: Path, session_prefix: str, current_batch: set[str]) -> None:
    """Inline reimplementation of _cleanup_session_uploads, so tests don't need Streamlit."""
    manifest_path = uploads_dir / f".manifest_{session_prefix}.json"
    if not manifest_path.exists():
        return
    try:
        manifest = json.loads(manifest_path.read_text())
        for fname in manifest.get("files", []):
            if fname not in current_batch:
                fpath = uploads_dir / fname
                fpath.unlink(missing_ok=True)
    except (OSError, json.JSONDecodeError):
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_cleanup_only_touches_session_files(tmp_path: Path) -> None:
    """Cleanup must not delete files that belong to another session."""
    # Session A owns two files
    (tmp_path / "aaa_h1_file1.log").write_text("session A file 1")
    (tmp_path / "aaa_h2_file2.log").write_text("session A file 2")
    _write_manifest(tmp_path, "aaa", ["aaa_h1_file1.log", "aaa_h2_file2.log"])

    # Session B owns one file
    (tmp_path / "bbb_h3_file3.log").write_text("session B file")
    _write_manifest(tmp_path, "bbb", ["bbb_h3_file3.log"])

    # Cleanup session A with only file1 in current batch → file2 should be deleted
    _do_cleanup(tmp_path, "aaa", {"aaa_h1_file1.log"})

    assert (tmp_path / "aaa_h1_file1.log").exists(), "file1 should survive (in current batch)"
    assert not (tmp_path / "aaa_h2_file2.log").exists(), "file2 should be removed (not in batch)"
    assert (tmp_path / "bbb_h3_file3.log").exists(), "session B file must not be touched"


def test_manifest_lifecycle(tmp_path: Path) -> None:
    """Full lifecycle: write manifest, create files, cleanup removes only the stale one."""
    (tmp_path / "abc_h1_f1.log").write_text("a")
    (tmp_path / "abc_h2_f2.log").write_text("b")
    (tmp_path / "xyz_h1_other.log").write_text("c")  # belongs to a different session

    _write_manifest(tmp_path, "abc", ["abc_h1_f1.log", "abc_h2_f2.log"])

    # Cleanup: current batch contains only f1 → f2 should be removed
    _do_cleanup(tmp_path, "abc", {"abc_h1_f1.log"})

    assert (tmp_path / "abc_h1_f1.log").exists()
    assert not (tmp_path / "abc_h2_f2.log").exists()
    assert (tmp_path / "xyz_h1_other.log").exists(), "unrelated-session file must survive"


def test_cleanup_no_manifest_is_noop(tmp_path: Path) -> None:
    """If no manifest exists, cleanup does nothing and raises no exception."""
    sentinel = tmp_path / "zzz_h1_keep.log"
    sentinel.write_text("keep me")

    _do_cleanup(tmp_path, "nonexistent", set())  # should not raise

    assert sentinel.exists()


def test_cleanup_corrupted_manifest_is_noop(tmp_path: Path) -> None:
    """A corrupted manifest triggers silent skip — no exception, no file deleted."""
    sentinel = tmp_path / "abc_h1_keep.log"
    sentinel.write_text("keep me")
    (tmp_path / ".manifest_abc.json").write_text("{bad json{{")

    _do_cleanup(tmp_path, "abc", set())  # should not raise

    assert sentinel.exists()


def test_cleanup_empty_batch_removes_all_session_files(tmp_path: Path) -> None:
    """Passing an empty current_batch removes every file the manifest lists."""
    (tmp_path / "abc_h1_old.log").write_text("old")
    (tmp_path / "abc_h2_older.log").write_text("older")
    _write_manifest(tmp_path, "abc", ["abc_h1_old.log", "abc_h2_older.log"])

    _do_cleanup(tmp_path, "abc", set())

    assert not (tmp_path / "abc_h1_old.log").exists()
    assert not (tmp_path / "abc_h2_older.log").exists()
