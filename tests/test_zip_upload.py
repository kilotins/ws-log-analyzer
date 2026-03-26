"""Unit tests for zip upload support in app.py."""
import io
import sys
from pathlib import Path
from unittest import mock
import zipfile

import pytest


class _AttrDict(dict):
    """Dict with attribute access for Streamlit session_state mocks."""

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError:
            raise AttributeError(key)


_streamlit_mock = mock.MagicMock()
_streamlit_mock.session_state = _AttrDict()
_streamlit_mock.fragment = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.cache_data = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.cache_resource = lambda *a, **kw: (lambda fn: fn) if not a else a[0]
_streamlit_mock.columns = lambda n=1, **kw: [mock.MagicMock() for _ in range(n)] if isinstance(n, int) else [mock.MagicMock() for _ in n]
_streamlit_mock.tabs = lambda names: [mock.MagicMock() for _ in names]
_streamlit_mock.selectbox = lambda label, options, **kw: (list(options)[0] if options else "")
_streamlit_mock.button = lambda *a, **kw: False
_streamlit_mock.file_uploader = lambda *a, **kw: None

sys.modules["streamlit"] = _streamlit_mock
sys.modules["streamlit.components"] = mock.MagicMock()
sys.modules["streamlit.components.v1"] = mock.MagicMock()

from app import (  # noqa: E402
    _InMemoryUpload,
    _cleanup_temp_dir,
    _expand_uploaded_archives,
    _extract_archive_upload,
    _is_zip_junk_member,
    _safe_zip_member_path,
)
import app  # noqa: E402


class _FakeUpload:
    """Minimal upload object used by the tests."""

    def __init__(self, name: str, content: bytes):
        self.name = name
        self._content = content
        self.size = len(content)

    def getvalue(self) -> bytes:
        return self._content


def _make_zip_upload(name: str, entries: dict[str, bytes]) -> _FakeUpload:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    return _FakeUpload(name, data.getvalue())


class TestZipUploadHelpers:
    def test_extract_single_log_file(self):
        upload = _make_zip_upload("archive.zip", {"app.log": b"INFO started\n"})

        extracted, preview = _extract_archive_upload(upload)

        assert [f.name for f in extracted] == ["app.log"]
        assert extracted[0].getvalue() == b"INFO started\n"
        assert preview == ["app.log"]

    def test_extract_multiple_log_files(self):
        upload = _make_zip_upload(
            "archive.zip",
            {"a.log": b"a\n", "b.log": b"b\n", "c.txt": b"c\n"},
        )

        extracted, preview = _extract_archive_upload(upload)

        assert [f.name for f in extracted] == ["a.log", "b.log", "c.txt"]
        assert preview == ["a.log", "b.log", "c.txt"]

    def test_junk_ds_store_is_filtered(self):
        upload = _make_zip_upload(
            "archive.zip",
            {".DS_Store": b"x", "app.log": b"log\n"},
        )

        extracted, preview = _extract_archive_upload(upload)

        assert [f.name for f in extracted] == ["app.log"]
        assert preview == ["app.log"]

    def test_junk_macosx_folder_is_filtered(self):
        upload = _make_zip_upload(
            "archive.zip",
            {"__MACOSX/app.log": b"junk", "real/service.log": b"log\n"},
        )

        extracted, preview = _extract_archive_upload(upload)

        assert [f.name for f in extracted] == ["real/service.log"]
        assert preview == ["real/service.log"]

    def test_junk_desktop_ini_is_filtered(self):
        upload = _make_zip_upload(
            "archive.zip",
            {"desktop.ini": b"x", "worker.log": b"log\n"},
        )

        extracted, _preview = _extract_archive_upload(upload)

        assert [f.name for f in extracted] == ["worker.log"]

    def test_nested_directories_are_preserved(self):
        upload = _make_zip_upload(
            "archive.zip",
            {"api/server.log": b"one\n", "worker/sub/task.log": b"two\n"},
        )

        extracted, preview = _extract_archive_upload(upload)

        assert [f.name for f in extracted] == ["api/server.log", "worker/sub/task.log"]
        assert preview == ["api/server.log", "worker/sub/task.log"]

    def test_empty_zip_returns_no_files(self):
        upload = _make_zip_upload("empty.zip", {})

        extracted, preview = _extract_archive_upload(upload)

        assert extracted == []
        assert preview == []

    def test_zip_with_no_log_files_returns_no_files(self):
        upload = _make_zip_upload("data.zip", {"notes.csv": b"id,value\n1,2\n"})

        extracted, preview = _extract_archive_upload(upload)

        assert extracted == []
        assert preview == []

    def test_gz_file_inside_zip_is_preserved(self):
        upload = _make_zip_upload("logs.zip", {"nested/app.log.gz": b"\x1f\x8braw"})

        extracted, preview = _extract_archive_upload(upload)

        assert [f.name for f in extracted] == ["nested/app.log.gz"]
        assert extracted[0].getvalue() == b"\x1f\x8braw"
        assert preview == ["nested/app.log.gz"]

    def test_mixed_regular_and_zip_uploads_expand_in_order(self):
        regular = _InMemoryUpload(b"plain\n", "plain.log")
        archive = _make_zip_upload("bundle.zip", {"inside.log": b"zip\n"})

        expanded, previews = _expand_uploaded_archives([regular, archive])

        assert [f.name for f in expanded] == ["plain.log", "inside.log"]
        assert previews == [("bundle.zip", ["inside.log"])]

    def test_no_log_files_zip_shows_warning(self):
        upload = _make_zip_upload("bundle.zip", {"image.png": b"png"})
        app.st.warning.reset_mock()

        expanded, previews = _expand_uploaded_archives([upload])

        assert expanded == []
        assert previews == []
        app.st.warning.assert_called_once_with("No supported log files found in bundle.zip.")

    def test_valid_zip_shows_info_message(self):
        upload = _make_zip_upload("bundle.zip", {"inside.log": b"zip\n", "more.log": b"x\n"})
        app.st.info.reset_mock()

        expanded, previews = _expand_uploaded_archives([upload])

        assert [f.name for f in expanded] == ["inside.log", "more.log"]
        assert previews == [("bundle.zip", ["inside.log", "more.log"])]
        app.st.info.assert_called_once_with("Extracted 2 log files from bundle.zip")

    def test_invalid_zip_shows_warning_and_skips_archive(self):
        upload = _FakeUpload("broken.zip", b"not-a-zip")
        app.st.warning.reset_mock()

        expanded, previews = _expand_uploaded_archives([upload])

        assert expanded == []
        assert previews == []
        app.st.warning.assert_called_once_with("No files extracted from broken.zip: invalid zip archive.")

    def test_cleanup_temp_dir_removes_nested_content(self, tmp_path):
        root = tmp_path / "extract"
        nested = root / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "app.log").write_text("x", encoding="utf-8")

        _cleanup_temp_dir(root)

        assert not root.exists()

    @pytest.mark.parametrize(
        ("member_name", "expected"),
        [
            (".DS_Store", True),
            ("__MACOSX/file.log", True),
            ("nested/thumbs.db", True),
            ("nested/desktop.ini", True),
            ("nested/__pycache__/x.pyc", True),
            ("nested/app.log", False),
        ],
    )
    def test_is_zip_junk_member(self, member_name, expected):
        assert _is_zip_junk_member(member_name) is expected

    def test_safe_zip_member_path_allows_nested_paths(self, tmp_path):
        target = _safe_zip_member_path(tmp_path, "api/server.log")

        assert target == (tmp_path / "api" / "server.log").resolve()

    @pytest.mark.parametrize("member_name", ["../escape.log", "/absolute.log", ".."])
    def test_safe_zip_member_path_rejects_traversal(self, tmp_path, member_name):
        assert _safe_zip_member_path(tmp_path, member_name) is None
