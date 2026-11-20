from unittest.mock import Mock

import pytest

from core import fs_guard


@pytest.fixture
def guarded_fs(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original_open = Mock()
    audit = Mock()
    monkeypatch.setattr(fs_guard, "SAFE_WORKSPACE", str(workspace))
    monkeypatch.setattr(fs_guard, "LOG_FILE", str(workspace / "audit.jsonl"))
    monkeypatch.setattr(fs_guard, "_original_open", original_open)
    monkeypatch.setattr(fs_guard, "log_event", audit)
    return workspace, original_open, audit


def test_allows_workspace_file_and_forwards_open_arguments(guarded_fs):
    workspace, original_open, audit = guarded_fs
    target = workspace / "report.txt"

    result = fs_guard._guarded_open(target, "w", buffering=1, encoding="utf-8")

    assert result is original_open.return_value
    original_open.assert_called_once_with(target, "w", 1, "utf-8", None, None, True, None)
    audit.assert_called_once_with(
        "fs_access", "ALLOWED", str(target), "Accesso consentito in safe zone", mode="w"
    )


@pytest.mark.parametrize("extension", [".env", ".key", ".pem", ".pyc"])
def test_blocks_restricted_extension(guarded_fs, extension):
    workspace, original_open, audit = guarded_fs
    target = workspace / f"config{extension}"

    with pytest.raises(fs_guard.FileSecurityException, match="files are restricted"):
        fs_guard._guarded_open(target, "w")

    original_open.assert_not_called()
    audit.assert_called_once_with(
        "fs_access", "BLOCKED", str(target), f"Violazione estensione ({extension})", mode="w"
    )


def test_blocks_file_outside_workspace(guarded_fs):
    workspace, original_open, audit = guarded_fs
    target = workspace.parent / "workspace-other" / "report.txt"

    with pytest.raises(fs_guard.FileSecurityException, match="outside workspace"):
        fs_guard._guarded_open(workspace / ".." / "workspace-other" / "report.txt")

    original_open.assert_not_called()
    audit.assert_called_once_with(
        "fs_access", "BLOCKED", str(target), "Tentativo di Directory Traversal", mode="r"
    )


def test_blocks_when_commonpath_cannot_compare_paths(guarded_fs, monkeypatch):
    workspace, original_open, audit = guarded_fs
    target = workspace / "report.txt"
    path_api = Mock(wraps=fs_guard.os.path)
    path_api.commonpath.side_effect = ValueError("paths on different drives")
    monkeypatch.setattr(fs_guard, "os", Mock(path=path_api))

    with pytest.raises(fs_guard.FileSecurityException, match="outside workspace"):
        fs_guard._guarded_open(target)

    path_api.commonpath.assert_called_once_with([str(workspace), str(target)])
    original_open.assert_not_called()
    audit.assert_called_once_with(
        "fs_access", "BLOCKED", str(target), "Tentativo di Directory Traversal", mode="r"
    )


@pytest.mark.temporary_security
@pytest.mark.xfail(
    strict=False,
    raises=AssertionError,
    reason="Known limitation: direct access to the audit path bypasses guard telemetry",
)
def test_direct_audit_access_is_logged_or_blocked(guarded_fs):
    _, original_open, audit = guarded_fs
    try:
        fs_guard._guarded_open(fs_guard.LOG_FILE)
    except fs_guard.FileSecurityException:
        original_open.assert_not_called()
        return

    assert audit.called, "The guard delegated direct audit access without logging it"
