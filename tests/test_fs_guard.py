import errno
import os
import subprocess
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


@pytest.mark.parametrize("relative_path", ["report.txt", ".gitignore", ".env.local/report.txt"])
def test_allows_workspace_file_and_forwards_open_arguments(guarded_fs, relative_path):
    workspace, original_open, audit = guarded_fs
    target = workspace / relative_path

    result = fs_guard._guarded_open(target, "w", buffering=1, encoding="utf-8")

    assert result is original_open.return_value
    original_open.assert_called_once_with(target, "w", 1, "utf-8", None, None, True, None)
    audit.assert_called_once_with(
        "fs_access", "ALLOWED", str(target), "Accesso consentito in safe zone", mode="w"
    )


@pytest.mark.parametrize(
    ("filename", "extension"),
    [
        (".env", ".env"),
        (".env.local", ".env"),
        (".env.production", ".env"),
        (".ENV", ".env"),
        (".Env.local", ".env"),
        ("config.ENV", ".env"),
        ("config.env", ".env"),
        ("config.key", ".key"),
        ("config.pem", ".pem"),
        ("config.pyc", ".pyc"),
    ],
)
@pytest.mark.parametrize("mode", ["r", "w"])
def test_blocks_restricted_filename(guarded_fs, filename, extension, mode):
    workspace, original_open, audit = guarded_fs
    target = workspace / filename

    with pytest.raises(fs_guard.FileSecurityException, match="files are restricted"):
        fs_guard._guarded_open(target, mode)

    original_open.assert_not_called()
    audit.assert_called_once_with(
        "fs_access", "BLOCKED", str(target), f"Violazione estensione ({extension})", mode=mode
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


def assert_workspace_blocked(guarded_fs, target, mode):
    _, original_open, audit = guarded_fs
    with pytest.raises(fs_guard.FileSecurityException, match="outside workspace"):
        fs_guard._guarded_open(target, mode)

    original_open.assert_not_called()
    audit.assert_called_once_with(
        "fs_access", "BLOCKED", str(target), "Tentativo di Directory Traversal", mode=mode
    )


@pytest.mark.parametrize("resolution_error", [None, errno.EACCES, errno.ELOOP])
def test_blocks_canonical_path_escape_or_resolution_error(
    guarded_fs, monkeypatch, resolution_error
):
    workspace, _, _ = guarded_fs
    target = workspace / "report.txt"
    outside = workspace.parent / "outside" / "report.txt"

    def resolve(path, **kwargs):
        requested = os.fspath(path)
        if requested == str(workspace):
            return str(workspace)
        assert requested == str(target)
        if resolution_error is not None:
            raise OSError(resolution_error, "simulated resolution error")
        return str(outside)

    path_api = Mock(wraps=os.path)
    path_api.realpath.side_effect = resolve
    monkeypatch.setattr(fs_guard, "os", Mock(wraps=os, path=path_api))

    assert_workspace_blocked(guarded_fs, target, "r")


@pytest.mark.parametrize(
    ("kind", "mode"),
    [
        ("file-outside", "r"),
        ("directory-outside", "r"),
        ("directory-outside", "w"),
        ("file-inside", "r"),
    ],
)
def test_symlink_workspace_containment(guarded_fs, kind, mode):
    workspace, original_open, audit = guarded_fs
    outside = workspace.parent / "outside"
    outside.mkdir()
    directory_link = kind == "directory-outside"
    base = workspace if kind == "file-inside" else outside
    destination = base if directory_link else base / "target.txt"
    if not directory_link:
        destination.touch()
    elif mode == "r":
        (destination / "report.txt").touch()

    link = workspace / "linked"
    try:
        link.symlink_to(destination, target_is_directory=directory_link)
    except NotImplementedError:
        pytest.skip("symlink creation is unavailable")
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314 or exc.errno in {
            errno.EACCES, errno.EPERM, errno.ENOSYS, errno.ENOTSUP
        }:
            pytest.skip(f"symlink creation is unavailable: {exc}")
        raise

    try:
        target = link / "report.txt" if directory_link else link
        if kind != "file-inside":
            assert_workspace_blocked(guarded_fs, target, mode)
        else:
            assert fs_guard._guarded_open(target, mode) is original_open.return_value
            original_open.assert_called_once_with(
                target, mode, -1, None, None, None, True, None
            )
            audit.assert_called_once_with(
                "fs_access", "ALLOWED", str(target), "Accesso consentito in safe zone", mode=mode
            )
    finally:
        if directory_link and os.name == "nt":
            link.rmdir()
        else:
            link.unlink()


@pytest.mark.skipif(os.name != "nt", reason="directory junctions require Windows")
def test_blocks_windows_junction_to_outside_workspace(guarded_fs):
    workspace, _, _ = guarded_fs
    outside = workspace.parent / "outside"
    outside.mkdir()
    (outside / "report.txt").touch()
    junction = workspace / "linked"
    cmd = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    env = dict(
        os.environ,
        AEGIS_TEST_JUNCTION_LINK=str(junction.absolute()),
        AEGIS_TEST_JUNCTION_TARGET=str(outside.absolute()),
    )
    try:
        result = subprocess.run(
            'cmd.exe /d /v:off /c mklink /J '
            '"%AEGIS_TEST_JUNCTION_LINK%" "%AEGIS_TEST_JUNCTION_TARGET%"',
            executable=cmd,
            cwd=workspace.parent,
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        pytest.skip("junction creation is unavailable: cmd.exe not found")
    assert result.returncode == 0, (
        f"junction creation failed ({result.returncode}): "
        f"{result.stdout} {result.stderr}"
    )

    try:
        assert junction.resolve() == outside.resolve()
        assert_workspace_blocked(guarded_fs, junction / "report.txt", "r")
    finally:
        junction.rmdir()


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
