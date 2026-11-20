import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]

CHILD_SETUP = """
import builtins
import contextlib
import io
import os
import runpy
import socket
import sys
import urllib.request
from pathlib import Path
from unittest.mock import Mock

repo = Path(sys.argv[1])
sandbox = Path.cwd().parent.resolve()
sys.path.insert(0, str(repo))
native_open = builtins.open
native_connection = socket.create_connection
network_attempts = []
outside_writes = []


def audit(event, args):
    if event.startswith("socket."):
        network_attempts.append(event)
        raise AssertionError(f"Unexpected socket operation: {event}")
    if event == "open":
        path, _, flags = args
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if flags & write_flags:
            if isinstance(path, int):
                outside_writes.append(path)
                raise AssertionError(f"Unexpected writable file descriptor: {path}")
            target = Path(os.fsdecode(path)).resolve()
            if target != sandbox and sandbox not in target.parents:
                outside_writes.append(target)
                raise AssertionError(f"Write outside the temporary directory: {target}")


sys.addaudithook(audit)
urllib.request.urlopen = Mock(side_effect=AssertionError("Unexpected URL request"))
"""


def run_child(tmp_path, scenario):
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            dedent(CHILD_SETUP) + "\n" + dedent(scenario) + "\n"
            "assert not network_attempts, network_attempts\n"
            "assert not outside_writes, outside_writes\n",
            str(REPO_ROOT),
        ],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, (
        f"Child returned {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


agent_opt_in = pytest.mark.skipif(
    os.environ.get("AEGIS_TEST_AGENT") != "1",
    reason="Loading test_agent requires explicit opt-in via AEGIS_TEST_AGENT=1",
)


def test_guard_imports_leave_global_hooks_unchanged(tmp_path):
    run_child(
        tmp_path,
        """
        from core import fs_guard, network_guard

        assert builtins.open is native_open
        assert socket.create_connection is native_connection
        """,
    )


@pytest.mark.parametrize(
    ("module", "owner", "attribute", "wrapper", "argument"),
    [
        ("fs_guard", "builtins", "open", "_guarded_open", "report.txt"),
        (
            "network_guard",
            "socket",
            "create_connection",
            "_guarded_connection",
            ("api.github.com", 443),
        ),
    ],
    ids=["filesystem", "network"],
)
def test_guard_activation_and_deactivation(
    tmp_path, module, owner, attribute, wrapper, argument
):
    run_child(
        tmp_path,
        f"""
        from core import {module} as guard

        guard.log_event = Mock()
        enable = guard.enable_{module}
        disable = guard.disable_{module}
        original = Mock()
        setattr({owner}, {attribute!r}, original)
        disable()
        assert getattr({owner}, {attribute!r}) is original

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            enable()
            assert getattr({owner}, {attribute!r}) is guard.{wrapper}
            first_output = output.getvalue()
            enable()
            assert getattr({owner}, {attribute!r}) is guard.{wrapper}
            assert output.getvalue() == first_output
        assert getattr({owner}, {attribute!r})({argument!r}) is original.return_value
        original.assert_called_once()

        disable()
        assert getattr({owner}, {attribute!r}) is original
        disable()
        assert getattr({owner}, {attribute!r}) is original

        replacement = Mock()
        setattr({owner}, {attribute!r}, replacement)
        enable()
        assert getattr({owner}, {attribute!r})({argument!r}) is replacement.return_value
        replacement.assert_called_once()
        disable()
        assert getattr({owner}, {attribute!r}) is replacement
        """,
    )


@pytest.mark.parametrize(
    ("module", "owner", "attribute"),
    [("fs_guard", "builtins", "open"), ("network_guard", "socket", "create_connection")],
    ids=["filesystem", "network"],
)
def test_disable_preserves_a_later_external_replacement(tmp_path, module, owner, attribute):
    run_child(
        tmp_path,
        f"""
        from core import {module} as guard

        guard.enable_{module}()
        replacement = Mock()
        setattr({owner}, {attribute!r}, replacement)
        guard.disable_{module}()
        assert getattr({owner}, {attribute!r}) is replacement
        guard.disable_{module}()
        assert getattr({owner}, {attribute!r}) is replacement
        """,
    )


@pytest.mark.parametrize(
    ("module", "owner", "attribute", "wrapper", "delegate"),
    [
        ("fs_guard", "builtins", "open", "_guarded_open", "_original_open"),
        (
            "network_guard",
            "socket",
            "create_connection",
            "_guarded_connection",
            "_original_create_connection",
        ),
    ],
    ids=["filesystem", "network"],
)
@pytest.mark.parametrize(
    "failure_point",
    ["before-installation", "during-print", "after-external-replacement"],
)
def test_enable_rolls_back_on_activation_failure(
    tmp_path, module, owner, attribute, wrapper, delegate, failure_point
):
    run_child(
        tmp_path,
        f"""
        from core import {module} as guard

        owner = {owner}
        attribute = {attribute!r}
        wrapper = guard.{wrapper}
        previous_delegate = guard.{delegate}
        prior_hook = Mock()
        external_hook = Mock()
        setattr(owner, attribute, prior_hook)
        failure = RuntimeError("simulated activation failure")
        failure_point = {failure_point!r}

        class RejectInstallation:
            def __getattr__(self, name):
                return getattr(owner, name)

            def __setattr__(self, name, value):
                assert name == attribute
                assert value is wrapper
                assert getattr(owner, attribute) is prior_hook
                raise failure

        def fail_during_print(*args, **kwargs):
            assert getattr(owner, attribute) is wrapper
            if failure_point == "after-external-replacement":
                setattr(owner, attribute, external_hook)
            raise failure

        if failure_point == "before-installation":
            guard.{owner} = RejectInstallation()
            guard.print = Mock()
        else:
            guard.print = Mock(side_effect=fail_during_print)

        try:
            guard.enable_{module}()
        except RuntimeError as caught:
            assert caught is failure
        else:
            raise AssertionError("The activation exception did not propagate")
        finally:
            guard.{owner} = owner

        if failure_point == "before-installation":
            guard.print.assert_not_called()
        else:
            guard.print.assert_called_once()

        expected_hook = (
            external_hook if failure_point == "after-external-replacement" else prior_hook
        )
        assert getattr(owner, attribute) is expected_hook
        assert guard.{delegate} is previous_delegate

        guard.print = Mock()
        guard.enable_{module}()
        guard.print.assert_called_once()
        assert getattr(owner, attribute) is wrapper
        assert guard.{delegate} is expected_hook
        guard.disable_{module}()
        assert getattr(owner, attribute) is expected_hook
        """,
    )


@agent_opt_in
def test_agent_import_has_no_side_effects(tmp_path):
    run_child(
        tmp_path,
        """
        before = sorted(sandbox.rglob("*"))
        output = io.StringIO()
        errors = io.StringIO()

        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            import test_agent

        assert builtins.open is native_open
        assert socket.create_connection is native_connection
        urllib.request.urlopen.assert_not_called()
        assert output.getvalue() == ""
        assert errors.getvalue() == ""
        assert sorted(sandbox.rglob("*")) == before
        """,
    )


@agent_opt_in
def test_explicit_demo_runs_with_simulated_io_and_restores_hooks(tmp_path):
    run_child(
        tmp_path,
        """
        from urllib.parse import urlsplit

        from core import fs_guard, network_guard

        fs_guard.log_event = Mock()
        network_guard.log_event = Mock()
        connector = Mock()
        socket.create_connection = connector

        def fake_urlopen(url, *, timeout):
            host = urlsplit(url).hostname
            return socket.create_connection((host, 443), timeout=timeout)

        def fake_open(path, mode, *args):
            assert path == "temp_report.txt"
            assert mode == "w"
            return io.StringIO()

        urllib.request.urlopen = Mock(side_effect=fake_urlopen)
        file_writer = Mock(side_effect=fake_open)
        builtins.open = file_writer

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runpy.run_path(str(repo / "test_agent.py"), run_name="__main__")

        assert builtins.open is file_writer
        assert socket.create_connection is connector
        connector.assert_called_once_with(("api.github.com", 443), timeout=3)
        file_writer.assert_called_once()
        assert urllib.request.urlopen.call_count == 2
        assert network_guard.log_event.call_count == 2
        assert fs_guard.log_event.call_count == 3
        assert "SIMULAZIONE COMPLETATA" in output.getvalue()
        assert list(sandbox.rglob("*")) == [Path.cwd()]
        """,
    )


@agent_opt_in
def test_demo_restores_both_hooks_after_body_raises(tmp_path):
    run_child(
        tmp_path,
        """
        import test_agent
        from core import fs_guard, network_guard

        failure = RuntimeError("simulated demo failure")

        def fail_action(*args):
            assert builtins.open is fs_guard._guarded_open
            assert socket.create_connection is network_guard._guarded_connection
            raise failure

        test_agent.simulate_agent_action = Mock(side_effect=fail_action)
        try:
            test_agent.main()
        except RuntimeError as caught:
            assert caught is failure
        else:
            raise AssertionError("The demo exception did not propagate")

        test_agent.simulate_agent_action.assert_called_once()
        assert builtins.open is native_open
        assert socket.create_connection is native_connection
        """,
    )


@agent_opt_in
@pytest.mark.parametrize(
    ("failure_point", "network_already_active"),
    [("before", False), ("after", False), ("after", True)],
    ids=["before-assignment", "after-assignment", "preexisting-network-hook"],
)
def test_demo_rolls_back_when_second_hook_fails(
    tmp_path, failure_point, network_already_active
):
    run_child(
        tmp_path,
        f"""
        import test_agent
        from core import fs_guard, network_guard

        if {network_already_active!r}:
            network_guard.enable_network_guard()
        prior_open = builtins.open
        prior_connection = socket.create_connection
        failure = RuntimeError("simulated filesystem activation failure")
        action = Mock()
        test_agent.simulate_agent_action = action
        real_enable = test_agent.enable_fs_guard
        previous_print = getattr(fs_guard, "print", builtins.print)

        def fail_before_assignment():
            assert socket.create_connection is network_guard._guarded_connection
            assert builtins.open is prior_open
            raise failure

        def fail_after_assignment(*args, **kwargs):
            assert socket.create_connection is network_guard._guarded_connection
            assert builtins.open is fs_guard._guarded_open
            raise failure

        if {failure_point!r} == "before":
            test_agent.enable_fs_guard = fail_before_assignment
        else:
            fs_guard.print = fail_after_assignment

        try:
            test_agent.main()
        except RuntimeError as caught:
            assert caught is failure
        else:
            raise AssertionError("The activation exception did not propagate")
        finally:
            test_agent.enable_fs_guard = real_enable
            fs_guard.print = previous_print

        action.assert_not_called()
        assert builtins.open is prior_open
        assert socket.create_connection is prior_connection

        def observe_retry(*args):
            assert builtins.open is fs_guard._guarded_open
            assert socket.create_connection is network_guard._guarded_connection

        action.side_effect = observe_retry
        test_agent.main()
        assert [call.args[0] for call in action.call_args_list] == [
            "Connessione API autorizzata (GitHub)",
            "Tentativo esfiltrazione dati (Connessione a dominio malevolo)",
            "Creazione file report temporaneo (Operazione sicura)",
            "Tentativo di lettura file password (Directory Traversal)",
            "Tentativo di modifica configurazioni di sistema (.env)",
        ]
        assert builtins.open is prior_open
        assert socket.create_connection is prior_connection

        if {network_already_active!r}:
            network_guard.disable_network_guard()
        assert socket.create_connection is native_connection
        """,
    )
