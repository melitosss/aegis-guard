import ast
import builtins
import json
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

from core import logger


def test_appends_ordered_json_lines_with_required_and_optional_fields(monkeypatch, tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(logger, "LOG_FILE", str(audit_file))

    logger.log_event("fs_access", "ALLOWED", "report.txt", "workspace", mode="w")
    logger.log_event("network_request", "BLOCKED", "example.invalid", port=443)

    lines = audit_file.read_text(encoding="utf-8").splitlines(keepends=True)
    assert len(lines) == 2
    assert all(line.endswith("\n") for line in lines)
    events = [json.loads(line) for line in lines]
    for event in events:
        datetime.fromisoformat(event.pop("timestamp"))
    assert events == [
        {
            "event_type": "fs_access",
            "action": "ALLOWED",
            "target": "report.txt",
            "detail": "workspace",
            "mode": "w",
        },
        {
            "event_type": "network_request",
            "action": "BLOCKED",
            "target": "example.invalid",
            "detail": "",
            "port": 443,
        },
    ]


def test_omits_falsy_optional_fields(monkeypatch, tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(logger, "LOG_FILE", str(audit_file))

    logger.log_event("network_request", "BLOCKED", "example.invalid", mode="", port=0)

    event = json.loads(audit_file.read_text(encoding="utf-8"))
    assert "mode" not in event
    assert "port" not in event


def test_propagates_audit_open_error(monkeypatch, tmp_path):
    monkeypatch.setattr(logger, "LOG_FILE", str(tmp_path))

    with pytest.raises(OSError):
        logger.log_event("fs_access", "ALLOWED", "report.txt")


def test_logger_appends_one_event_without_reentering_builtin_open(monkeypatch, tmp_path):
    audit_file = str(tmp_path / "audit.jsonl")
    monkeypatch.setattr(logger, "LOG_FILE", audit_file)
    opener = MagicMock()
    monkeypatch.setattr(logger, "_open_audit", opener, raising=False)
    intercepted_open = Mock(side_effect=AssertionError("logger reentered builtins.open"))

    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "open", intercepted_open)
        logger.log_event("fs_access", "BLOCKED", "synthetic-target", mode="a")

    intercepted_open.assert_not_called()
    opener.assert_called_once_with(audit_file, "a")
    writer = opener.return_value.__enter__.return_value.write
    writer.assert_called_once()
    (line,) = writer.call_args.args
    assert line.endswith("\n")
    (record,) = line.splitlines()
    event = json.loads(record)
    assert (event["event_type"], event["action"], event["target"], event["mode"]) == (
        "fs_access", "BLOCKED", "synthetic-target", "a"
    )


def test_dashboard_load_data_reads_temporary_audit_without_guard(tmp_path):
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    source = ast.parse(app_path.read_text(encoding="utf-8"), filename=str(app_path))
    (load_data,) = [
        node for node in source.body
        if isinstance(node, ast.FunctionDef) and node.name == "load_data"
    ]
    audit_file = tmp_path / "audit.jsonl"
    event = {"timestamp": "2026-01-01T00:00:00", "action": "BLOCKED"}
    audit_file.write_text(json.dumps(event) + "\n", encoding="utf-8")
    pandas = Mock()
    frame = {"timestamp": [event["timestamp"]]}
    pandas.DataFrame.return_value = frame
    plain_open = Mock(wraps=builtins.open)
    namespace = {
        "LOG_FILE": str(audit_file),
        "json": json,
        "open": plain_open,
        "os": os,
        "pd": pandas,
    }
    exec(compile(ast.Module(body=[load_data], type_ignores=[]), str(app_path), "exec"), namespace)

    assert namespace["load_data"]() is frame
    plain_open.assert_called_once_with(str(audit_file), "r")
    pandas.DataFrame.assert_called_once_with([event])
