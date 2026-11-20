import json
from datetime import datetime

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
