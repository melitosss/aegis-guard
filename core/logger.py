import json
import datetime
import os

LOG_FILE = "aegis_audit.jsonl"

def log_event(event_type, action, target, detail="", mode=None, port=None):
    """Sistema centralizzato per l'Audit Logging strutturato."""
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "action": action,
        "target": target,
        "detail": detail
    }
    if mode: event["mode"] = mode
    if port: event["port"] = port
    
    # Usiamo builtins.open per evitare conflitti con il nostro FS Guard
    import builtins
    with builtins.open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")