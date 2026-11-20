import builtins
import os
from .logger import log_event, LOG_FILE

SAFE_WORKSPACE = os.path.abspath(os.getcwd())
_original_open = builtins.open

class FileSecurityException(Exception): pass

def _guarded_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    # Ignora i file interni di Python (es. importlib) e il nostro file di log
    if isinstance(file, str) and (file.startswith('<') or os.path.abspath(file) == os.path.abspath(LOG_FILE)):
        return _original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)

    target_path = os.path.abspath(file)
    
    try:
        common = os.path.commonpath([SAFE_WORKSPACE, target_path])
        is_safe = common == SAFE_WORKSPACE
    except ValueError:
        is_safe = False

    BLOCKED_EXTENSIONS = [".env", ".key", ".pem", ".pyc"]
    filename = os.path.basename(target_path).lower()
    _, ext = os.path.splitext(target_path)
    if filename == ".env" or filename.startswith(".env.") or ext.lower() == ".env":
        ext = ".env"

    if ext in BLOCKED_EXTENSIONS:
        log_event("fs_access", "BLOCKED", target_path, f"Violazione estensione ({ext})", mode=mode)
        raise FileSecurityException(f"File system policy violation: {ext} files are restricted.")

    if not is_safe:
        log_event("fs_access", "BLOCKED", target_path, "Tentativo di Directory Traversal", mode=mode)
        raise FileSecurityException(f"Path traversal violation: Access outside workspace blocked.")

    log_event("fs_access", "ALLOWED", target_path, "Accesso consentito in safe zone", mode=mode)
    return _original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)

def enable_fs_guard():
    """Attiva l'intercettatore del file system a livello globale."""
    global _original_open

    current_open = builtins.open
    if current_open is _guarded_open:
        return

    previous_delegate = _original_open
    try:
        _original_open = current_open
        builtins.open = _guarded_open
        print("[AEGIS] File System Supervisor attivato.")
    except BaseException:
        if builtins.open is _guarded_open:
            builtins.open = current_open
        _original_open = previous_delegate
        raise


def disable_fs_guard():
    """Ripristina il delegato se il guard è ancora installato."""
    if builtins.open is _guarded_open:
        builtins.open = _original_open