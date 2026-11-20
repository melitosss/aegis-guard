import socket
from .logger import log_event

ALLOWED_DOMAINS = ["api.github.com", "jsonplaceholder.typicode.com"]
_original_create_connection = socket.create_connection

class NetworkSecurityException(Exception): pass

def _guarded_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    host, port = address
    
    if host not in ALLOWED_DOMAINS:
        log_event("network_request", "BLOCKED", host, "Dominio non in allowlist", port=port)
        raise NetworkSecurityException(f"Egress policy violation: Access to {host} is blocked.")
    
    log_event("network_request", "ALLOWED", host, "Dominio autorizzato", port=port)
    
    if source_address:
        return _original_create_connection(address, timeout=timeout, source_address=source_address)
    return _original_create_connection(address, timeout=timeout)

def enable_network_guard():
    """Attiva l'intercettatore di rete a livello globale."""
    global _original_create_connection

    current_connection = socket.create_connection
    if current_connection is _guarded_connection:
        return

    previous_delegate = _original_create_connection
    try:
        _original_create_connection = current_connection
        socket.create_connection = _guarded_connection
        print("[AEGIS] Egress Network Guard attivato.")
    except BaseException:
        if socket.create_connection is _guarded_connection:
            socket.create_connection = current_connection
        _original_create_connection = previous_delegate
        raise


def disable_network_guard():
    """Ripristina il delegato se il guard è ancora installato."""
    if socket.create_connection is _guarded_connection:
        socket.create_connection = _original_create_connection