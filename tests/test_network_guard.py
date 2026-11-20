from unittest.mock import Mock

import pytest

from core import network_guard


@pytest.fixture
def guarded_network(monkeypatch):
    original_connection = Mock()
    audit = Mock()
    monkeypatch.setattr(network_guard, "_original_create_connection", original_connection)
    monkeypatch.setattr(network_guard, "log_event", audit)
    return original_connection, audit


@pytest.mark.parametrize("host", ["api.github.com", "jsonplaceholder.typicode.com"])
@pytest.mark.parametrize("source_address", [None, ("127.0.0.1", 0)])
def test_allows_exact_domain_and_forwards_arguments(guarded_network, host, source_address):
    original_connection, audit = guarded_network
    address = (host, 443)

    result = network_guard._guarded_connection(address, timeout=2, source_address=source_address)

    assert result is original_connection.return_value
    expected_kwargs = {"timeout": 2}
    if source_address is not None:
        expected_kwargs["source_address"] = source_address
    original_connection.assert_called_once_with(address, **expected_kwargs)
    audit.assert_called_once_with(
        "network_request", "ALLOWED", host, "Dominio autorizzato", port=443
    )


@pytest.mark.parametrize("host", ["example.invalid", "api.github.com.example.invalid"])
def test_blocks_host_absent_from_allowlist(guarded_network, host):
    original_connection, audit = guarded_network

    with pytest.raises(network_guard.NetworkSecurityException, match="Egress policy violation"):
        network_guard._guarded_connection((host, 443))

    original_connection.assert_not_called()
    audit.assert_called_once_with(
        "network_request", "BLOCKED", host, "Dominio non in allowlist", port=443
    )


def test_propagates_connector_error_after_logging_policy_decision(guarded_network):
    original_connection, audit = guarded_network
    error = OSError("simulated connection failure")
    original_connection.side_effect = error
    address = ("api.github.com", 443)

    with pytest.raises(OSError) as caught:
        network_guard._guarded_connection(address, timeout=2)

    assert caught.value is error
    audit.assert_called_once_with(
        "network_request", "ALLOWED", address[0], "Dominio autorizzato", port=443
    )
