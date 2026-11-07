from pydantic import SecretStr, ValidationError
import pytest

from app.core.config import Settings
from app.services.blockchain import BlockchainConfigurationError, BlockchainDependencyError, BlockchainService, SepoliaBlockchainAdapter


def test_default_mode_is_mock():
    config = Settings()
    assert config.blockchain_mode == "mock"
    assert BlockchainService(config).status().on_chain is False


def test_sepolia_requires_complete_configuration():
    with pytest.raises(ValidationError):
        Settings(blockchain_mode="sepolia")


def test_invalid_mode_is_rejected():
    with pytest.raises(ValidationError):
        Settings(blockchain_mode="mainnet")


def sepolia_config(**overrides):
    values = {
        "blockchain_mode": "sepolia",
        "blockchain_rpc_url": "https://sepolia.example.invalid",
        "blockchain_contract_address": "0x" + "1" * 40,
        "blockchain_private_key": SecretStr("0x" + "a" * 64),
        "blockchain_account_address": "0x" + "2" * 40,
    }
    values.update(overrides)
    return Settings(**values)


def test_wrong_chain_id_is_rejected():
    with pytest.raises(ValidationError):
        sepolia_config(blockchain_chain_id=5)


@pytest.mark.parametrize("field", ["blockchain_contract_address", "blockchain_account_address"])
def test_invalid_address_is_rejected(field):
    with pytest.raises(ValidationError):
        sepolia_config(**{field: "not-an-address"})


def test_invalid_private_key_is_rejected():
    with pytest.raises(ValidationError):
        sepolia_config(blockchain_private_key=SecretStr("not-a-private-key"))


def test_mainnet_configuration_is_rejected():
    with pytest.raises(ValidationError):
        sepolia_config(blockchain_chain_id=1)
    with pytest.raises(ValidationError):
        sepolia_config(blockchain_rpc_url="https://mainnet.example.invalid")


def test_private_key_is_not_exposed():
    config = sepolia_config()
    assert config.blockchain_private_key.get_secret_value() not in repr(config)
    assert config.blockchain_private_key.get_secret_value() not in str(config)


def test_rpc_unavailable_is_explicit(monkeypatch):
    config = sepolia_config()
    adapter = SepoliaBlockchainAdapter(config)
    monkeypatch.setattr(adapter, "derive_account_address", lambda: config.blockchain_account_address)
    monkeypatch.setattr(adapter, "_load_web3", lambda: (_ for _ in ()).throw(ConnectionError("unavailable")))
    with pytest.raises(ConnectionError, match="validation failed|unavailable"):
        adapter.validate_provider()


def test_application_can_import_without_web3():
    from app.main import app
    assert app.title == "Nexus Threat Intelligence API"


def test_account_mismatch_is_rejected_before_provider(monkeypatch):
    config = sepolia_config()
    adapter = SepoliaBlockchainAdapter(config)
    monkeypatch.setattr(adapter, "derive_account_address", lambda: "0x" + "3" * 40)
    with pytest.raises(BlockchainConfigurationError, match="does not match"):
        adapter.validate_account()
