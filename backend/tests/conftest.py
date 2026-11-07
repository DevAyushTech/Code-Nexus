import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def isolate_blockchain_configuration(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "BLOCKCHAIN_RPC_URL",
        "BLOCKCHAIN_CONTRACT_ADDRESS",
        "BLOCKCHAIN_PRIVATE_KEY",
        "BLOCKCHAIN_ACCOUNT_ADDRESS",
        "BLOCKCHAIN_CONTRACT_OWNER",
    ):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("BLOCKCHAIN_MODE", "mock")
    monkeypatch.setattr(settings, "blockchain_mode", "mock")
    monkeypatch.setattr(settings, "blockchain_rpc_url", None)
    monkeypatch.setattr(settings, "blockchain_contract_address", None)
    monkeypatch.setattr(settings, "blockchain_private_key", None)
    monkeypatch.setattr(settings, "blockchain_account_address", None)
    yield
