from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.services.blockchain import BlockchainConfigurationError, BlockchainRPCError, BlockchainTransactionError, SepoliaBlockchainAdapter, transition_state


def config():
    return Settings(
        blockchain_mode="sepolia",
        blockchain_rpc_url="https://sepolia.example.invalid",
        blockchain_contract_address="0x" + "1" * 40,
        blockchain_private_key=SecretStr("0x" + "a" * 64),
        blockchain_account_address="0x" + "2" * 40,
    )


def read_only_config():
    return Settings(
        blockchain_mode="sepolia",
        blockchain_rpc_url="https://sepolia.example.invalid",
        blockchain_contract_address="0x" + "1" * 40,
    )


class FakeCall:
    def __init__(self, value):
        self.value = value

    def call(self):
        return self.value


class FakeFunctions:
    def __init__(self, exists=False, authorized=True):
        self.exists = exists
        self.authorized = authorized

    def operators(self, address):
        return FakeCall(self.authorized)

    def verifyThreat(self, digest):
        return FakeCall((self.exists, "0x" + "3" * 40, 123))

    def registerThreat(self, digest):
        return self

    def build_transaction(self, values):
        return dict(values, data="0x1234")

    def estimate_gas(self, values):
        return 50_000


class FakeContract:
    def __init__(self, exists=False, authorized=True):
        self.functions = FakeFunctions(exists, authorized)


class FakeEth:
    chain_id = 11155111
    gas_price = 1
    block_number = 12

    def __init__(self, receipt=None, send_error=None):
        self.receipt = receipt or {"status": 1, "blockNumber": 10, "gasUsed": 40_000}
        self.send_error = send_error
        self.send_count = 0

    def get_code(self, address):
        return b"\x60\x00"

    def contract(self, address, abi):
        return FakeContract()

    def get_transaction_count(self, address, state):
        return 1

    def send_raw_transaction(self, raw):
        self.send_count += 1
        if self.send_error:
            raise self.send_error
        return b"\x12" * 32

    def wait_for_transaction_receipt(self, tx_hash, timeout):
        return self.receipt

    def get_transaction_receipt(self, tx_hash):
        return self.receipt


class FakeWeb3:
    def __init__(self, eth=None, connected=True):
        self.eth = eth or FakeEth()
        self.connected = connected

    def is_connected(self):
        return self.connected

    def to_checksum_address(self, address):
        return address

    def to_hex(self, value):
        return "0x" + value.hex()


def prepare_adapter(monkeypatch, eth=None, connected=True, authorized=True):
    adapter = SepoliaBlockchainAdapter(config())
    adapter._web3 = FakeWeb3(eth, connected)
    adapter._contract = FakeContract(authorized=authorized)
    monkeypatch.setattr(adapter, "derive_account_address", lambda: config().blockchain_account_address)
    monkeypatch.setattr(adapter, "_contract_instance", lambda web3: adapter._contract)
    class Account:
        address = config().blockchain_account_address
        def sign_transaction(self, transaction):
            return SimpleNamespace(raw_transaction=b"signed")
    adapter._account = Account()
    return adapter


def test_authorized_operator_check(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    assert adapter.validate_provider().status == "validated"


def test_read_only_provider_validation_does_not_require_signer(monkeypatch):
    adapter = SepoliaBlockchainAdapter(read_only_config())
    adapter._web3 = FakeWeb3()
    adapter._contract = FakeContract()
    status = adapter.validate_read_provider()
    assert status.status == "validated"
    assert not status.account_address


def test_read_only_verification_uses_contract_without_signer(monkeypatch):
    adapter = SepoliaBlockchainAdapter(read_only_config())
    adapter._web3 = FakeWeb3()
    adapter._contract = FakeContract(exists=True)
    result = adapter.verify_commitment("ab" * 32)
    assert result.status == "confirming"
    assert result.verified is False


def test_write_validation_rejects_missing_signer():
    adapter = SepoliaBlockchainAdapter(read_only_config())
    with pytest.raises(BlockchainConfigurationError, match="account address"):
        adapter.validate_configuration()


def test_unauthorized_operator_rejected(monkeypatch):
    adapter = prepare_adapter(monkeypatch, authorized=False)
    with pytest.raises(BlockchainConfigurationError, match="authorized"):
        adapter.validate_provider()


def test_wrong_chain_id_rejected(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    adapter._web3.eth.chain_id = 1
    with pytest.raises(BlockchainConfigurationError, match="not Ethereum Sepolia"):
        adapter.validate_provider()


def test_rpc_unavailable(monkeypatch):
    adapter = prepare_adapter(monkeypatch, connected=False)
    with pytest.raises(BlockchainRPCError, match="unavailable"):
        adapter.validate_provider()


def test_missing_contract_bytecode(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    adapter._web3.eth.get_code = lambda address: b""
    with pytest.raises(BlockchainConfigurationError, match="bytecode"):
        adapter.validate_provider()


def test_invalid_signer(monkeypatch):
    adapter = SepoliaBlockchainAdapter(config())
    monkeypatch.setattr(adapter, "derive_account_address", lambda: "0x" + "4" * 40)
    with pytest.raises(BlockchainConfigurationError, match="does not match"):
        adapter.validate_account()


def test_successful_registration(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    result = adapter.register_hash("ab" * 32)
    assert result.status == "confirmed"
    assert result.tx_hash.startswith("0x")
    assert result.block_number == 10
    assert result.gas_used == 40_000
    assert result.confirmations == 3


def test_duplicate_registration_is_idempotent(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    adapter._contract = FakeContract(exists=True)
    result = adapter.register_hash("ab" * 32)
    assert result.status == "confirming"
    assert result.error_code == "confirmation_depth_unknown"
    assert result.tx_hash is None


def test_gas_estimation_failure(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    adapter._contract.functions.estimate_gas = lambda values: (_ for _ in ()).throw(RuntimeError("gas"))
    with pytest.raises(BlockchainTransactionError):
        adapter.register_hash("ab" * 32)


def test_submission_failure(monkeypatch):
    adapter = prepare_adapter(monkeypatch, eth=FakeEth(send_error=RuntimeError("send")))
    with pytest.raises(BlockchainTransactionError):
        adapter.register_hash("ab" * 32)


def test_reverted_receipt(monkeypatch):
    adapter = prepare_adapter(monkeypatch, eth=FakeEth(receipt={"status": 0, "blockNumber": 10, "gasUsed": 40_000}))
    result = adapter.register_hash("ab" * 32)
    assert result.status == "reverted"
    assert result.error_message


def test_receipt_timeout(monkeypatch):
    class TimeoutEth(FakeEth):
        def wait_for_transaction_receipt(self, tx_hash, timeout):
            raise TimeoutError("timeout")
    adapter = prepare_adapter(monkeypatch, eth=TimeoutEth())
    result = adapter.register_hash("ab" * 32)
    assert result.status == "timeout"
    assert result.error_code == "receipt_timeout"


def test_rpc_timeout_is_sanitized(monkeypatch):
    class TimeoutProvider(FakeEth):
        def wait_for_transaction_receipt(self, tx_hash, timeout):
            raise TimeoutError("RPC provider timeout")
    adapter = prepare_adapter(monkeypatch, eth=TimeoutProvider())
    result = adapter.register_hash("ab" * 32)
    assert result.status == "timeout"
    assert "RPC provider" not in (result.error_message or "")


def test_insufficient_confirmations(monkeypatch):
    adapter = prepare_adapter(monkeypatch, eth=FakeEth())
    adapter._web3.eth.block_number = 10
    result = adapter.register_hash("ab" * 32)
    assert result.status == "confirming"
    assert result.error_code == "insufficient_confirmations"


def test_malformed_receipt_is_reported_as_rpc_error(monkeypatch):
    adapter = prepare_adapter(monkeypatch, eth=FakeEth(receipt={"status": 1}))
    with pytest.raises(BlockchainRPCError, match="receipt"):
        adapter.register_hash("ab" * 32)


def test_receipt_recovery(monkeypatch):
    eth = FakeEth()
    adapter = prepare_adapter(monkeypatch, eth=eth)
    result = adapter.inspect_transaction("0x" + "12" * 32)
    assert result.status == "confirmed"
    assert eth.send_count == 0


def test_invalid_state_transition():
    with pytest.raises(BlockchainTransactionError):
        transition_state("confirmed", "submitted")


def test_on_chain_verification_match(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    result = adapter.verify_hash("ab" * 32)
    assert result["status"] == "completed"
    assert result["exists"] is False


def test_on_chain_verification_exists(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    adapter._contract = FakeContract(exists=True)
    result = adapter.verify_hash("ab" * 32)
    assert result["exists"] is True
    assert result["reporter"].startswith("0x")


def test_verified_commitment_requires_successful_receipt_and_depth(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    adapter._contract = FakeContract(exists=True)
    result = adapter.verify_commitment("ab" * 32, "0x" + "12" * 32)
    assert result.status == "verified"
    assert result.verified is True
    assert result.confirmations == 3
    assert result.receipt_status == 1


def test_canonical_hash_is_deterministic():
    from app.api.v1.router import canonical_report_hash
    report = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000001",
        target_hash="a" * 64,
        classification="SUSPICIOUS",
        risk_score=42,
    )
    assert canonical_report_hash(report) == canonical_report_hash(report)


def test_unregistered_commitment(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    result = adapter.verify_commitment("ab" * 32)
    assert result.status == "not_registered"
    assert result.verified is False


def test_verification_pending_when_receipt_unavailable(monkeypatch):
    class PendingEth(FakeEth):
        def get_transaction_receipt(self, tx_hash):
            raise RuntimeError("transaction receipt not found")
    adapter = prepare_adapter(monkeypatch, eth=PendingEth())
    result = adapter.verify_commitment("ab" * 32, "0x" + "12" * 32)
    assert result.status == "pending"
    assert result.error_code == "receipt_unavailable"


def test_verification_reverted_receipt(monkeypatch):
    adapter = prepare_adapter(monkeypatch, eth=FakeEth(receipt={"status": 0, "blockNumber": 10, "gasUsed": 40_000}))
    adapter._contract = FakeContract(exists=True)
    result = adapter.verify_commitment("ab" * 32, "0x" + "12" * 32)
    assert result.status == "mismatch"
    assert result.verified is False
    assert result.error_code == "transaction_reverted"


def test_verification_insufficient_confirmations(monkeypatch):
    adapter = prepare_adapter(monkeypatch, eth=FakeEth())
    adapter._web3.eth.block_number = 10
    adapter._contract = FakeContract(exists=True)
    result = adapter.verify_commitment("ab" * 32, "0x" + "12" * 32)
    assert result.status == "confirming"
    assert result.verified is False
    assert result.error_code == "insufficient_confirmations"


def test_verification_malformed_receipt_is_rpc_error(monkeypatch):
    adapter = prepare_adapter(monkeypatch, eth=FakeEth(receipt={"status": 1}))
    adapter._contract = FakeContract(exists=True)
    with pytest.raises(BlockchainRPCError, match="receipt"):
        adapter.verify_commitment("ab" * 32, "0x" + "12" * 32)


def test_on_chain_match_without_receipt_is_not_verified(monkeypatch):
    adapter = prepare_adapter(monkeypatch)
    adapter._contract = FakeContract(exists=True)
    result = adapter.verify_commitment("ab" * 32)
    assert result.status == "confirming"
    assert result.verified is False
    assert result.error_code == "confirmation_depth_unknown"


def test_private_key_not_disclosed():
    config_value = config()
    assert config_value.blockchain_private_key.get_secret_value() not in repr(config_value)
