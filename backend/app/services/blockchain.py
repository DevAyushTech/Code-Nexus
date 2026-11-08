import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Callable

from app.core.config import Settings, settings

SEPOLIA_CHAIN_ID = 11155111
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
PRIVATE_KEY_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")
ABI_PATH = Path(__file__).resolve().parents[2] / "contracts" / "abi" / "ThreatRegistry.v1.json"
TRANSACTION_STATES = frozenset({"pending", "submitted", "confirming", "confirmed", "failed", "reverted", "timeout"})
VALID_STATE_TRANSITIONS = {
    "pending": frozenset({"submitted", "confirmed", "failed"}),
    "submitted": frozenset({"confirming", "confirmed", "reverted", "timeout", "failed"}),
    "confirming": frozenset({"confirmed", "reverted", "timeout", "failed"}),
    "timeout": frozenset({"confirming", "confirmed", "reverted", "timeout", "failed"}),
}


def transition_state(current: str, target: str) -> str:
    if current == target:
        return target
    if current not in TRANSACTION_STATES or target not in TRANSACTION_STATES or target not in VALID_STATE_TRANSITIONS.get(current, frozenset()):
        raise BlockchainTransactionError(f"Invalid blockchain transaction state transition: {current} -> {target}.")
    return target


class BlockchainConfigurationError(ValueError):
    pass


class BlockchainDependencyError(RuntimeError):
    pass


class BlockchainRPCError(RuntimeError):
    pass


class BlockchainTransactionError(RuntimeError):
    pass


@dataclass(frozen=True)
class BlockchainStatus:
    mode: str
    status: str
    chain_id: int | None
    contract_address: str | None
    account_address: str | None
    on_chain: bool = False


@dataclass(frozen=True)
class RegistrationResult:
    status: str
    tx_hash: str | None
    chain_id: int
    contract_address: str
    block_number: int | None = None
    gas_used: int | None = None
    submitted_at: datetime | None = None
    confirmed_at: datetime | None = None
    confirmations: int | None = None
    error_message: str | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    status: str
    verified: bool
    chain_id: int
    contract_address: str
    registered: bool = False
    reporter: str | None = None
    on_chain_timestamp: int | None = None
    confirmations: int | None = None
    receipt_status: int | None = None
    block_number: int | None = None
    error_code: str | None = None


def _receipt_result(status: BlockchainStatus, config: Settings, tx_hash: str, receipt: Any, submitted_at: datetime, web3: Any) -> RegistrationResult:
    try:
        block_number = int(receipt["blockNumber"])
        gas_used = int(receipt["gasUsed"])
        receipt_status = int(receipt["status"])
        current_block = int(web3.eth.block_number)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise BlockchainRPCError("Blockchain receipt response was malformed.") from exc
    if receipt_status != 1:
        return RegistrationResult("reverted", tx_hash, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", block_number, gas_used, submitted_at, None, 0, "Transaction receipt reported failure.", "transaction_reverted")
    confirmations = max(0, current_block - block_number + 1)
    if confirmations < config.blockchain_confirmations:
        return RegistrationResult("confirming", tx_hash, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", block_number, gas_used, submitted_at, None, confirmations, "Receipt is successful but confirmation depth has not been reached.", "insufficient_confirmations")
    return RegistrationResult("confirmed", tx_hash, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", block_number, gas_used, submitted_at, datetime.now(timezone.utc), confirmations)


class MockBlockchainAdapter:
    def status(self) -> BlockchainStatus:
        return BlockchainStatus("mock", "mock", None, None, None, False)

    def validate_provider(self) -> BlockchainStatus:
        return self.status()


class SepoliaBlockchainAdapter:
    def __init__(self, config: Settings):
        self.config = config
        self._web3: Any = None
        self._contract: Any = None
        self._account: Any = None

    def _load_web3(self) -> Any:
        if self._web3 is not None:
            return self._web3
        try:
            from web3 import Web3
        except ImportError as exc:
            raise BlockchainDependencyError("Web3.py is required for Sepolia mode. Install requirements-blockchain.txt.") from exc
        self._web3 = Web3(Web3.HTTPProvider(self.config.blockchain_rpc_url, request_kwargs={"timeout": self.config.request_timeout_seconds}))
        return self._web3

    def _load_abi(self) -> list[dict[str, Any]]:
        try:
            with ABI_PATH.open(encoding="utf-8") as file:
                artifact = json.load(file)
            abi = artifact["abi"]
            if not isinstance(abi, list):
                raise ValueError
            return abi
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise BlockchainConfigurationError("ThreatRegistry ABI artifact is invalid or unavailable.") from exc

    def validate_configuration(self) -> None:
        if self.config.blockchain_chain_id != SEPOLIA_CHAIN_ID:
            raise BlockchainConfigurationError("Only Ethereum Sepolia chain ID 11155111 is supported.")
        if not self.config.blockchain_contract_address or not ADDRESS_PATTERN.fullmatch(self.config.blockchain_contract_address):
            raise BlockchainConfigurationError("Invalid Sepolia contract address.")
        if not self.config.blockchain_account_address or not ADDRESS_PATTERN.fullmatch(self.config.blockchain_account_address):
            raise BlockchainConfigurationError("Invalid Sepolia account address.")
        if not self.config.blockchain_private_key or not PRIVATE_KEY_PATTERN.fullmatch(self.config.blockchain_private_key.get_secret_value()):
            raise BlockchainConfigurationError("Invalid private key format.")

    def validate_read_configuration(self) -> None:
        if self.config.blockchain_chain_id != SEPOLIA_CHAIN_ID:
            raise BlockchainConfigurationError("Only Ethereum Sepolia chain ID 11155111 is supported.")
        if not self.config.blockchain_contract_address or not ADDRESS_PATTERN.fullmatch(self.config.blockchain_contract_address):
            raise BlockchainConfigurationError("Invalid Sepolia contract address.")
        if not self.config.blockchain_rpc_url:
            raise BlockchainConfigurationError("Sepolia RPC URL is required for verification.")

    def derive_account_address(self) -> str:
        self.validate_configuration()
        try:
            from eth_account import Account
        except ImportError as exc:
            raise BlockchainDependencyError("Web3.py is required for private-key account derivation.") from exc
        return Account.from_key(self.config.blockchain_private_key.get_secret_value()).address

    def validate_account(self) -> None:
        derived = self.derive_account_address()
        if derived.lower() != self.config.blockchain_account_address.lower():
            raise BlockchainConfigurationError("Configured account address does not match the private key.")

    def _contract_instance(self, web3: Any) -> Any:
        if self._contract is None:
            address = web3.to_checksum_address(self.config.blockchain_contract_address)
            self._contract = web3.eth.contract(address=address, abi=self._load_abi())
        return self._contract

    def validate_provider(self) -> BlockchainStatus:
        self.validate_configuration()
        self.validate_account()
        return self._validate_network(require_operator=True)

    def _validate_network(self, require_operator: bool = False) -> BlockchainStatus:
        web3 = self._load_web3()
        try:
            if not web3.is_connected():
                raise BlockchainRPCError("Blockchain RPC endpoint is unavailable.")
            rpc_chain_id = int(web3.eth.chain_id)
            if rpc_chain_id != SEPOLIA_CHAIN_ID:
                raise BlockchainConfigurationError("RPC endpoint is not Ethereum Sepolia.")
            code = web3.eth.get_code(web3.to_checksum_address(self.config.blockchain_contract_address))
            if not code or code in (b"", "0x", "0x0"):
                raise BlockchainConfigurationError("No deployed contract bytecode exists at the configured address.")
            if require_operator:
                contract = self._contract_instance(web3)
                authorized = contract.functions.operators(web3.to_checksum_address(self.config.blockchain_account_address)).call()
                if not authorized:
                    raise BlockchainConfigurationError("Configured signer is not an authorized contract operator.")
        except (BlockchainConfigurationError, BlockchainDependencyError, BlockchainRPCError):
            raise
        except Exception as exc:
            raise BlockchainRPCError("Blockchain provider validation failed.") from exc
        return BlockchainStatus("sepolia", "validated", rpc_chain_id, self.config.blockchain_contract_address, self.config.blockchain_account_address, True)

    def validate_read_provider(self) -> BlockchainStatus:
        self.validate_read_configuration()
        return self._validate_network()

    def _hash_bytes32(self, report_hash: str) -> bytes:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", report_hash):
            raise BlockchainConfigurationError("Report hash must be a 32-byte hexadecimal digest.")
        return bytes.fromhex(report_hash)

    def inspect_transaction(self, tx_hash: str, submitted_at: datetime | None = None) -> RegistrationResult:
        status = self.validate_read_provider()
        web3 = self._load_web3()
        submitted_at = submitted_at or datetime.now(timezone.utc)
        try:
            receipt = web3.eth.get_transaction_receipt(tx_hash)
        except Exception as exc:
            message = str(exc).lower()
            if "not found" in message or "unknown" in message or "receipt" in message:
                return RegistrationResult("timeout", tx_hash, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", submitted_at=submitted_at, error_message="Transaction receipt is not yet available.", error_code="receipt_unavailable")
            raise BlockchainRPCError("Transaction receipt lookup failed.") from exc
        try:
            return _receipt_result(status, self.config, tx_hash, receipt, submitted_at, web3)
        except BlockchainRPCError:
            raise
        except Exception as exc:
            raise BlockchainRPCError("Blockchain receipt response was invalid.") from exc

    def register_hash(self, report_hash: str, on_submitted: Callable[[str, datetime], None] | None = None) -> RegistrationResult:
        status = self.validate_provider()
        web3 = self._load_web3()
        contract = self._contract_instance(web3)
        digest = self._hash_bytes32(report_hash)
        submitted_at = datetime.now(timezone.utc)
        try:
            exists, _, _ = contract.functions.verifyThreat(digest).call()
            if exists:
                return RegistrationResult("confirming", None, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", confirmations=None, error_message="Threat is registered on-chain; confirmation depth could not be established from the verification call.", error_code="confirmation_depth_unknown")
            account = self._account
            if account is None:
                from eth_account import Account
                account = Account.from_key(self.config.blockchain_private_key.get_secret_value())
                self._account = account
            nonce = web3.eth.get_transaction_count(account.address, "pending")
            gas_price = web3.eth.gas_price
            transaction = contract.functions.registerThreat(digest).build_transaction({
                "from": account.address,
                "nonce": nonce,
                "chainId": SEPOLIA_CHAIN_ID,
                "gas": self.config.blockchain_gas_limit,
                "gasPrice": gas_price,
            })
            estimated = contract.functions.registerThreat(digest).estimate_gas({"from": account.address})
            if estimated > self.config.blockchain_gas_limit:
                raise BlockchainTransactionError("Estimated gas exceeds configured gas limit.")
            transaction["gas"] = estimated
            signed = account.sign_transaction(transaction)
            tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
            tx_hex = web3.to_hex(tx_hash)
            if on_submitted:
                on_submitted(tx_hex, submitted_at)
            try:
                receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=self.config.blockchain_tx_timeout)
            except TimeoutError:
                return RegistrationResult("timeout", tx_hex, SEPOLIA_CHAIN_ID, status.contract_address or "", submitted_at=submitted_at, error_message="Transaction receipt timed out.", error_code="receipt_timeout")
            return _receipt_result(status, self.config, tx_hex, receipt, submitted_at, web3)
        except BlockchainTransactionError:
            raise
        except BlockchainRPCError:
            raise
        except Exception as exc:
            raise BlockchainTransactionError("Blockchain transaction failed.") from exc

    def verify_hash(self, report_hash: str) -> dict[str, Any]:
        status = self.validate_read_provider()
        web3 = self._load_web3()
        contract = self._contract_instance(web3)
        try:
            exists, reporter, timestamp = contract.functions.verifyThreat(self._hash_bytes32(report_hash)).call()
            return {"status": "completed", "on_chain": True, "chain_id": status.chain_id, "contract_address": status.contract_address, "exists": bool(exists), "reporter": reporter, "timestamp": int(timestamp)}
        except Exception as exc:
            raise BlockchainRPCError("On-chain verification failed.") from exc

    def verify_commitment(self, expected_hash: str, tx_hash: str | None = None) -> VerificationResult:
        status = self.validate_read_provider()
        web3 = self._load_web3()
        contract = self._contract_instance(web3)
        try:
            exists, reporter, timestamp = contract.functions.verifyThreat(self._hash_bytes32(expected_hash)).call()
            exists = bool(exists)
            timestamp = int(timestamp)
        except (BlockchainConfigurationError, BlockchainRPCError):
            raise
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            raise BlockchainRPCError("On-chain verification response was malformed.") from exc
        except Exception as exc:
            raise BlockchainRPCError("On-chain verification failed.") from exc
        receipt_status = None
        confirmations = None
        block_number = None
        if tx_hash:
            try:
                receipt = web3.eth.get_transaction_receipt(tx_hash)
            except Exception as exc:
                message = str(exc).lower()
                if "not found" in message or "unknown" in message or "receipt" in message:
                    return VerificationResult("pending", False, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", bool(exists), reporter if exists else None, int(timestamp) if exists else None, error_code="receipt_unavailable")
                raise BlockchainRPCError("Transaction receipt lookup failed.") from exc
            try:
                receipt_status = int(receipt["status"])
                block_number = int(receipt["blockNumber"])
                confirmations = max(0, int(web3.eth.block_number) - block_number + 1)
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise BlockchainRPCError("Blockchain receipt response was malformed.") from exc
            if receipt_status != 1:
                return VerificationResult("mismatch", False, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", bool(exists), reporter if exists else None, int(timestamp) if exists else None, confirmations, receipt_status, block_number, "transaction_reverted")
            if confirmations < self.config.blockchain_confirmations:
                return VerificationResult("confirming", False, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", bool(exists), reporter if exists else None, int(timestamp) if exists else None, confirmations, receipt_status, block_number, "insufficient_confirmations")
        elif exists:
            return VerificationResult("confirming", False, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", True, reporter, int(timestamp), None, error_code="confirmation_depth_unknown")
        if not exists:
            return VerificationResult("not_registered", False, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", False, confirmations=confirmations, receipt_status=receipt_status, block_number=block_number)
        return VerificationResult("verified", True, status.chain_id or SEPOLIA_CHAIN_ID, status.contract_address or "", True, reporter, int(timestamp), confirmations, receipt_status, block_number)


class BlockchainService:
    def __init__(self, config: Settings = settings):
        self.config = config
        self.adapter = MockBlockchainAdapter() if config.blockchain_mode == "mock" else SepoliaBlockchainAdapter(config)

    def status(self) -> BlockchainStatus:
        return self.adapter.status() if self.config.blockchain_mode == "mock" else self.adapter.validate_provider()


def get_blockchain_service() -> BlockchainService:
    return BlockchainService()
