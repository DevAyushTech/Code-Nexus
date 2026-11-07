// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract ThreatRegistry is Ownable, Pausable {
    struct Record {
        address reporter;
        uint64 timestamp;
        bool exists;
    }

    mapping(bytes32 => Record) public records;
    mapping(address => bool) public operators;

    event ThreatRegistered(bytes32 indexed reportHash, address indexed reporter, uint64 timestamp);
    event OperatorUpdated(address indexed operator, bool authorized);

    error EmptyHash();
    error AlreadyRegistered();
    error NotOperator();

    /// @notice Creates a registry with the deployer as owner and optional first operator.
    /// @param initialOwner Account allowed to manage operators and pause state.
    /// @param initialOperator Backend account allowed to register commitments.
    constructor(address initialOwner, address initialOperator) Ownable(initialOwner) {
        if (initialOperator != address(0)) {
            operators[initialOperator] = true;
            emit OperatorUpdated(initialOperator, true);
        }
    }

    modifier onlyOperator() {
        if (!operators[msg.sender]) revert NotOperator();
        _;
    }

    /// @notice Registers a privacy-preserving report commitment.
    /// @dev Raw URLs, messages, emails, and personal data must never be submitted.
    function registerThreat(bytes32 reportHash) external onlyOperator whenNotPaused {
        if (reportHash == bytes32(0)) revert EmptyHash();
        if (records[reportHash].exists) revert AlreadyRegistered();
        records[reportHash] = Record(msg.sender, uint64(block.timestamp), true);
        emit ThreatRegistered(reportHash, msg.sender, uint64(block.timestamp));
    }

    /// @notice Adds or removes an authorized backend operator.
    function setOperator(address operator, bool authorized) external onlyOwner {
        operators[operator] = authorized;
        emit OperatorUpdated(operator, authorized);
    }

    /// @notice Pauses registration while preserving public verification.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Resumes registration.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Reads a commitment without requiring authorization.
    function verifyThreat(bytes32 reportHash) external view returns (bool, address, uint64) {
        Record memory record = records[reportHash];
        return (record.exists, record.reporter, record.timestamp);
    }
}
