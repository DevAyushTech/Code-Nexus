require("@nomicfoundation/hardhat-ethers");
require("@nomicfoundation/hardhat-chai-matchers");
require("dotenv").config();

const SEPOLIA_CHAIN_ID = 11155111;
const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY;

if (process.env.BLOCKCHAIN_MODE === "sepolia" && (!process.env.BLOCKCHAIN_RPC_URL || !privateKey)) {
  throw new Error("Sepolia tooling requires BLOCKCHAIN_RPC_URL and BLOCKCHAIN_PRIVATE_KEY.");
}
if (process.env.BLOCKCHAIN_RPC_URL && process.env.BLOCKCHAIN_RPC_URL.toLowerCase().includes("mainnet")) {
  throw new Error("Mainnet RPC endpoints are not supported.");
}

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 }
    }
  },
  networks: {
    hardhat: {},
    sepolia: {
      chainId: SEPOLIA_CHAIN_ID,
      url: process.env.BLOCKCHAIN_RPC_URL || "http://127.0.0.1:8545",
      accounts: privateKey ? [privateKey] : []
    }
  },
  paths: {
    artifacts: "./artifacts",
    cache: "./cache",
    sources: "./contracts",
    tests: "./contract-tests"
  }
};
