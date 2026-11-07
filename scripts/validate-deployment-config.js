const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const PRIVATE_KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/;

if (process.env.BLOCKCHAIN_MODE !== "sepolia") {
  throw new Error("Set BLOCKCHAIN_MODE=sepolia for deployment configuration validation.");
}
if (process.env.BLOCKCHAIN_CHAIN_ID !== "11155111") {
  throw new Error("BLOCKCHAIN_CHAIN_ID must be exactly 11155111.");
}
if (!process.env.BLOCKCHAIN_RPC_URL || process.env.BLOCKCHAIN_RPC_URL.toLowerCase().includes("mainnet")) {
  throw new Error("A non-mainnet Sepolia RPC URL is required.");
}
if (!process.env.BLOCKCHAIN_PRIVATE_KEY || !PRIVATE_KEY_PATTERN.test(process.env.BLOCKCHAIN_PRIVATE_KEY)) {
  throw new Error("A valid private key format is required.");
}
for (const name of ["BLOCKCHAIN_ACCOUNT_ADDRESS", "BLOCKCHAIN_CONTRACT_OWNER"]) {
  if (!process.env[name] || !ADDRESS_PATTERN.test(process.env[name])) {
    throw new Error(`${name} must be a valid Ethereum address.`);
  }
}
console.log("Sepolia deployment configuration shape is valid; no RPC connection was made.");
