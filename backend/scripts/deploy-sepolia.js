const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

const SEPOLIA_CHAIN_ID = 11155111;

async function main() {
  if (process.env.BLOCKCHAIN_MODE !== "sepolia") {
    throw new Error("Deployment requires BLOCKCHAIN_MODE=sepolia.");
  }
  if (!process.env.BLOCKCHAIN_CONTRACT_OWNER || !process.env.BLOCKCHAIN_ACCOUNT_ADDRESS) {
    throw new Error("Set BLOCKCHAIN_CONTRACT_OWNER and BLOCKCHAIN_ACCOUNT_ADDRESS before deployment.");
  }
  const network = await hre.ethers.provider.getNetwork();
  if (Number(network.chainId) !== SEPOLIA_CHAIN_ID) {
    throw new Error("Refusing deployment: provider is not Sepolia.");
  }
  const [deployer] = await hre.ethers.getSigners();
  const deployerAddress = await deployer.getAddress();
  if (deployerAddress.toLowerCase() !== process.env.BLOCKCHAIN_ACCOUNT_ADDRESS.toLowerCase()) {
    throw new Error("Configured account does not match the deployment signer.");
  }
  const Factory = await hre.ethers.getContractFactory("ThreatRegistry");
  const contract = await Factory.deploy(process.env.BLOCKCHAIN_CONTRACT_OWNER, process.env.BLOCKCHAIN_ACCOUNT_ADDRESS);
  const deploymentTx = contract.deploymentTransaction();
  if (!deploymentTx) {
    throw new Error("Deployment transaction was not created.");
  }
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  const metadata = {
    contract: "ThreatRegistry",
    schemaVersion: 1,
    network: "sepolia",
    chainId: SEPOLIA_CHAIN_ID,
    address,
    deployer: deployerAddress,
    deploymentTransaction: deploymentTx.hash
  };
  const destination = path.join(__dirname, "..", "deployments", "sepolia.json");
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, JSON.stringify(metadata, null, 2) + "\n");
  console.log(`ThreatRegistry deployed at ${address}.`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
