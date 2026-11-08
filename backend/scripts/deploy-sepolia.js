const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

const SEPOLIA_CHAIN_ID = 11155111;
const DEPLOYMENT_METADATA_PATH = path.join(__dirname, "..", "deployments", "sepolia.json");

function assertDeploymentMetadataDoesNotExist(destination) {
  if (fs.existsSync(destination)) {
    throw new Error(`Deployment metadata already exists at ${destination}; refusing to overwrite it.`);
  }
}

function writeDeploymentMetadataAtomic(destination, metadata) {
  const directory = path.dirname(destination);
  const temporary = path.join(
    directory,
    `.${path.basename(destination)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`
  );
  const contents = JSON.stringify(metadata, null, 2) + "\n";

  fs.mkdirSync(directory, { recursive: true });
  assertDeploymentMetadataDoesNotExist(destination);
  try {
    fs.writeFileSync(temporary, contents, { encoding: "utf8", flag: "wx" });
    fs.renameSync(temporary, destination);
  } finally {
    if (fs.existsSync(temporary)) {
      fs.unlinkSync(temporary);
    }
  }
}

async function main() {
  assertDeploymentMetadataDoesNotExist(DEPLOYMENT_METADATA_PATH);
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
  writeDeploymentMetadataAtomic(DEPLOYMENT_METADATA_PATH, metadata);
  console.log(`ThreatRegistry deployed at ${address}.`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  assertDeploymentMetadataDoesNotExist,
  writeDeploymentMetadataAtomic
};
