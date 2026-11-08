const fs = require("fs");
const path = require("path");

const file = path.join(__dirname, "..", "deployments", "sepolia.json");
if (!fs.existsSync(file)) {
  throw new Error("No Sepolia deployment metadata found.");
}

const metadata = JSON.parse(fs.readFileSync(file, "utf8"));
if (metadata.network !== "sepolia" || metadata.chainId !== 11155111 || !metadata.address || !metadata.deploymentTransaction) {
  throw new Error("Deployment metadata is incomplete or not Sepolia.");
}
console.log(JSON.stringify({
  contract: metadata.contract,
  network: metadata.network,
  chainId: metadata.chainId,
  address: metadata.address,
  deploymentTransaction: metadata.deploymentTransaction
}, null, 2));
