const fs = require("fs");
const path = require("path");

const source = path.join(__dirname, "..", "artifacts", "contracts", "ThreatRegistry.sol", "ThreatRegistry.json");
const destination = path.join(__dirname, "..", "contracts", "abi", "ThreatRegistry.v1.json");

if (!fs.existsSync(source)) {
  throw new Error("Compile the contract before exporting its ABI.");
}

const artifact = JSON.parse(fs.readFileSync(source, "utf8"));
fs.mkdirSync(path.dirname(destination), { recursive: true });
fs.writeFileSync(destination, JSON.stringify({
  contract: "ThreatRegistry",
  schemaVersion: 1,
  compiler: "0.8.24",
  abi: artifact.abi
}, null, 2) + "\n");
console.log("Exported versioned ABI metadata.");
