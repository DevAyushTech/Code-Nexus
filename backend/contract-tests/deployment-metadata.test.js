const fs = require("fs");
const os = require("os");
const path = require("path");
const { expect } = require("chai");
const {
  assertDeploymentMetadataDoesNotExist,
  writeDeploymentMetadataAtomic
} = require("../scripts/deploy-sepolia");

describe("Sepolia deployment metadata", function () {
  let directory;

  beforeEach(function () {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-deployment-"));
  });

  afterEach(function () {
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("aborts when deployment metadata already exists", function () {
    const destination = path.join(directory, "deployments", "sepolia.json");
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, "existing\n");

    expect(() => assertDeploymentMetadataDoesNotExist(destination))
      .to.throw("refusing to overwrite it");
    expect(fs.readFileSync(destination, "utf8")).to.equal("existing\n");
  });

  it("permits metadata writing when the destination is missing", function () {
    const destination = path.join(directory, "deployments", "sepolia.json");
    const metadata = { network: "sepolia", chainId: 11155111 };

    writeDeploymentMetadataAtomic(destination, metadata);

    expect(JSON.parse(fs.readFileSync(destination, "utf8"))).to.deep.equal(metadata);
  });

  it("writes through a temporary file before renaming atomically", function () {
    const destination = path.join(directory, "deployments", "sepolia.json");
    const metadata = { network: "sepolia", chainId: 11155111 };
    const originalRename = fs.renameSync;
    let observedTemporary;

    fs.renameSync = (temporary, finalPath) => {
      observedTemporary = temporary;
      expect(finalPath).to.equal(destination);
      expect(fs.existsSync(temporary)).to.equal(true);
      expect(fs.existsSync(destination)).to.equal(false);
      originalRename(temporary, finalPath);
    };
    try {
      writeDeploymentMetadataAtomic(destination, metadata);
    } finally {
      fs.renameSync = originalRename;
    }

    expect(observedTemporary).to.be.a("string");
    expect(fs.existsSync(destination)).to.equal(true);
    expect(fs.existsSync(observedTemporary)).to.equal(false);
  });

  it("cleans up temporary metadata when the final rename fails", function () {
    const destination = path.join(directory, "deployments", "sepolia.json");
    const originalRename = fs.renameSync;
    let observedTemporary;

    fs.renameSync = (temporary) => {
      observedTemporary = temporary;
      throw new Error("simulated rename failure");
    };
    try {
      expect(() => writeDeploymentMetadataAtomic(destination, { network: "sepolia" }))
        .to.throw("simulated rename failure");
    } finally {
      fs.renameSync = originalRename;
    }

    expect(fs.existsSync(destination)).to.equal(false);
    expect(fs.existsSync(observedTemporary)).to.equal(false);
  });
});
