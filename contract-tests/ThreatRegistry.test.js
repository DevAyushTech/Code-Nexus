const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry", function () {
  async function deployed() {
    const [owner, operator, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("ThreatRegistry");
    const registry = await Factory.deploy(owner.address, operator.address);
    await registry.waitForDeployment();
    return { registry, owner, operator, other };
  }

  it("allows an authorized operator to register and publicly verify", async function () {
    const { registry, operator } = await deployed();
    const hash = ethers.keccak256(ethers.toUtf8Bytes("nexus-test-1"));
    await expect(registry.connect(operator).registerThreat(hash))
      .to.emit(registry, "ThreatRegistered")
      .withArgs(hash, operator.address, anyValue);
    const record = await registry.verifyThreat(hash);
    expect(record[0]).to.equal(true);
    expect(record[1]).to.equal(operator.address);
  });

  it("rejects unauthorized, zero, and duplicate registrations", async function () {
    const { registry, operator, other } = await deployed();
    const hash = ethers.keccak256(ethers.toUtf8Bytes("nexus-test-2"));
    await expect(registry.connect(other).registerThreat(hash)).to.be.revertedWithCustomError(registry, "NotOperator");
    await expect(registry.connect(operator).registerThreat(ethers.ZeroHash)).to.be.revertedWithCustomError(registry, "EmptyHash");
    await registry.connect(operator).registerThreat(hash);
    await expect(registry.connect(operator).registerThreat(hash)).to.be.revertedWithCustomError(registry, "AlreadyRegistered");
  });

  it("allows the owner to manage operators and pause registration", async function () {
    const { registry, owner, operator, other } = await deployed();
    const hash = ethers.keccak256(ethers.toUtf8Bytes("nexus-test-3"));
    await registry.connect(owner).pause();
    await expect(registry.connect(operator).registerThreat(hash)).to.be.revertedWithCustomError(registry, "EnforcedPause");
    await registry.connect(owner).unpause();
    await registry.connect(owner).setOperator(other.address, true);
    await expect(registry.connect(other).registerThreat(hash)).to.emit(registry, "ThreatRegistered");
  });
});

const anyValue = require("@nomicfoundation/hardhat-chai-matchers/withArgs").anyValue;
