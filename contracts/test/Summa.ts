import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { Summa, Halo2VerifyingKey, Verifier, GrandsumVerifier, InclusionVerifier } from "../typechain-types";
import { BigNumber } from "ethers";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import * as fs from "fs";
import * as path from "path";

describe("Summa Contract", () => {
  async function deploySummaFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3]: SignerWithAddress[] =
      await ethers.getSigners();

    const verifyingKey = await ethers.deployContract(
      "src/VerifyingKey.sol:Halo2VerifyingKey"
    );
    await verifyingKey.deployed();

    const snarkVerifier = await ethers.deployContract(
      "src/SnarkVerifier.sol:Verifier"
    );
    await snarkVerifier.deployed();

    const grandsumVerifier = await ethers.deployContract(
      "src/GrandsumVerifier.sol:GrandsumVerifier"
    ) as GrandsumVerifier;
    await grandsumVerifier.deployed();

    const inclusionVerifier = await ethers.deployContract(
      "src/InclusionVerifier.sol:InclusionVerifier"
    ) as InclusionVerifier;
    await inclusionVerifier.deployed();

    const summa = await ethers.deployContract("Summa", [
      verifyingKey.address,
      snarkVerifier.address,
      grandsumVerifier.address,
      inclusionVerifier.address,
      ["ETH", "BTC"],
      ["ETH", "BTC"],
      8, // The number of bytes used to represent the balance of a cryptocurrency in the polynomials
    ]);
    await summa.deployed();

    return {
      summa: summa as Summa,
      owner,
      addr1,
      addr2,
      addr3,
    };
  }

  describe("deployment tests", () => {
    let verifyingKey: Halo2VerifyingKey;
    let snarkVerifier: Verifier;
    let grandsumVerifier: GrandsumVerifier;
    let inclusionVerifier: InclusionVerifier;

    beforeEach(async () => {
      // Deploy the verifying key and verifiers
      verifyingKey = await ethers.deployContract(
        "src/VerifyingKey.sol:Halo2VerifyingKey"
      ) as Halo2VerifyingKey;
      await verifyingKey.deployed();

      snarkVerifier = await ethers.deployContract(
        "src/SnarkVerifier.sol:Verifier"
      ) as Verifier;
      await snarkVerifier.deployed();

      grandsumVerifier = await ethers.deployContract(
        "src/GrandsumVerifier.sol:GrandsumVerifier"
      ) as GrandsumVerifier;
      await grandsumVerifier.deployed();

      inclusionVerifier = await ethers.deployContract(
        "src/InclusionVerifier.sol:InclusionVerifier"
      ) as InclusionVerifier;
      await inclusionVerifier.deployed();
    });

    it("should not deploy with invalid currencies", async () => {
      await expect(
        ethers.deployContract("Summa", [
          verifyingKey.address,
          snarkVerifier.address,
          grandsumVerifier.address,
          inclusionVerifier.address,
          ["", "BTC"],
          ["ETH", "BTC"],
          8,
        ])
      ).to.be.revertedWith("Invalid cryptocurrency");

      await expect(
        ethers.deployContract("Summa", [
          verifyingKey.address,
          snarkVerifier.address,
          grandsumVerifier.address,
          inclusionVerifier.address,
          ["ETH", "BTC"],
          ["ETH", ""],
          8,
        ])
      ).to.be.revertedWith("Invalid cryptocurrency");

      await expect(
        ethers.deployContract("Summa", [
          verifyingKey.address,
          snarkVerifier.address,
          grandsumVerifier.address,
          inclusionVerifier.address,
          [],
          ["ETH", ""],
          8,
        ])
      ).to.be.revertedWith("Cryptocurrency names and chains number mismatch");
    });

    it("should not deploy with invalid byte range", async () => {
      await expect(
        ethers.deployContract("Summa", [
          verifyingKey.address,
          snarkVerifier.address,
          grandsumVerifier.address,
          inclusionVerifier.address,
          ["ETH", "BTC"],
          ["ETH", "BTC"],
          0, // Invalid byte range
        ])
      ).to.be.revertedWith(
        "The config parameters do not correspond to the verifying key"
      );
    });

    it("should not deploy with invalid verification key", async () => {
      await expect(
        ethers.deployContract("Summa", [
          ethers.constants.AddressZero,
          snarkVerifier.address,
          grandsumVerifier.address,
          inclusionVerifier.address,
          ["ETH", "BTC"],
          ["ETH", "BTC"],
          8,
        ])
      ).to.be.revertedWith("Invalid verifying key address");
    });

    it("should not deploy with invalid snark verifier", async () => {
      const verifyingKey = await ethers.deployContract(
        "src/VerifyingKey.sol:Halo2VerifyingKey"
      );
      await verifyingKey.deployed();
      await expect(
        ethers.deployContract("Summa", [
          verifyingKey.address,
          ethers.constants.AddressZero,
          grandsumVerifier.address,
          inclusionVerifier.address,
          ["ETH", "BTC"],
          ["ETH", "BTC"],
          8,
        ])
      ).to.be.revertedWith("Invalid polynomial encoding verifier address");
    });


    it("should not deploy with invalid grandsum verifier", async () => {
      const verifyingKey = await ethers.deployContract(
        "src/VerifyingKey.sol:Halo2VerifyingKey"
      );
      await verifyingKey.deployed();
      await expect(
        ethers.deployContract("Summa", [
          verifyingKey.address,
          snarkVerifier.address,
          ethers.constants.AddressZero,
          inclusionVerifier.address,
          ["ETH", "BTC"],
          ["ETH", "BTC"],
          8,
        ])
      ).to.be.revertedWith("Invalid grandsum verifier address");
    });

    it("should not deploy with invalid inclusion verifier", async () => {
      await expect(
        ethers.deployContract("Summa", [
          verifyingKey.address,
          snarkVerifier.address,
          grandsumVerifier.address,
          ethers.constants.AddressZero,
          ["ETH", "BTC"],
          ["ETH", "BTC"],
          8,
        ])
      ).to.be.revertedWith("Invalid inclusion verifier address");
    });

    it("should not deploy if the number of cryptocurrencies is not matching the verification key ", async () => {
      const dummyVerifyingKey = await ethers.deployContract(
        "src/DummyVerifyingKey.sol:Halo2VerifyingKey"
      );
      await dummyVerifyingKey.deployed();

      await expect(
        ethers.deployContract("Summa", [
          dummyVerifyingKey.address,
          snarkVerifier.address,
          grandsumVerifier.address,
          ethers.constants.AddressZero,
          ["ETH", "BTC"],
          ["ETH", "BTC"],
          8,
        ])
      ).to.be.revertedWith(
        "The config parameters do not correspond to the verifying key"
      );
    });
  });

  describe("verify address ownership", () => {
    let summa: Summa;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
    let account3: SignerWithAddress;
    let ownedAddresses: Summa.AddressOwnershipProofStruct[];
    const message = ethers.utils.defaultAbiCoder.encode(
      ["string"],
      ["Summa proof of solvency for CryptoExchange"]
    );

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deploySummaFixture);
      summa = deploymentInfo.summa as Summa;
      account1 = deploymentInfo.addr1;
      account2 = deploymentInfo.addr2;
      account3 = deploymentInfo.addr3;

      //Reference signing procedure for ETH:
      // const message = ethers.utils.defaultAbiCoder.encode(
      //   ["string"],
      //   ["Summa proof of solvency for CryptoExchange"]
      // );
      // const hashedMessage = ethers.utils.solidityKeccak256(
      //   ["bytes"],
      //   [message]
      // );
      // const signature = await deploymentInfo.addr3.signMessage(
      //   ethers.utils.arrayify(hashedMessage)
      // );
      // console.log("signature", signature);

      ownedAddresses = [
        {
          chain: "ETH",
          cexAddress: account1.address.toString(),
          signature:
            "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
          message: message,
        },
        {
          chain: "ETH",
          cexAddress: account2.address.toString(),
          signature:
            "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
          message: message,
        },
      ];
    });

    it("should verify the address ownership and store the addresses", async () => {
      await expect(summa.submitProofOfAddressOwnership(ownedAddresses))
        .to.emit(summa, "AddressOwnershipProofSubmitted")
        .withArgs((ownedAddresses: any) => {
          return (
            ownedAddresses[0].chain == "ETH" &&
            ownedAddresses[0].cexAddress == account1.address &&
            ownedAddresses[0].signature ==
            "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b" &&
            ownedAddresses[0].message == message &&
            ownedAddresses[1].chain == "ETH" &&
            ownedAddresses[1].cexAddress == account2.address &&
            ownedAddresses[1].signature ==
            "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c" &&
            ownedAddresses[1].message == message
          );
        });

      const addr1Hash = ethers.utils.solidityKeccak256(
        ["string"],
        [account1.address]
      );
      let proofOfAddressOwnership1 = await summa.getAddressOwnershipProof(
        addr1Hash
      );
      expect(proofOfAddressOwnership1.chain).to.be.equal("ETH");
      expect(proofOfAddressOwnership1.cexAddress).to.be.equal(account1.address);
      expect(proofOfAddressOwnership1.signature).to.be.equal(
        "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b"
      );
      expect(proofOfAddressOwnership1.message).to.be.equal(message);
      const addr2Hash = ethers.utils.solidityKeccak256(
        ["string"],
        [account2.address]
      );
      let proofOfAddressOwnership2 = await summa.getAddressOwnershipProof(
        addr2Hash
      );
      expect(proofOfAddressOwnership2.chain).to.be.equal("ETH");
      expect(proofOfAddressOwnership2.cexAddress).to.be.equal(account2.address);
      expect(proofOfAddressOwnership2.signature).to.be.equal(
        "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c"
      );
      expect(proofOfAddressOwnership2.message).to.be.equal(message);
    });

    it("should revert if the caller is not the owner", async () => {
      await expect(
        summa.connect(account3).submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("should revert if the address ownership has already been verified", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Address already verified");
    });

    it("should revert if the proof of address ownership has invalid address", async () => {
      ownedAddresses[0].cexAddress = "";
      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Invalid proof of address ownership");
    });

    it("should revert if the proof of address ownership has invalid chain type", async () => {
      ownedAddresses[0].chain = "";
      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Invalid proof of address ownership");
    });

    it("should revert if the proof of address ownership has invalid signature", async () => {
      ownedAddresses[0].signature = ethers.utils.toUtf8Bytes("");
      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Invalid proof of address ownership");
    });

    it("should revert if the proof of address ownership has invalid message", async () => {
      ownedAddresses[0].message = ethers.utils.toUtf8Bytes("");
      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Invalid proof of address ownership");
    });

    it("should revert if requesting proof for unverified address", async () => {
      const addr1Hash = ethers.utils.solidityKeccak256(
        ["string"],
        [account1.address]
      );
      await expect(
        summa.getAddressOwnershipProof(addr1Hash)
      ).to.be.revertedWith("Address not verified");
    });
  });

  describe("submit commitment", () => {
    let rangeCheckSnarkProof: string;
    let grandsumProof: string;
    let totalBalances: BigNumber[];
    let summa: Summa;

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deploySummaFixture);
      summa = deploymentInfo.summa as Summa;

      const commitmentCalldataJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../kzg_prover/bin/commitment_solidity_calldata.json"
        ),
        "utf-8"
      );
      const commitmentCalldata: any = JSON.parse(commitmentCalldataJson);

      rangeCheckSnarkProof = commitmentCalldata.range_check_snark_proof;
      grandsumProof = commitmentCalldata.grand_sums_batch_proof;
      totalBalances = commitmentCalldata.total_balances;
    });

    it("should submit a valid commitment", async () => {
      let expect_commitment_on_contract = "0x" + rangeCheckSnarkProof.slice(130, grandsumProof.length + 128);
      expect(await summa.commitments(1)).to.be.equal("0x");
      await summa.submitCommitment(rangeCheckSnarkProof, grandsumProof, totalBalances, 1);
      expect(await summa.commitments(1)).to.be.equal(expect_commitment_on_contract);
    });

    it("should reject submit an invalid total balances", async () => {
      await expect(
        summa.submitCommitment(rangeCheckSnarkProof, grandsumProof, [], 1)
      ).to.be.revertedWith("Invalid total balances length");
    });

    it("should reject submit when grandsum proof length mismatches with total balances", async () => {

      let wrong_total_balance = totalBalances.slice(0, totalBalances.length - 1);
      await expect(
        summa.submitCommitment(rangeCheckSnarkProof, grandsumProof, wrong_total_balance, 1)
      ).to.be.revertedWith("Invalid grandsum proof length");

      let wrong_grandsum_proof = grandsumProof.slice(0, grandsumProof.length - 64);
      await expect(
        summa.submitCommitment(rangeCheckSnarkProof, wrong_grandsum_proof, totalBalances, 1)
      ).to.be.revertedWith("Invalid grandsum proof length");
    });

    it("should reject submit when snark proof length less than grandsum proof", async () => {
      let wrong_range_check_snark_proof = rangeCheckSnarkProof.slice(0, grandsumProof.length - 64);
      await expect(
        summa.submitCommitment(wrong_range_check_snark_proof, grandsumProof, totalBalances, 1)
      ).to.be.revertedWith("Invalid snark proof length");
    });

    it("should reject submit an invalid snark proof", async () => {
      let wrong_range_check_snark_proof = rangeCheckSnarkProof.replace("1", "2");
      await expect(
        summa.submitCommitment(wrong_range_check_snark_proof, grandsumProof, totalBalances, 1)
      ).to.be.reverted;
    });
  });

  describe("verify inclusion proof", () => {
    let rangeCheckSnarkProof: string;
    let inclusionProof: string;
    let challenges: BigNumber[];
    let values: BigNumber[];
    let summa: Summa;

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deploySummaFixture);
      summa = deploymentInfo.summa as Summa;

      const commitmentCalldataJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../kzg_prover/bin/commitment_solidity_calldata.json"
        ),
        "utf-8"
      );
      const commitmentCalldata: any = JSON.parse(commitmentCalldataJson);

      rangeCheckSnarkProof = commitmentCalldata.range_check_snark_proof;

      const inclusionCalldataJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../kzg_prover/bin/inclusion_proof_solidity_calldata.json"
        ),
        "utf-8"
      );
      const inclusionCalldata: any = JSON.parse(inclusionCalldataJson);
      inclusionProof = inclusionCalldata.proof;
      challenges = inclusionCalldata.challenges;
      values = inclusionCalldata.user_values;
    });

    // Testing verifyInclusionProof function
    it("should verify inclusion proof with `verifyInclusionProof` function", async () => {
      let proofArray = ethers.utils.arrayify(inclusionProof);
      let snarkProofarray = ethers.utils.arrayify(rangeCheckSnarkProof).slice(0, proofArray.length);
      let proof = ethers.utils.concat([proofArray, snarkProofarray]);

      expect(await summa.verifyInclusionProof(proof, challenges, values)).to.be.true;
    });

    it("should reject invalid inclusion proof", async () => {
      let proofArray = ethers.utils.arrayify(inclusionProof);
      let snarkProofarray = ethers.utils.arrayify(rangeCheckSnarkProof).slice(0, proofArray.length);
      let wrongProof = ethers.utils.concat([snarkProofarray, snarkProofarray]);

      // This is an issue with https://github.com/NomicFoundation/hardhat/issues/3446
      await expect(summa.verifyInclusionProof(wrongProof, challenges, values)).to.be.reverted;
    });

    it("should reject verifying inclusion proof length mismatches with values length", async () => {
      let proofArray = ethers.utils.arrayify(inclusionProof);
      let snarkProofarray = ethers.utils.arrayify(rangeCheckSnarkProof).slice(0, proofArray.length - 1);
      let wrongProof = ethers.utils.concat([proofArray, snarkProofarray]);

      await expect(summa.verifyInclusionProof(wrongProof, challenges, values)).to.be.revertedWith("Invalid inclusion proof length");
      await expect(summa.verifyInclusionProof(wrongProof, challenges, values.slice(0, values.length - 1))).to.be.revertedWith("Invalid inclusion proof length");
    });

    it("should reject verifying inclusion proof with wrong challenge points", async () => {
      let proofArray = ethers.utils.arrayify(inclusionProof);
      let snarkProofarray = ethers.utils.arrayify(rangeCheckSnarkProof).slice(0, proofArray.length);
      let proof = ethers.utils.concat([proofArray, snarkProofarray]);

      await expect(summa.verifyInclusionProof(proof, challenges.slice(0, challenges.length - 1), values)).to.be.revertedWith("Invalid challenges length");
    });
  });
});
