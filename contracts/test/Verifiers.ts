import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { Verifier as SnarkVerifier, InclusionVerifier, GrandsumVerifier, Halo2VerifyingKey } from "../typechain-types";
import { BigNumber } from "ethers";
import { BytesLike } from "ethers/lib/utils";
import * as fs from "fs";
import * as path from "path";

describe("Verifier Contracts", () => {
  async function deployVerifyingFixture() {
    // Contracts are deployed using the first signer/account by default
    const verifyingKey = await ethers.deployContract(
      "src/VerifyingKey.sol:Halo2VerifyingKey",
    ) as Halo2VerifyingKey;

    const commitmentJson = fs.readFileSync(path.resolve(__dirname, "../../kzg_prover/bin/commitment_solidity_calldata.json"), "utf-8");
    const commitmentCalldata = JSON.parse(commitmentJson);

    return {
      verifyingKey,
      commitmentCalldata,
    };
  }


  describe("Snark Proof Verifier", () => {
    let snarkVerifier: SnarkVerifier;
    let verifyingKey: Halo2VerifyingKey;
    let commitmentCalldata: {
      range_check_snark_proof: BytesLike;
      grand_sums_batch_proof: BytesLike;
      total_balances: BigNumber[];
    };
    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deployVerifyingFixture);
      verifyingKey = deploymentInfo.verifyingKey;
      commitmentCalldata = deploymentInfo.commitmentCalldata;

      // Deploy SnarkVerifier contract
      snarkVerifier = await ethers.deployContract(
        "src/SnarkVerifier.sol:Verifier"
      ) as SnarkVerifier;

      await snarkVerifier.deployed();
    });

    it("should verify snark proof", async () => {
      // The verifier contract checks the number of instances in the VerifyingKey contract at 0x00c0 with the given 'instances' input
      expect(await snarkVerifier.verifyProof(verifyingKey.address, commitmentCalldata.range_check_snark_proof, [1])).to.be.true;
    });

    it("should fail to verify snark proof without the number of instances", async () => {
      await expect(snarkVerifier.verifyProof(verifyingKey.address, commitmentCalldata.range_check_snark_proof, [])).to.be.reverted;
    });

  });

  describe("Grandsum Proof Verifier", () => {
    let grandSumVerifier: GrandsumVerifier;
    let verifyingKey: Halo2VerifyingKey;
    let commitmentCalldata: {
      range_check_snark_proof: BytesLike;
      grand_sums_batch_proof: BytesLike;
      total_balances: BigNumber[];
    };

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deployVerifyingFixture);
      verifyingKey = deploymentInfo.verifyingKey;
      commitmentCalldata = deploymentInfo.commitmentCalldata;

      // Deploy GrandSumVerifier contract
      grandSumVerifier = await ethers.deployContract(
        "src/GrandsumVerifier.sol:GrandsumVerifier"
      ) as GrandsumVerifier;
    });

    it("should verify grandsum proof", async () => {
      // Concatenates the snark proof and the grand sum proof
      let snarkProofArray = ethers.utils.arrayify(commitmentCalldata.range_check_snark_proof);
      let grandSumProofArray = ethers.utils.arrayify(commitmentCalldata.grand_sums_batch_proof);
      let totalBalances = commitmentCalldata.total_balances;

      // The first 64 bytes of the snark proof represent a commitment to the corresponding username polynomial
      // Starting from the next 64 bytes, each set of 64 bytes represents commitments corresponding to the total sum of balances
      let grandSumCommitments = snarkProofArray.slice(64, (64 + grandSumProofArray.length));

      // The verifier iterates over points in the proofs while verifying them.
      // The proofs look like:
      //  i = 0                                       1                                               N                 
      // [grand_sum_proof_p1_x, grand_sum_proof_p1_y, grand_sum_proof_p2_x, grand_sum_proof_p2_y, ... grand_sum_proof_pN_x, grand_sum_proof_pN_y, ...]
      // [    snark_proof_p1_x,     snark_proof_p1_y,     snark_proof_p2_x,     snark_proof_p2_y, ...     snark_proof_pN_x,     snark_proof_pN_y, ...] 
      //  Where `N` is the number of currencies
      let proofs = ethers.utils.concat([grandSumProofArray, grandSumCommitments]);

      expect(await grandSumVerifier.verifyProof(verifyingKey.address, proofs, totalBalances)).to.be.not.reverted;
    });
  });


  describe("Inclusion Proof Verifier", () => {
    let inclusionVerifier: InclusionVerifier;
    let verifyingKey: Halo2VerifyingKey;
    let inclusionProof: BytesLike;
    let commitmentCalldata: {
      range_check_snark_proof: BytesLike;
      grand_sums_batch_proof: BytesLike;
      total_balances: BigNumber[];
    };
    let challenges: [BigNumber, BigNumber, BigNumber, BigNumber];
    let username: BytesLike;
    let username_biguint: BigNumber;
    let balance1: BigNumber;
    let balance2: BigNumber;

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deployVerifyingFixture);
      verifyingKey = deploymentInfo.verifyingKey;
      commitmentCalldata = deploymentInfo.commitmentCalldata;

      // InclusionVerifier requires BN256G2 contract for performing elliptic curve operations on G2 subgroup
      // const bn256g2 = await deployBN256G2();
      inclusionVerifier = await ethers.deployContract(
        "src/InclusionVerifier.sol:InclusionVerifier"
      ) as InclusionVerifier;
      await inclusionVerifier.deployed();

      verifyingKey = deploymentInfo.verifyingKey;

      const inclusionJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../kzg_prover/bin/inclusion_proof_solidity_calldata.json"
        ),
        "utf-8"
      );
      const inclusionCalldata: any = JSON.parse(inclusionJson);

      inclusionProof = inclusionCalldata.proof;
      username = inclusionCalldata.username;
      challenges = inclusionCalldata.challenges;
      username_biguint = inclusionCalldata.user_values[0];
      balance1 = inclusionCalldata.user_values[1];
      balance2 = inclusionCalldata.user_values[2];
    });

    it("should verify inclusion proof", async () => {
      // Generating proof with concatenated snark proof and inclusion proof
      let snarkProof = commitmentCalldata.range_check_snark_proof;

      // Slice the snarkProof to match the length of inclusionProof
      let proofArray = ethers.utils.arrayify(inclusionProof);
      let snarkProofarray = ethers.utils.arrayify(snarkProof).slice(0, proofArray.length);

      let proofs = ethers.utils.concat([proofArray, snarkProofarray]);

      expect(await inclusionVerifier.verifyProof(
        verifyingKey.address,
        proofs,
        [challenges[0], challenges[1], challenges[2], challenges[3]],
        [username_biguint, balance1, balance2]
      )).to.be.true;
    });

    it("should not verify inclusion proof", async () => {
      // Generating proof with concatenated snark proof and inclusion proof
      let snarkProof = commitmentCalldata.range_check_snark_proof;

      // Slice the snarkProof to match the length of inclusionProof
      let proofArray = ethers.utils.arrayify(inclusionProof);
      let snarkProofarray = ethers.utils.arrayify(snarkProof).slice(0, proofArray.length);

      let wrongProofs = ethers.utils.concat([snarkProofarray, snarkProofarray]);

      await expect(inclusionVerifier.callStatic.verifyProof(
        verifyingKey.address,
        wrongProofs,
        [challenges[0], challenges[1], challenges[2], challenges[3]],
        [username_biguint, balance1, balance2]
      )).to.be.reverted;
    });
  });
});
