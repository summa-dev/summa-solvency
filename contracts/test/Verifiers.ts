import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { Verifier as SnarkVerifier, InclusionVerifier, GrandSumVerifier, Halo2VerifyingKey } from "../typechain-types";
import { BigNumber, providers } from "ethers";
import { Bytes, BytesLike, defaultAbiCoder, isBytesLike } from "ethers/lib/utils";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import * as fs from "fs";
import * as path from "path";

describe("Verifier Contracts", () => {
  async function deployBN256G2() {
    const bn256g2 = await ethers.getContractFactory("BN256G2");
    const bn256g2Instance = await bn256g2.deploy();
    return bn256g2Instance;
  }

  async function deployVerifyingFixture() {
    // Contracts are deployed using the first signer/account by default
    const verifyingKey = await ethers.deployContract(
      "src/verifying_key.sol:Halo2VerifyingKey",
    ) as Halo2VerifyingKey;

    const commitmentJson = fs.readFileSync(path.resolve(__dirname, "../../kzg_prover/bin/commitment_solidity_calldata.json"), "utf-8");
    const commitmentCalldata = JSON.parse(commitmentJson);

    return {
      verifyingKey,
      commitmentCalldata,
    };
  }

  describe("BN256G2 operation test", () => {
    it("should test addition", async () => {
      const bn256g2 = await deployBN256G2();
      let res = await bn256g2.ECTwistAdd(BigNumber.from("0x010acd800ef6f6752c7fd63efd27310fbbc0cddeafd19df13772b0162dd60198"),
        BigNumber.from("0x11fb65fc8359f0a2fbc2076b919b10cd6a0259be9b982c77749f6612bd84f619"),
        BigNumber.from("0x1842bf644523eb1b63e72b333290bdd8e71b61217d423d03e76035f5672dca3b"),
        BigNumber.from("0x248e3efe73cd2286e12e6649a4e3a6557d6ddb21dab6cdeb6af71e83e54f5c39"),
        BigNumber.from("0x0d76cdeac516681d6ee49f97ea2449a332da02f2932820e780672d858c0b9e67"),
        BigNumber.from("0x23cf199ce510a7bd88d1a36d01d27a5d20877a089257cee26e9e3da130e08a56"),
        BigNumber.from("0x1e2d1cb11f0c832929d64e7e2d9497344a5756f5ee4144186b7384c5babeb2d4"),
        BigNumber.from("0x2e01ba57b5e27d864f0b161e9fb642373bc2a0cb009114a504fe87ce46d2362e"));

      expect(res[0]).to.be.equal(BigNumber.from("0x123aeb5d388385c95f621887198c49ce360be39e202f1e5b2cb716fb16a2947e"));
      expect(res[1]).to.be.equal(BigNumber.from("0x187aabbe9dbc6b188789e8063c6848253365b628774cadfa2f5499c389bc720d"));
      expect(res[2]).to.be.equal(BigNumber.from("0xe1d1cc06f98a2603ed2b548b4776241a444b38bc3066023cdb27fe567849116"));
      expect(res[3]).to.be.equal(BigNumber.from("0x1671331a9c903755d2517f0f98e8fbf84b025ab5e50b89866974556ff86827f2"));
    });
    it("should test multiplication", async () => {
      const bn256g2 = await deployBN256G2();

      let res = await bn256g2.ECTwistMul(
        BigNumber.from("0x08b88ebb6b6820ebe287214692ad2b2aed666a4b0c6375a73a63c16264d1bf64"),
        BigNumber.from("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        BigNumber.from("0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
        BigNumber.from("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"),
        BigNumber.from("0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"));

      expect(res[0]).to.be.equal(BigNumber.from("0x010acd800ef6f6752c7fd63efd27310fbbc0cddeafd19df13772b0162dd60198"));
      expect(res[1]).to.be.equal(BigNumber.from("0x11fb65fc8359f0a2fbc2076b919b10cd6a0259be9b982c77749f6612bd84f619"));
      expect(res[2]).to.be.equal(BigNumber.from("0x1842bf644523eb1b63e72b333290bdd8e71b61217d423d03e76035f5672dca3b"));
      expect(res[3]).to.be.equal(BigNumber.from("0x248e3efe73cd2286e12e6649a4e3a6557d6ddb21dab6cdeb6af71e83e54f5c39"));
    });

  });

  describe("Snark Proof Verifier", () => {
    let snarkVerifier: SnarkVerifier;
    let verifyingKey: Halo2VerifyingKey;
    let commitmentCalldata: {
      range_check_snark_proof: BytesLike;
      grand_sums_batch_proof: BytesLike;
    };
    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deployVerifyingFixture);
      verifyingKey = deploymentInfo.verifyingKey;
      commitmentCalldata = deploymentInfo.commitmentCalldata;

      // Deploy SnarkVerifier contract
      snarkVerifier = await ethers.deployContract(
        "src/snark_verifier.sol:Verifier"
      ) as SnarkVerifier;

      await snarkVerifier.deployed();
    });

    it("should verify snark proof", async () => {
      // The verifier contract checks the number of instances in the VerifyingKey contract at 0x00c0 with the given 'instances' input
      expect(await snarkVerifier.verifyProof(verifyingKey.address, commitmentCalldata.range_check_snark_proof, [1])).to.be.true;
    });

    it("hould fail to verify snark proof without the number of instances", async () => {
      await expect(snarkVerifier.verifyProof(verifyingKey.address, commitmentCalldata.range_check_snark_proof, [])).to.be.reverted;
    });

  });

  describe("Grandsum Proof Verifier", () => {
    let grandSumVerifier: GrandSumVerifier;
    let verifyingKey: Halo2VerifyingKey;
    let commitmentCalldata: {
      range_check_snark_proof: BytesLike;
      grand_sums_batch_proof: BytesLike;
    };

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deployVerifyingFixture);
      verifyingKey = deploymentInfo.verifyingKey;
      commitmentCalldata = deploymentInfo.commitmentCalldata;

      // Deploy GrandSumVerifier contract
      grandSumVerifier = await ethers.deployContract(
        "src/grandsum_kzg_verifier.sol:GrandsumVerifier"
      ) as GrandSumVerifier;
    });

    it("should verify grandsum proof", async () => {
      // Concatenates the snark proof and the grand sum proof
      let snarkProofArray = ethers.utils.arrayify(commitmentCalldata.range_check_snark_proof);
      let grandSumProofArray = ethers.utils.arrayify(commitmentCalldata.grand_sums_batch_proof);

      // The first 64 bytes of the snark proof represent a commitment to the corresponding username polynomial
      // Starting from the next 64 bytes, each set of 64 bytes represents commitments corresponding to the total sum of balances
      let grandSumCommitments = snarkProofArray.slice(64, (64 + grandSumProofArray.length));

      // The verifier iterates over points in the proofs while verifying them.
      // The proofs look like:
      //  i = 0                                       1                                               N                 
      // [grand_sum_proof_p1_x, grand_sum_proof_p1_y, grand_sum_proof_p2_x, grand_sum_proof_p2_y, ... grand_sum_proof_pN_x, grand_sum_proof_pN_y, ...]
      // [    snark_proof_p1_x,     snark_proof_p1_y,     snark_proof_p2_x,     snark_proof_p2_y, ...     snark_proof_pN_x,     snark_proof_pN_y, ...] 
      //  Where `N` is the number of currencies
      let proofs = ethers.utils.hexlify(ethers.utils.concat([grandSumProofArray, grandSumCommitments]));
      
      expect(await grandSumVerifier.verifyProof(verifyingKey.address, proofs, [])).to.be.true;
    });
  });


  describe("Inclusion Proof Verifier", () => {
    let inclusionVerifier: InclusionVerifier;
    let verifyingKey: Halo2VerifyingKey;
    let inclusionProof: BytesLike;
    let commitmentCalldata: {
      range_check_snark_proof: BytesLike;
      grand_sums_batch_proof: BytesLike;
    };
    let challenge: BytesLike;
    let username: BytesLike;
    let username_biguint: BigNumber;
    let balance1: BigNumber;
    let balance2: BigNumber;

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deployVerifyingFixture);
      verifyingKey = deploymentInfo.verifyingKey;
      commitmentCalldata = deploymentInfo.commitmentCalldata;

      // InclusionVerifier requires BN256G2 contract for performing elliptic curve operations on G2 subgroup
      const bn256g2 = await deployBN256G2();
      inclusionVerifier = await ethers.deployContract(
        "src/inclusion_kzg_verifier.sol:InclusionVerifier", [bn256g2.address]
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
      challenge = inclusionCalldata.challenge;
      username_biguint = inclusionCalldata.balances[0];
      balance1 = inclusionCalldata.balances[1];
      balance2 = inclusionCalldata.balances[2];
    });

    it("should verify inclusion proof", async () => {

      // Generating proof with concatenated snark proof and inclusion proof
      let snarkProof = commitmentCalldata.range_check_snark_proof;

      // Slice the snarkProof to match the length of inclusionProof
      let proofArray = ethers.utils.arrayify(inclusionProof);
      let snarkProofarray = ethers.utils.arrayify(snarkProof).slice(0, proofArray.length);

      let combinedProof = ethers.utils.concat([proofArray, snarkProofarray]);
      let proofs = ethers.utils.hexlify(combinedProof);

      let verifiy_tx = await inclusionVerifier.populateTransaction.verifyProof(
        verifyingKey.address,
        challenge,
        proofs,
        [username_biguint, balance1, balance2]
      )

      try {

        let result = await inclusionVerifier.verifyProof(
          verifyingKey.address,
          challenge,
          proofs,
          [username_biguint, balance1, balance2]
        )
        console.log("result\n", result);
      } catch (error) {
        if (error instanceof Error) {
          // parse message data field 
          // let parsed_message = error.message.split("data:");
          console.log("error\n", error.message);
        } else {
          console.log("unparsed error\n", error);
        }
      }
    });
  });
});
