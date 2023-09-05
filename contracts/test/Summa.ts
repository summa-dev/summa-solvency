import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { Summa } from "../typechain-types";
import { BigNumber } from "ethers";
import { defaultAbiCoder } from "ethers/lib/utils";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import * as fs from "fs";
import * as path from "path";

describe("Summa Contract", () => {
  function submitProofOfSolvency(
    summa: Summa,
    mstRoot: BigNumber,
    proof: string,
    assets = [
      {
        chain: "ETH",
        assetName: "ETH",
        amount: BigNumber.from(556863),
      },
      {
        chain: "ETH",
        assetName: "USDT",
        amount: BigNumber.from(556863),
      },
    ]
  ): any {
    return summa.submitProofOfSolvency(
      mstRoot,
      assets,
      proof,
      BigNumber.from(1693559255)
    );
  }

  function verifyInclusionProof(
    summa: Summa,
    inclusionProof: string,
    leafHash: BigNumber,
    mstRoot: BigNumber
  ): any {
    return summa.verifyInclusionProof(
      inclusionProof,
      [leafHash, mstRoot],
      1693559255
    );
  }

  async function deploySummaFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3]: SignerWithAddress[] =
      await ethers.getSigners();

    const solvencyVerifier = await ethers.deployContract(
      "src/SolvencyVerifier.sol:Verifier"
    );
    await solvencyVerifier.deployed();

    const inclusionVerifier = await ethers.deployContract(
      "src/InclusionVerifier.sol:Verifier"
    );
    await inclusionVerifier.deployed();

    const summa = await ethers.deployContract("Summa", [
      solvencyVerifier.address,
      inclusionVerifier.address,
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
          cexAddress: defaultAbiCoder.encode(["address"], [account1.address]),
          signature:
            "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
          message: message,
        },
        {
          chain: "ETH",
          cexAddress: defaultAbiCoder.encode(["address"], [account2.address]),
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
            ownedAddresses[0].cexAddress ==
              defaultAbiCoder.encode(["address"], [account1.address]) &&
            ownedAddresses[0].signature ==
              "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b" &&
            ownedAddresses[0].message == message &&
            ownedAddresses[1].chain == "ETH" &&
            ownedAddresses[1].cexAddress ==
              defaultAbiCoder.encode(["address"], [account2.address]) &&
            ownedAddresses[1].signature ==
              "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c" &&
            ownedAddresses[1].message == message
          );
        });

      let proofOfAddressOwnership0 = await summa.addressOwnershipProofs(0);
      expect(proofOfAddressOwnership0.chain).to.be.equal("ETH");
      expect(proofOfAddressOwnership0.cexAddress).to.be.equal(
        defaultAbiCoder.encode(["address"], [account1.address])
      );
      expect(proofOfAddressOwnership0.signature).to.be.equal(
        "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b"
      );
      expect(proofOfAddressOwnership0.message).to.be.equal(message);
      let proofOfAddressOwnership1 = await summa.addressOwnershipProofs(1);
      expect(proofOfAddressOwnership1.chain).to.be.equal("ETH");
      expect(proofOfAddressOwnership1.cexAddress).to.be.equal(
        defaultAbiCoder.encode(["address"], [account2.address])
      );
      expect(proofOfAddressOwnership1.signature).to.be.equal(
        "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c"
      );
      expect(proofOfAddressOwnership1.message).to.be.equal(message);
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
  });

  describe("verify proof of solvency", () => {
    let mstRoot: BigNumber;
    let summa: Summa;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
    let proof: string;
    //let ethAccount3;
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

      ownedAddresses = [
        {
          chain: "ETH",
          cexAddress: defaultAbiCoder.encode(["address"], [account1.address]),
          signature:
            "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
          message: message,
        },
        {
          chain: "ETH",
          cexAddress: defaultAbiCoder.encode(["address"], [account2.address]),
          signature:
            "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
          message: message,
        },
      ];

      const jsonData = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../zk_prover/examples/solvency_proof_solidity_calldata.json"
        ),
        "utf-8"
      );
      const calldata: any = JSON.parse(jsonData);

      mstRoot = calldata.public_inputs[0];
      proof = calldata.proof;
    });

    it("should verify the proof of solvency for the given public input", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(submitProofOfSolvency(summa, mstRoot, proof))
        .to.emit(summa, "SolvencyProofSubmitted")
        .withArgs(
          BigNumber.from(1693559255),
          mstRoot,
          (assets: Summa.AssetStruct[]) => {
            return (
              assets[0].chain == "ETH" &&
              assets[0].assetName == "ETH" &&
              BigNumber.from(556863).eq(assets[0].amount as BigNumber) &&
              assets[1].chain == "ETH" &&
              assets[1].assetName == "USDT" &&
              BigNumber.from(556863).eq(assets[1].amount as BigNumber)
            );
          }
        );
    });

    it("should revert if the caller is not the owner", async () => {
      await expect(
        summa.connect(account2).submitProofOfSolvency(
          mstRoot,
          [
            {
              chain: "ETH",
              assetName: "ETH",
              amount: BigNumber.from(556863),
            },
            {
              chain: "ETH",
              assetName: "USDT",
              amount: BigNumber.from(556863),
            },
          ],
          proof,
          BigNumber.from(1693559255)
        )
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("should not verify the proof of solvency if the CEX hasn't proven the address ownership", async () => {
      await expect(
        submitProofOfSolvency(summa, mstRoot, proof)
      ).to.be.revertedWith(
        "The CEX has not submitted any address ownership proofs"
      );
    });

    it("should revert with invalid MST root", async () => {
      mstRoot = BigNumber.from(0);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        submitProofOfSolvency(summa, mstRoot, proof)
      ).to.be.revertedWith("Invalid ZK proof");
    });

    it("should revert with invalid assets", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        submitProofOfSolvency(summa, mstRoot, proof, [
          {
            chain: "",
            assetName: "ETH",
            amount: BigNumber.from(556863),
          },
        ])
      ).to.be.revertedWith("Invalid asset");

      await expect(
        submitProofOfSolvency(summa, mstRoot, proof, [
          {
            chain: "ETH",
            assetName: "",
            amount: BigNumber.from(556863),
          },
        ])
      ).to.be.revertedWith("Invalid asset");
    });

    it("should revert with invalid proof", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);

      proof = proof.replace("1", "2");

      await expect(
        submitProofOfSolvency(summa, mstRoot, proof)
      ).to.be.revertedWith("Invalid ZK proof");

      proof = "0x000000";

      await expect(
        submitProofOfSolvency(summa, mstRoot, proof)
      ).to.be.revertedWithoutReason();
    });
  });

  describe("verify proof of inclusion", () => {
    let mstRoot: BigNumber;
    let leafHash: BigNumber;
    let summa: Summa;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
    let inclusionProof: string;
    let solvencyProof: string;
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

      ownedAddresses = [
        {
          chain: "ETH",
          cexAddress: defaultAbiCoder.encode(["address"], [account1.address]),
          signature:
            "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
          message: message,
        },
        {
          chain: "ETH",
          cexAddress: defaultAbiCoder.encode(["address"], [account2.address]),
          signature:
            "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
          message: message,
        },
      ];

      const solvencyJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../zk_prover/examples/solvency_proof_solidity_calldata.json"
        ),
        "utf-8"
      );
      const solvencyCalldata: any = JSON.parse(solvencyJson);

      mstRoot = solvencyCalldata.public_inputs[0];
      solvencyProof = solvencyCalldata.proof;

      const inclusionJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../zk_prover/examples/inclusion_proof_solidity_calldata.json"
        ),
        "utf-8"
      );
      const inclusionCalldata: any = JSON.parse(inclusionJson);

      leafHash = inclusionCalldata.public_inputs[0];
      mstRoot = inclusionCalldata.public_inputs[1];
      inclusionProof = inclusionCalldata.proof;
    });

    it("should verify the proof of inclusion for the given public input", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitProofOfSolvency(summa, mstRoot, solvencyProof);
      expect(
        await verifyInclusionProof(summa, inclusionProof, leafHash, mstRoot)
      ).to.be.equal(true);
    });

    it("should not verify with invalid MST root", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitProofOfSolvency(summa, mstRoot, solvencyProof);
      mstRoot = BigNumber.from(0);
      await expect(
        verifyInclusionProof(summa, inclusionProof, leafHash, mstRoot)
      ).to.be.revertedWith("Invalid MST root");
    });

    it("should not verify if the MST root lookup by timestamp returns an incorrect MST root", async () => {
      // The lookup will return a zero MST root as no MST root has been stored yet
      await expect(
        verifyInclusionProof(summa, inclusionProof, leafHash, mstRoot)
      ).to.be.revertedWith("Invalid MST root");
    });

    it("should not verify with invalid leaf", async () => {
      leafHash = BigNumber.from(0);

      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitProofOfSolvency(summa, mstRoot, solvencyProof);
      expect(
        await verifyInclusionProof(summa, inclusionProof, leafHash, mstRoot)
      ).to.be.equal(false);
    });

    it("should not verify with invalid proof", async () => {
      inclusionProof = inclusionProof.replace("1", "2");

      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitProofOfSolvency(summa, mstRoot, solvencyProof);
      expect(
        await verifyInclusionProof(summa, inclusionProof, leafHash, mstRoot)
      ).to.be.equal(false);
    });
  });
});
