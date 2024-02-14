import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { Summa } from "../typechain-types";
import { BigNumber } from "ethers";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import * as fs from "fs";
import * as path from "path";

describe("Summa Contract", () => {
  function submitCommitment(
    summa: Summa,
    rangeCheckSnarkProof: string,
    cryptocurrencies = [
      {
        chain: "ETH",
        name: "ETH",
      },
      {
        chain: "BTC",
        name: "BTC",
      },
    ]
  ): any {
    return summa.submitCommitment(
      rangeCheckSnarkProof,
      cryptocurrencies,
      BigNumber.from(1693559255)
    );
  }

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

    const summa = await ethers.deployContract("Summa", [
      verifyingKey.address,
      snarkVerifier.address,
      2, // The number of cryptocurrencies in the balance polynomials
      14, // The number of bytes used to represent the balance of a cryptocurrency in the polynomials
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
    let summa: Summa;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
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

      const commitmentCalldataJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../kzg_prover/bin/commitment_solidity_calldata.json"
        ),
        "utf-8"
      );
      const commitmentCalldata: any = JSON.parse(commitmentCalldataJson);

      rangeCheckSnarkProof = commitmentCalldata.range_check_snark_proof;
    });

    it("should submit commitment for the given public input", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(submitCommitment(summa, rangeCheckSnarkProof))
        .to.emit(summa, "LiabilitiesCommitmentSubmitted")
        .withArgs(
          BigNumber.from(1693559255),
          rangeCheckSnarkProof,
          (cryptocurrencies: [Summa.CryptocurrencyStruct]) => {
            return (
              cryptocurrencies[0].chain == "ETH" &&
              cryptocurrencies[0].name == "ETH"
            );
          }
        );
    });

    it("should revert if the caller is not the owner", async () => {
      await expect(
        summa.connect(account2).submitCommitment(
          rangeCheckSnarkProof,
          [
            {
              chain: "ETH",
              name: "ETH",
            },
          ],
          BigNumber.from(1693559255)
        )
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("should revert with invalid cryptocurrencies", async () => {
      await expect(
        submitCommitment(summa, rangeCheckSnarkProof, [])
      ).to.be.revertedWith("Cryptocurrencies list cannot be empty");

      await expect(
        submitCommitment(summa, rangeCheckSnarkProof, [
          {
            chain: "BTC",
            name: "BTC",
          },
          {
            chain: "",
            name: "ETH",
          },
        ])
      ).to.be.revertedWith("Invalid cryptocurrency");

      await expect(
        submitCommitment(summa, rangeCheckSnarkProof, [
          {
            chain: "ETH",
            name: "ETH",
          },
          {
            chain: "BTC",
            name: "",
          },
        ])
      ).to.be.revertedWith("Invalid cryptocurrency");
    });

    it("should not submit invalid proof", async () => {
      await expect(submitCommitment(summa, "0x00")).to.be.revertedWith(
        "Invalid proof length"
      );
    });
  });
});
