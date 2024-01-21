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
  function submitCommitment(
    summa: Summa,
    mstRoot: BigNumber,
    rootBalances: BigNumber[],
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
      mstRoot,
      rootBalances,
      cryptocurrencies,
      BigNumber.from(1693559255)
    );
  }

  function verifyInclusionProof(
    summa: Summa,
    inclusionProof: string,
    leafHash: BigNumber,
    mstRoot: BigNumber,
    balance1: BigNumber,
    balance2: BigNumber
  ): any {
    return summa.verifyInclusionProof(
      inclusionProof,
      [leafHash, mstRoot, balance1, balance2],
      1693559255
    );
  }

  async function deploySummaFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3]: SignerWithAddress[] =
      await ethers.getSigners();

    const inclusionVerifier = await ethers.deployContract(
      "src/InclusionVerifier.sol:Verifier"
    );
    await inclusionVerifier.deployed();

    const summa = await ethers.deployContract("Summa", [
      inclusionVerifier.address,
      4, // The number of levels of the Merkle sum tree
      2, // The number of cryptocurrencies supported by the Merkle sum tree
      8, // The number of bytes used to represent the balance of a cryptocurrency in the Merkle sum tree
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
    let mstRoot: BigNumber;
    let rootBalances: BigNumber[];
    let summa: Summa;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
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
          "../../zk_prover/examples/commitment_solidity_calldata.json"
        ),
        "utf-8"
      );
      const commitmentCalldata: any = JSON.parse(commitmentCalldataJson);

      mstRoot = commitmentCalldata.root_hash;
      rootBalances = commitmentCalldata.root_balances;
    });

    it("should submit commitment for the given public input", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(submitCommitment(summa, mstRoot, rootBalances))
        .to.emit(summa, "LiabilitiesCommitmentSubmitted")
        .withArgs(
          BigNumber.from(1693559255),
          mstRoot,
          rootBalances,
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
          mstRoot,
          [BigNumber.from(1000000000)],
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

    it("should revert with invalid root sum", async () => {
      rootBalances = [BigNumber.from(0), BigNumber.from(0)];

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        submitCommitment(summa, mstRoot, rootBalances)
      ).to.be.revertedWith("All root sums should be greater than zero");
    });

    it("should revert with invalid cryptocurrencies", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        submitCommitment(summa, mstRoot, rootBalances, [
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
        submitCommitment(summa, mstRoot, rootBalances, [
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

    it("should not submit invalid root", async () => {
      await expect(
        submitCommitment(summa, BigNumber.from(0), rootBalances)
      ).to.be.revertedWith("Invalid MST root");
    });

    it("should revert if cryptocurrency and liability counts don't match", async () => {
      rootBalances = [BigNumber.from(10000000)];
      await expect(
        submitCommitment(summa, mstRoot, rootBalances)
      ).to.be.revertedWith(
        "Root liabilities sums and liabilities number mismatch"
      );
    });
  });

  describe("verify proof of inclusion", () => {
    let commitmentMstRoot: BigNumber;
    let rootBalances: BigNumber[];
    let inclusionMstRoot: BigNumber;
    let leafHash: BigNumber;
    let balance1: BigNumber;
    let balance2: BigNumber;
    let summa: Summa;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
    let inclusionProof: string;
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

      const inclusionJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../zk_prover/examples/inclusion_proof_solidity_calldata.json"
        ),
        "utf-8"
      );
      const inclusionCalldata: any = JSON.parse(inclusionJson);

      inclusionProof = inclusionCalldata.proof;
      leafHash = inclusionCalldata.public_inputs[0];
      inclusionMstRoot = inclusionCalldata.public_inputs[1];
      balance1 = inclusionCalldata.public_inputs[2];
      balance2 = inclusionCalldata.public_inputs[3];

      const commitmentCalldataJson = fs.readFileSync(
        path.resolve(
          __dirname,
          "../../zk_prover/examples/commitment_solidity_calldata.json"
        ),
        "utf-8"
      );
      const commitmentCalldata: any = JSON.parse(commitmentCalldataJson);

      commitmentMstRoot = commitmentCalldata.root_hash;
      rootBalances = commitmentCalldata.root_balances;
    });

    it("should verify the proof of inclusion for the given public input", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitCommitment(summa, commitmentMstRoot, rootBalances);
      expect(
        await verifyInclusionProof(
          summa,
          inclusionProof,
          leafHash,
          inclusionMstRoot,
          balance1,
          balance2
        )
      ).to.be.equal(true);
    });

    it("should not verify with invalid MST root", async () => {
      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitCommitment(summa, commitmentMstRoot, rootBalances);
      inclusionMstRoot = BigNumber.from(0);
      await expect(
        verifyInclusionProof(
          summa,
          inclusionProof,
          leafHash,
          inclusionMstRoot,
          balance1,
          balance2
        )
      ).to.be.revertedWith("Invalid MST root");
    });

    it("should not verify if the MST root lookup by timestamp returns an incorrect MST root", async () => {
      // The lookup will return a zero MST root as no MST root has been stored yet
      await expect(
        verifyInclusionProof(
          summa,
          inclusionProof,
          leafHash,
          inclusionMstRoot,
          balance1,
          balance2
        )
      ).to.be.revertedWith("Invalid MST root");
    });

    it("should not verify with invalid root balances", async () => {
      balance1 = BigNumber.from(0);

      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitCommitment(summa, commitmentMstRoot, rootBalances);
      await expect(
        verifyInclusionProof(
          summa,
          inclusionProof,
          leafHash,
          inclusionMstRoot,
          balance1,
          balance2
        )
      ).to.be.revertedWith("Invalid root balance");
    });

    it("should not verify with invalid leaf", async () => {
      leafHash = BigNumber.from(0);

      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitCommitment(summa, commitmentMstRoot, rootBalances);
      await expect(
        verifyInclusionProof(
          summa,
          inclusionProof,
          leafHash,
          inclusionMstRoot,
          balance1,
          balance2
        )
      ).to.be.revertedWith("Invalid inclusion proof");
    });

    it("should not verify with invalid proof", async () => {
      inclusionProof = inclusionProof.replace("1", "2");

      await summa.submitProofOfAddressOwnership(ownedAddresses);
      await submitCommitment(summa, commitmentMstRoot, rootBalances);
      await expect(
        verifyInclusionProof(
          summa,
          inclusionProof,
          leafHash,
          inclusionMstRoot,
          balance1,
          balance2
        )
      ).to.be.revertedWith("Invalid inclusion proof");
    });
  });
});
