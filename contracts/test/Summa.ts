import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import {
  ERC20BalanceRetriever,
  ETHBalanceRetriever,
  EVMAddressVerifier,
  MockERC20,
  Summa,
} from "../typechain-types";
import { BigNumber, Signer } from "ethers";
import { defaultAbiCoder, solidityKeccak256 } from "ethers/lib/utils";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import * as fs from 'fs';
import * as path from 'path';

describe("Summa Contract", () => {
  async function deploySummaFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3]: SignerWithAddress[] =
      await ethers.getSigners();

    const mockERC20 = await ethers.deployContract("MockERC20");
    await mockERC20.deployed();

    const verifier = await ethers.deployContract(
      "src/SolvencyVerifier.sol:Verifier"
    );
    await verifier.deployed();

    const evmAddresVerifier = await ethers.deployContract("EVMAddressVerifier");
    await evmAddresVerifier.deployed();

    const ethBalanceRetriever = await ethers.deployContract(
      "ETHBalanceRetriever"
    );
    await ethBalanceRetriever.deployed();

    const erc20BalanceRetriever = await ethers.deployContract(
      "ERC20BalanceRetriever"
    );
    await erc20BalanceRetriever.deployed();

    const summa = await ethers.deployContract("Summa", [verifier.address]);
    await summa.deployed();

    return {
      summa: summa as Summa,
      mockERC20,
      evmAddresVerifier,
      ethBalanceRetriever,
      erc20BalanceRetriever,
      owner,
      addr1,
      addr2,
      addr3,
    };
  }

  describe("verify address ownership", () => {
    let summa: Summa;
    let mockERC20: MockERC20;
    let evmAddresVerifier: EVMAddressVerifier;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
    let account3: SignerWithAddress;
    let ownedAddresses: Summa.OwnedAddressStruct[];

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deploySummaFixture);
      summa = deploymentInfo.summa as Summa;
      mockERC20 = deploymentInfo.mockERC20 as MockERC20;
      account1 = deploymentInfo.addr1;
      account2 = deploymentInfo.addr2;
      account3 = deploymentInfo.addr3;
      evmAddresVerifier =
        deploymentInfo.evmAddresVerifier as EVMAddressVerifier;

      await mockERC20.mint(account2.address, 556863);

      //Reference signing procedure:
      // const message = ethers.utils.defaultAbiCoder.encode(
      //   ["string"],
      //   ["Summa proof of solvency for CryptoExchange"]
      // );
      // const hashedMessage = ethers.utils.solidityKeccak256(
      //   ["bytes"],
      //   [message]
      // );
      // const signature = await deployemtnInfo.addr3.signMessage(
      //   ethers.utils.arrayify(hashedMessage)
      // );
      // console.log("signature", signature);

      ownedAddresses = [
        {
          addressType: ethers.utils.solidityKeccak256(["string"], ["EVM"]),
          cexAddress: defaultAbiCoder.encode(["address"], [account1.address]),
          ownershipProof:
            "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
        },
        {
          addressType: ethers.utils.solidityKeccak256(["string"], ["EVM"]),
          cexAddress: defaultAbiCoder.encode(["address"], [account2.address]),
          ownershipProof:
            "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
        },
      ];
    });

    it("should allow admin to add an address verifier", async () => {
      await expect(summa.setAddressOwnershipVerifier(evmAddresVerifier.address))
        .to.emit(summa, "AddressVerifierSet")
        .withArgs(
          solidityKeccak256(["string"], ["EVM"]),
          evmAddresVerifier.address
        );
    });

    it("should not allow to add an invalid address verifier", async () => {
      await expect(
        summa.setAddressOwnershipVerifier(ethers.constants.AddressZero)
      ).to.be.revertedWith("Invalid address verifier");
    });

    it("should not allow to add an invalid address verifier", async () => {
      const invalidAddressVerifier = await ethers.deployContract(
        "InvalidAddressVerifier"
      );
      await invalidAddressVerifier.deployed();
      await expect(
        summa.setAddressOwnershipVerifier(invalidAddressVerifier.address)
      ).to.be.revertedWith("Invalid address type");
    });

    it("should revert if a non-admin is trying to add an address verifier", async () => {
      await expect(
        summa
          .connect(account1)
          .setAddressOwnershipVerifier(evmAddresVerifier.address)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("should revert if address verifier was not set", async () => {
      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Address verifier not set for this type of address");
    });

    it("should verify the address ownership and store the addresses", async () => {
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);

      await expect(summa.submitProofOfAddressOwnership(ownedAddresses))
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs((ownedAddresses: any) => {
          return (
            ownedAddresses[0].addressType ==
              ethers.utils.solidityKeccak256(["string"], ["EVM"]) &&
            ownedAddresses[0].cexAddress ==
              defaultAbiCoder.encode(["address"], [account1.address]) &&
            ownedAddresses[0].ownershipProof ==
              "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b" &&
            ownedAddresses[1].addressType ==
              ethers.utils.solidityKeccak256(["string"], ["EVM"]) &&
            ownedAddresses[1].cexAddress ==
              defaultAbiCoder.encode(["address"], [account2.address]) &&
            ownedAddresses[1].ownershipProof ==
              "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c"
          );
        });
    });

    it("should revert if a signature is invalid", async () => {
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);

      //Invalid signature
      ownedAddresses[0].ownershipProof =
        "0x9a9f2dd5ad8242b8feb5ad19e6f5cc87693bc2335ed849c8f9fa908e49c047d0250d001da1d1a83fed254171f1c686e83482b9b927702768efdaafac7375eac91d";

      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("ECDSA: invalid signature");
    });

    it("should revert if the signer is invalid", async () => {
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);

      //Invalid signer (account #3)
      ownedAddresses[0].ownershipProof =
        "0x2cb485683668d6a9e68b27763fb40bffe6953c7ba81490f28d1b39584778568d481bca493437d9c0f2c3f0ccd989cdde746eef49faa3d6b5a4f924107684383b1b";

      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Invalid signer");
    });

    it("should revert if the address has already been verified", async () => {
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        summa.submitProofOfAddressOwnership(ownedAddresses)
      ).to.be.revertedWith("Address already verified");
    });
  });

  describe("verify proof of solvency", () => {
    let mstRoot: BigNumber;
    let summa: Summa;
    let mockERC20: MockERC20;
    let account1: SignerWithAddress;
    let account2: SignerWithAddress;
    let evmAddresVerifier: EVMAddressVerifier;
    let ethBalanceRetriever: ETHBalanceRetriever;
    let erc20BalanceRetriever: ERC20BalanceRetriever;
    let ownedAddresses: Summa.OwnedAddressStruct[];
    let ownedAssets: Summa.OwnedAssetStruct[];
    let proof: string;
    //let ethAccount3;

    beforeEach(async () => {
      const deploymentInfo = await loadFixture(deploySummaFixture);
      summa = deploymentInfo.summa as Summa;
      mockERC20 = deploymentInfo.mockERC20 as MockERC20;
      account1 = deploymentInfo.addr1;
      account2 = deploymentInfo.addr2;
      evmAddresVerifier =
        deploymentInfo.evmAddresVerifier as EVMAddressVerifier;
      ethBalanceRetriever =
        deploymentInfo.ethBalanceRetriever as ETHBalanceRetriever;
      erc20BalanceRetriever =
        deploymentInfo.erc20BalanceRetriever as ERC20BalanceRetriever;

      ownedAddresses = [
        {
          addressType: ethers.utils.solidityKeccak256(["string"], ["EVM"]),
          cexAddress: defaultAbiCoder.encode(["address"], [account1.address]),
          ownershipProof:
            "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
        },
        {
          addressType: ethers.utils.solidityKeccak256(["string"], ["EVM"]),
          cexAddress: defaultAbiCoder.encode(["address"], [account2.address]),
          ownershipProof:
            "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
        },
      ];

      ownedAssets = [
        {
          assetType: ethers.utils.solidityKeccak256(["string"], ["ETH"]),
          addresses: [
            defaultAbiCoder.encode(["address"], [account1.address]),
            defaultAbiCoder.encode(["address"], [account2.address]),
          ],
          amountToProve: BigNumber.from(556863),
          balanceRetrieverArgs: "0x",
        },
        {
          assetType: ethers.utils.solidityKeccak256(["string"], ["ERC20"]),
          addresses: [defaultAbiCoder.encode(["address"], [account2.address])],
          amountToProve: BigNumber.from(556863),
          balanceRetrieverArgs: defaultAbiCoder.encode(
            ["address"],
            [mockERC20.address]
          ),
        },
      ];

      await mockERC20.mint(account2.address, 556863);

      const jsonData = fs.readFileSync(path.resolve(__dirname, '../../zk_prover/examples/proof_solidity_calldata.json'), 'utf-8');
      const calldata: any = JSON.parse(jsonData);

      mstRoot = calldata.public_inputs[0]
      proof = calldata.proof;
    });

    it("should allow admin to set a balance retriever", async () => {
      await expect(summa.setBalanceRetriever(ethBalanceRetriever.address))
        .to.emit(summa, "BalanceRetrieverSet")
        .withArgs(
          solidityKeccak256(["string"], ["ETH"]),
          ethBalanceRetriever.address
        );
    });

    it("should revert if a non-admin is trying to set a balance retriever", async () => {
      await expect(
        summa.connect(account1).setBalanceRetriever(ethBalanceRetriever.address)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("should not allow to set an invalid balance retriever", async () => {
      await expect(
        summa.setBalanceRetriever(ethers.constants.AddressZero)
      ).to.to.be.revertedWith("Invalid balance retriever");
    });

    it("should not allow to set a balance retriever with an invalid asset", async () => {
      const invalidBalanceRetriever = await ethers.deployContract(
        "InvalidBalanceRetriever"
      );
      await invalidBalanceRetriever.deployed();
      await expect(
        summa.setBalanceRetriever(invalidBalanceRetriever.address)
      ).to.to.be.revertedWith("Invalid asset type");
    });

    it("should not verify the proof if the balance retriever was not set", async () => {
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        summa.submitProofOfSolvency(
          ownedAssets,
          mstRoot,
          proof,
          BigNumber.from(0)
        )
      ).to.be.revertedWith("Balance retriever not set for this type of asset");
    });

    it("should verify the proof of solvency for the given public input", async () => {
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);
      await summa.setBalanceRetriever(ethBalanceRetriever.address);
      await summa.setBalanceRetriever(erc20BalanceRetriever.address);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        summa.submitProofOfSolvency(
          ownedAssets,
          mstRoot,
          proof,
          BigNumber.from(0)
        )
      )
        .to.emit(summa, "ProofOfSolvencySubmitted")
        .withArgs(mstRoot);
    });

    it("should not verify the proof of solvency if the CEX hasn't proven the address ownership", async () => {
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);
      await summa.setBalanceRetriever(ethBalanceRetriever.address);
      await summa.setBalanceRetriever(erc20BalanceRetriever.address);

      await expect(
        summa.submitProofOfSolvency(
          ownedAssets,
          mstRoot,
          proof,
          BigNumber.from(0)
        )
      ).to.be.revertedWith("Address ownership not verified");
    });

    it("should revert if actual ETH balance is less than the proven balance", async () => {
      //Make the proven balance bigger than the actual balance
      ownedAssets[0].amountToProve = (
        await ethers.provider.getBalance(account1.address)
      )
        .add(await ethers.provider.getBalance(account2.address))
        .add(BigNumber.from(1000000000000000));

      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);
      await summa.setBalanceRetriever(ethBalanceRetriever.address);
      await summa.setBalanceRetriever(erc20BalanceRetriever.address);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        summa.submitProofOfSolvency(
          ownedAssets,
          mstRoot,
          proof,
          BigNumber.from(0)
        )
      ).to.be.revertedWith("Actual balance is less than the amount to prove");
    });

    it("should revert if actual ERC20 balance is less than the proven balance", async () => {
      //Make the proven balance bigger than the actual balance
      ownedAssets[1].amountToProve = BigNumber.from(556864);

      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);
      await summa.setBalanceRetriever(ethBalanceRetriever.address);
      await summa.setBalanceRetriever(erc20BalanceRetriever.address);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        summa.submitProofOfSolvency(
          ownedAssets,
          mstRoot,
          proof,
          BigNumber.from(0)
        )
      ).to.be.revertedWith("Actual balance is less than the amount to prove");
    });

    it("should revert with invalid MST root", async () => {
      mstRoot = BigNumber.from(0);
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);
      await summa.setBalanceRetriever(ethBalanceRetriever.address);
      await summa.setBalanceRetriever(erc20BalanceRetriever.address);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        summa.submitProofOfSolvency(
          ownedAssets,
          mstRoot,
          proof,
          BigNumber.from(0)
        )
      ).to.be.revertedWith("Invalid zk proof");
    });

    it("should revert with invalid proof", async () => {
      proof = "0x000000";
      await summa.setAddressOwnershipVerifier(evmAddresVerifier.address);
      await summa.setBalanceRetriever(ethBalanceRetriever.address);
      await summa.setBalanceRetriever(erc20BalanceRetriever.address);

      await summa.submitProofOfAddressOwnership(ownedAddresses);

      await expect(
        summa.submitProofOfSolvency(
          ownedAssets,
          mstRoot,
          proof,
          BigNumber.from(0)
        )
      ).to.be.revertedWithoutReason();
    });
  });
});
