import { expect } from "chai";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { MockERC20, Summa } from "../typechain-types";
import { BigNumber } from "ethers";

describe("Summa Contract", () => {
  async function deploySummaFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3] = await ethers.getSigners();

    const mockERC20 = await ethers.deployContract("MockERC20");
    await mockERC20.deployed();

    const verifier = await ethers.deployContract(
      "src/SolvencyVerifier.sol:Verifier"
    );
    await verifier.deployed();

    const summa = await ethers.deployContract("Summa", [verifier.address]);
    await summa.deployed();

    return {
      summa: summa as Summa,
      mockERC20,
      owner,
      addr1,
      addr2,
      addr3,
    };
  }

  describe("verify address ownership", () => {
    let cexAddresses: string[];
    let cexSignatures: string[];
    let summa: Summa;
    let mockERC20: MockERC20;
    let address1: string;
    let address2: string;
    let address3: string;

    beforeEach(async () => {
      const deployemtnInfo = await loadFixture(deploySummaFixture);
      summa = deployemtnInfo.summa as Summa;
      mockERC20 = deployemtnInfo.mockERC20 as MockERC20;
      address1 = deployemtnInfo.addr1.address;
      address2 = deployemtnInfo.addr2.address;
      address3 = deployemtnInfo.addr3.address;

      await mockERC20.mint(address2, 556863);

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

      cexAddresses = [address1, address2];
      cexSignatures = [
        "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
        "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
      ];
    });

    it("should verify the address ownership and store the addresses", async () => {
      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);
    });

    it("should be able to rewrite the address array for any combination", async () => {
      //Submit the addresses
      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      expect(await summa.cexAddresses(0)).to.be.equal(address1);
      expect(await summa.cexAddresses(1)).to.be.equal(address2);
      try {
        await summa.cexAddresses(2);
      } catch (e: any) {
        expect(e.code).to.be.equal("CALL_EXCEPTION");
      }

      //Re-submit the same addresses
      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      expect(await summa.cexAddresses(0)).to.be.equal(address1);
      expect(await summa.cexAddresses(1)).to.be.equal(address2);
      try {
        await summa.cexAddresses(2);
      } catch (e: any) {
        expect(e.code).to.be.equal("CALL_EXCEPTION");
      }

      //Submit the same addresses in reverse order
      cexAddresses = [address2, address1];
      cexSignatures = [
        "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
        "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
      ];

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      expect(await summa.cexAddresses(0)).to.be.equal(address2);
      expect(await summa.cexAddresses(1)).to.be.equal(address1);
      try {
        await summa.cexAddresses(2);
      } catch (e: any) {
        expect(e.code).to.be.equal("CALL_EXCEPTION");
      }

      //Submit fewer addresses than stored
      cexAddresses = [address1];
      cexSignatures = [
        "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
      ];

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      expect(await summa.cexAddresses(0)).to.be.equal(address1);
      try {
        await summa.cexAddresses(1);
      } catch (e: any) {
        expect(e.code).to.be.equal("CALL_EXCEPTION");
      }

      //Submit more addresses than stored
      cexAddresses = [address2, address1, address3];
      cexSignatures = [
        "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
        "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
        "0xeb648c7409f45ba9064707d22bdae23dff15517aaf0942b8507b60b9a924bbeb4c8f2ceafc26ede9fd9eb3232cc138500ded3e3c7b8555fa43b995bd15c234ff1c",
      ];

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      expect(await summa.cexAddresses(0)).to.be.equal(address2);
      expect(await summa.cexAddresses(1)).to.be.equal(address1);
      expect(await summa.cexAddresses(2)).to.be.equal(address3);
      try {
        await summa.cexAddresses(3);
      } catch (e: any) {
        expect(e.code).to.be.equal("CALL_EXCEPTION");
      }
    });

    it("should revert if a signature is invalid", async () => {
      //Invalid signature
      cexSignatures[0] =
        "0x9a9f2dd5ad8242b8feb5ad19e6f5cc87693bc2335ed849c8f9fa908e49c047d0250d001da1d1a83fed254171f1c686e83482b9b927702768efdaafac7375eac91d";

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      ).to.be.revertedWith("ECDSA: invalid signature");
    });

    it("should revert if the signer is invalid", async () => {
      //Invalid signer (account #3)
      cexSignatures[0] =
        "0x2cb485683668d6a9e68b27763fb40bffe6953c7ba81490f28d1b39584778568d481bca493437d9c0f2c3f0ccd989cdde746eef49faa3d6b5a4f924107684383b1b";

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      ).to.be.revertedWith("Invalid signer for ETH address");
    });

    it("should revert if not all signatures are provided", async () => {
      cexSignatures.pop();

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      ).to.be.revertedWith("CEX addresses and signatures count mismatch");
    });
  });

  describe("verifyProofOfSolvency", () => {
    let cexAddresses: string[];
    let balancesToProve: BigNumber[];
    let cexSignatures: string[];
    let erc20ContractAddresses: string[];
    let mstRoot: BigNumber;
    let summa: Summa;
    let mockERC20: MockERC20;
    let address1: string;
    let address2: string;
    let proof: string;
    //let ethAccount3;

    beforeEach(async () => {
      const deployemtnInfo = await loadFixture(deploySummaFixture);
      summa = deployemtnInfo.summa as Summa;
      mockERC20 = deployemtnInfo.mockERC20 as MockERC20;
      address1 = deployemtnInfo.addr1.address;
      address2 = deployemtnInfo.addr2.address;
      //ethAccount3 = deployemtnInfo.addr3;

      await mockERC20.mint(address2, 556863);

      cexAddresses = [address1, address2];
      cexSignatures = [
        "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b",
        "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c",
      ];
      erc20ContractAddresses = [mockERC20.address];
      balancesToProve = [BigNumber.from(556863), BigNumber.from(556863)];
      mstRoot =
        BigNumber.from(
          1300633067792667740851197998552728163078912135282962223512949070409098715333n
        );
      proof =
        "0x2aaca81e8eabeb3f860c64afc22359371a21ff693cbcc7ff8adde42c2ee8211a0e81bff0dfc99250c7e0f26c4f78256985685ea01ccf0ef96df1ca4797c7a2bf005e9febb07cf28acb4b61797511327afeca3236418ca8019b1efc1152d5a48c08f7c6e8f02849c54945c587d05a2cffd74c4dd49368e715d84d732ab45ab206021a9d0c3ab796a469f3ef177346b0e7d0768548263c6e05ae47f48cdb6644b800860a833467ed6e69191628f5d23e55693abc97133742afabdab70b005b8c7427dbfb530a76ee0ccf886a456beb3c40bf56bf83eab42caf2729830c80829fda1a566a1f1d193b9c6dee3142152bc7379eadd060b4e8b5058e8602304775950f14a73e1a3eba05ed59ea20496aa8cfcd05ba29129b198a716868c144617f949b06c62b7aef804d2b2efb73b1ad97801b1b5b66a0f71aa0642a156c45e967f93826ee110efec50529245b983b4ab64701e40a83374c9e9f6527881f58758d28f4249db4a890ac9de7d294e786c8ceeee8fd56389965c718a8ad2c045783571be42dfae36db5d113bedaff3bf2201decbc6d1dbdf8fa9214422511c63c653f191d272bc3647665c19e8c9cb0726db983fa1a32859b2f9f47e47bf7254105c4db962194c453db17906ab1d8e049bb5abaccae0033f28985d8ecfdd194e954e3fe512dd8dd9a2d80e27e97bdba4a0b208338f353029fda27396c47f7ac0a3e4cadad2e7ab146dc6a9a890f49a09121ebcd1f25d238652cd8d288a313448301728ff90b5d0e2efd9639a0491617bc1a3ab130207545f9f1ac04f0dd6734660f29758c066db15eb3f9afff2c11a2507beb26ca5bbfdd14975fd76a10c20bca07729b7e22bfce22e8978c4392832cd1e932fb081494e9c74d8a75fcbecedfe70a25084b189215e6bbc49831e015bf029918f2178bdd8dde5035d69368dc0b9577eed2db02fd626ba37dc733855d2d60a593c51bc8da4efcb19a0002c9b5897ac0e74f122ef5e1ccdf9dd0c62c72bbf0f7fa779feb2f4d76e3d43e66fa78e9a589a866e50d99a3ea6b6e138a9592a6a0289a3a4ec4c3cddcaf10b64dea0da903971fa60422d946ed5e2b6e8bbd7adaa01ba84a3499402717b1e792e6e30ecfbb751d83c90dccc56737d726a29666111ac7cd77badd6d67d4ef5733fdf94ed66724e23867243377091d0223a96a3167ddee0066e877e707650b214952a597670c63de902d097c227f5b5d3ff8cf85f88f4026334b9bd95d7f8cf8f9a724bb1fe903c7fa15274fa6a6d02ed4c9b2f12b43093765f1f66af8a7df82f9244bd2d014dbfc3312213027e5b6a792b3acb2223cb1e74fe5160fc20652e505689eaa3ee3e3598152063a484a46689b766f2100051396ede8b37c2350c86ec0377593e04abce82d3d0bf262b9fa02f031f032c6bb5db9305abc5fde869f333d8ef2e069db1fb38f3b1411d6ebb54f11ba33eb8b192d4062e0ae36f2cacf5926811cee6a68229b6a8f2618b7b0bdae46956e07842c0cf975270b0554dc3893d05d5b1869c5975736160abf62eeaf6a429caa2f83c98520e80a8a8a3035c6faf9cbfeacbdda51b5558d04c9f3c1d19df787a8ea9eeb3772008522c8bbdae6c347c63d521b5ca46b969d04bc9663e840c3ce28b7e6e11824bb24bd059cc7e03d9ef162b9e99b64f48b30069135d7e35123069b71ac8c5d912dd2c66001d4003a847215d910a4bb14dc3f270939a60bedb1f78ed147a341cfc14d38aada8b20570c90626abe363e8a8aef1f450f1f1b44bd28cd2e1dd58b7ac6800232f75b5c48355c8710cd50c228b3490663889aa6f9adfa029e8c0322e7572377e6f6b9a3c91ddc7fe8e88c8baf1bd922545883469c9ff0e447311b2fe4dd9152561811e5c9caa11c25dc95871e36240e2a56f6d9ee9b2fbf850e29244727902c75480d14ec5fac0ac8ffacd39c341115bcb1e3e0abb30ac71f4179766d294ab59fddd54819ec3c424bc92af78c25010e86f8dff12ce966eb5cfdf3850e4155d814c2dfc7a77963b2479814e22718110837005a77f51eed0e8740f2e3e96a00da3d718cf0f4145fc89bf2a31076d11117115bca8501f0c6599cdd0c95427ec7a6385f2cab9693f612c3c30f320fa0850ac598978570887f6119b8e48192d068b3e2eadb46832ae189fbb8744dbd62a724b4d05b1cc92417e4544716771f92e13ab116fa49c619768da6ed4612b2608c156c3f28d322f18916688575df6079cf7ea26951598021b88b8d5f50451e854c02a5257534becaeb6c4ee936d075f6e098db7bf16b8710ccc8d789731aa6589f0c5e57c9356c2cda369986b2821f5825107f075309000283f7155ce8b4b2f2e42f8f8f846187cc1685aca1a26ed56361c0a2782f33e2970cfdf1133e3663a17a10a12099e165db30172875fa2ee79df6aa1382f10361fc044ac17a436207263c03e7c1099b153e8a108a7ff6d952c30424e762654f4f00194aab2b3ee48d3a240d64363363d83de6f3b66ac8b8795516d2a38e1151146e62e194a63995cc160217d5e318c798b25ea4f6bd2794abf2d14c045e569f41dc33c1f5457a6a28f7db0bbe0ea3e2041d94946fd51cbfd884ab8a25a87cfaddabcd0343ef65f255a74420c2e069e2adbb349b58703ba3a007475e988a22be4b88703c38a85ce2781d071c6f87b8f7ddcab68f3ce936a1420e2b4e3fea1a12b745f1161867f471716334017c320f3b1afe8796a0eeb164f945c3e8b2b2deb9909b98a1e2a4734a3840e71297cb44895a872e779e7b80dbcf9fe971b762c4b19ad77d98e83b03c0fef12f2409a2742bc7e9cd6d54c3c84bdbfeaa94c37c4a58879f02e79b7990dc1f49cf1b4412e59f68648f709238300795daf4e4b8e019d26b17ae682ed82396cb702008a34e6fbe421139c19b40d85949614b9fe6ecbe90d5b548c76bad5847b60c9f1a837e27eeb65b150d0ac6961e9a6da049a8e9a4038f64430bd466ef0a451b58035af595e31a69ba480392979d432b280f8cfa260dfce13b207bb84b3c1b89d015e99e5defef361aa870883632cfe254394b2742f9ec0b734684c644c877b68512f530dec6b07326702d272c6ad9ba5fa95638e5556e15d54f3e08341c722bbd0dfb5e6b1a5ce79df103214245384b1648b1e6543bb3b666e9360fde310437951e1e26eecb2f866641ad629380ec116ced0a055a76c13102100a85ea8146b84c";
    });

    it("should verify the proof of solvency for the given public input", async () => {
      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      await expect(
        summa.submitProofOfSolvency(
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      )
        .to.emit(summa, "ProofOfSolvencySubmitted")
        .withArgs(mstRoot);
    });

    it("should revert if actual ETH balance is less than the proven balance", async () => {
      balancesToProve[0] = (await ethers.provider.getBalance(address1))
        .add(await ethers.provider.getBalance(address2))
        .add(BigNumber.from(1000));

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      await expect(
        summa.submitProofOfSolvency(
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith(
        "Actual ETH balance is less than the proven balance"
      );
    });

    it("should revert if actual ERC20 balance is less than the proven balance", async () => {
      balancesToProve[1] = BigNumber.from(556864);

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      await expect(
        summa.submitProofOfSolvency(
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith(
        "Actual ERC20 balance is less than the proven balance"
      );
    });

    it("should revert if not all ERC20 token addresses are provided", async () => {
      erc20ContractAddresses = [];

      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      await expect(
        summa.submitProofOfSolvency(
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("ERC20 addresses and balances count mismatch");
    });

    it("should revert with invalid MST root", async () => {
      mstRoot = BigNumber.from(0);
      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      await expect(
        summa.submitProofOfSolvency(
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("Invalid zk proof");
    });

    it("should revert with invalid proof", async () => {
      proof = "0x000000";
      await expect(
        summa.submitProofOfAccountOwnership(
          cexAddresses,
          cexSignatures,
          "Summa proof of solvency for CryptoExchange"
        )
      )
        .to.emit(summa, "ExchangeAddressesSubmitted")
        .withArgs(cexAddresses);

      await expect(
        summa.submitProofOfSolvency(
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWithoutReason();
    });
  });
});
