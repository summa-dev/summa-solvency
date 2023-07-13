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
        "0x095ccd79cf0fef9757faed74485f7ded9dce7a67490773630adce50112f1e13907f894b25e6ad9bfd5e88c4fbd01327976e70c8fb83016c4d2f21930f72278e2240e9e1d49eca19e6ae06e8f500442e69354c6855299ab806984971c07e935ed1aa8d7c3d3ec19f7a65df38ec899aa085e9d917b51781e2c89a57e4d033306be04c1ec6a7265dd96431fd06f59a7c10cdd1b2c17bb8a259ea1f0aa473990a7fd2633b8fa4d3395806dd22cb52edc43f313f6bafc368c151eb2110e20bab9f23f0c9d2d2aac1c6035695f8087fc70a5bb7440bc9dc9073f74b155756b61e9734d05260ef5fa80036420528a209e0c767e1726f8e64ebcfb5ee9a59d12edb50cfb042e43a2bda4bfdc02fad894ea18981ddc58c80af745f67b5ff97ef04f9b37c90b9eaedb194eda4d7abc8c49097304d2a8515f18620b9ff59bbc56e0dcbe377c1308f11d72d983e263fc440811d6e9f193b0a0fa264f38e67f4f431eceb8470920b263648501bd10d7ee87b1ac413ff080ceb691f53e95791e2a1e39deb1b1e72d2968566eebef50f4f2e79a91221eed08f4ac57f07cdfb3780001f73f5ea89f0066094b22cc19559c81b898193816359039435a69f34b9245b6db8c8f76e1aa075939e23db318371e7ee4f4ea41b548551457cb4131280794621ca72ba2cef007cffcf5ceb934bc9a69f2c80c0625b667842428081b74920e603957e172806f29dc85bd03199aad1988eba070e2bfc8a0a37f9984701d8857a84a65a64dbfa61ba6b830fa5047ad4be4bc6b3357481b8d83d677e03f27db83a147aa49218c1401533188c87da56d4b7871964fad13103bd5125e33ee3ac41d241dff20b4be5d0304a46b3f973064c76b9999207f0606b0dbf417fb8362e7f29773713764326e27d44618a59c7b2b741f2f9e5a225fd63482113795b81f3476224e4be55e89280cee3e773320d85b175670273a14c8e9b4821bf2069ef5254ebba4fe2ed7b744020fdef85cebaa478f34eddc114701de9d9f4c6318dd3e55349bc92f837bf01a0afaa3e07561e8a281898f69981a1505370aeb063a61a29cb713debbe4ca6cac2cf40034fc6faeeba1f31b78730521ec6b6de6e2d0ae2f4a0781b130680120131bbf8bffe56f5baa7556a0b846b2a827e8eb55ac207a528810a975281329cb7a04c5d064170e42cdf6c9d9291edc8c3373f9f73fc50f7ab8dec245bc155b27f7174f87f87670016ab8763f1121f05745c7d6f70114e81db2eb822a94f28ff29318de1f4fc21f8d3502fb0806ace655edcb2e68c57f841f186c834e306ca07f9c04d33d11ffe15f71eff3076d0ef01c6d434dc2fe13ae3d4536fff415613f5b5f13c5bcc11c5569651b58f300abcc1e4e8692f36adc21149d5989a494e1544ba6111b57c7d0dd823ab53191e7aded3e96e11a88546419d409a164708b0777a2ca2bef4a705d7e2048efdd9c5978e6fc3a23302547a082a3d0893d3500b8b6c1ac1ac376ec9ebe367b3f852c6eac7aa70b396985826e83e9cadb6e8bd9c889997907ca30a75797e24fd52db5ae01fee5bb60ad0a26e39f73bee7c319703e7a45c403fe6104fa01c8ee86bc5cd4d6ac229ec9d0a7151b10dc91309302e4113870841c786a41a9090004afaa14ef347429a29097f837ed9fa88cd8a0cfa158e2766c2926033bf5649846a3503a4f6cfe081e5f2a20df844428bef230df79ec079c8525304f246b6cb90e3616ca07a8b0e11ad5f8de084aa125a498890cc7a8ca3d530f2c1df65a6e163c4373efa7766b7cf76b87270c8493d6d54abcde7b1c15507008370cc980d7ad3828e204cd7ae65db8538c6f742d8d0f0de08450617dfe4b3a05fbd7c73836de16e166caf0a0996e42793c6ddf0945014b310e4ad9ee64a22a2a2f5df921226f31d81322e8cf26c6da09b1dffdb42942b3c24c717dfd09a0831e1d7ffd20f43a21f07051449bef2d7e7fa662233fe493191ae6960e70ed7b9027eaafe9e42c49d8bf01988eb6cbb5352248ecae0a7fd31f9784522738675b8b219d95479c69e4e4061cc059c6dc935a678799c05e25c6f3ff445758399d80ea30388310ae65091c556d902ccfe2c55dc0d36b5c650c9ff907a51c695fe04ced186033d72daa6a5e90b651a7c4439d8376c82d0b4e5a5bd55c4075c9cbeabbfc1831c82d27556c6a21805e37ee343af28d5b155dd4df511a7cfd61a23c3e883729e8faf874e65e49ca84d76af5a0f8c36229212fe5ce6c69b4f268095cb4e1da01e8ed9374da2a7caf40b42ae0aa8bddc477911bd6aeb3376620a9d177779f420577660b7f457c168b6d7c953649545b2bbb8f8f4f2a089f1add2dba02f745672ca2e8b6936aded6139df497ddf2c9580a0f6e4a215332b209c372b87bc02df4207906f52996194c8b90203c249c8e94120fd24c514d0534d6adb3b1432b9b9b0fe71c1e4e41d4fd7f4f38f8092da15093d64791cfa1989efb096b3bbcd6a28b08468788cb1496329e5a771e9ba6589798bc355479dc82982e2b586182ee47121aad284cdf04ea85714ea3c2a6d4c4a229ec4efb37f819d4ff7dc7be4c37d5cf0cb3a85190d269f5ed86568959c77016cfde4b625168a9d423c00d5b3468c9402087ce7b8f1d60561cae28355278302a80cbf41f6f5cb825cdb86848f5c612490b4f6a46f6e1ce405b3f2a5bb47fc41093b5a71bed6edcc26ba4774d62ae2a3c243d1449d88a62ecc9ad3b9cd3c75769a799c39e614773c60301adbf068a28152d360fa6f5bc0c28e6bbab10bcc5e7489a42479b7fe818839c480c6111f0093d11361f1e64cd5ad836ed5447b04d723bff21d8c532a8c5171a6052e8f715416b10a7350ee05209d05c89a38647c472a9cc3340bc297bab55d412b55e903b1ab020b8fb2ddba3489e975afd45001ab45d1da25c74c2dc63ec4a4c71542c05aa7c0c03e33520ae22819ac1610c83146f1293f75e9a3d570d98e2b1a6a7ba4480ee299ee59065eb72fe388128bf5a435cb31ed75a2703426ee79eb3224538f7acb009642910ff7f8f851c4e15ec89dcca116cffb699be25d16326ce3bb9cf00f763062b0b5dab0673b3e1c97e32a3a292d18dd3df69e223369ec988a586c3d4ec2c1bc914b6dd72b8d50ac2c8ac5375016e0f8f0deb2213f9836cbe0bb76fd238ab22b3dd71c800b022cb90e4984ecf2149b6940850ceec181e65d2e6c1cfbe378f";
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
