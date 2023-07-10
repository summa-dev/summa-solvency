import { expect } from "chai";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { MockERC20, Summa } from "../typechain-types";
import { defaultAbiCoder, solidityKeccak256 } from "ethers/lib/utils";
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

  describe("verifyProofOfSolvency", () => {
    let exchangeId: string;
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

      //Reference signing procedure:
      // const message = ethers.utils.defaultAbiCoder.encode(
      //   ["string", "string"],
      //   ["Summa proof of solvency for ", "CryptoExchange"]
      // );
      // const hashedMessage = ethers.utils.solidityKeccak256(
      //   ["bytes"],
      //   [message]
      // );
      // const signature = await ethAccount2.signMessage(
      //   ethers.utils.arrayify(hashedMessage)
      // );
      // console.log("signature", signature);

      exchangeId = "CryptoExchange";
      cexAddresses = [address1, address2];
      cexSignatures = [
        "0xea576c302228671c074bdf26fbd757d9c64016aa9974eaeb911274d1458a49f05aa5d4b9df5c0a4a68d2256bea8a6c762130e538b41f47fd54b2cbbdccd6a9de1c",
        "0x5dc26d1b8cf94a11897872bbba7301fcf9e16a9767b4170b978586659b9ec52842621d323f42bf398ae23970fa21194ba8319faea4b2fd85e133a112702e21ab1b",
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
      const exchangeIdHash = ethers.utils.keccak256(
        defaultAbiCoder.encode(["string"], ["CryptoExchange"])
      );
      //calldata: (
      //Bytes(0x1b531702eb8124c58c0691d2b5293d41d6f86eda516a14629af3304a69dee6121f41a2f37101cc5c7141cb4d5111aeebb7482efc7dc0d9c2930ad4849ed3012528594c3ac2e2852d9fcae5c092d9747875e7587f5875184b263a158d9b93d3da21f854d412bef9ff730c023e33e73c96149b2cbcd6a64b94719bb7778ab91a4126eb960525dd35e31c736de87cc993458883224801ec059db2a1866b17208f822328136b19d4231f4f4ef53eaf4b55f4438da656c48a5a998821217b7329074a16e2089f730191067b45f23fa546aa2b9170675a72ca91a52443978dee507b20150b7153f947eaf9945d31c112a9d33c15c0299904f36a8f6f30d61ece884615114fb5df0268a0555777ec236c1b447009fc21c9e4f46bb40bd4386066f9a86c2f5df3f2ad11dd2756c25af2b80b811c9a39ebe822173ed0ef6574f966bcccc514b98dd8da5672337f345297f1b09275f0b367b59bb8797134593a90eb3e939820ca20fa72be051f47e8033d0e3477efe4de3574046cadc3ae24012ce1874648193adfd7da3e5fdd62d8d923be6dd3076663d6cf96ebc4dcf47d60cba70492ef1654326fe57ff5c91cc697738b8b9ab3a316659f9c5561c968f28951670fc8d31151888eef09ce7feed2b7af2bba339aa76bca36a6e32d646415e448ab55dd4513d8c3c78f53dae778f3e7234bc3add935fe020397f0a9249514a1b1060702040e102d8683c4801c0538dcdd28d6eb8567366f012e6402d87fae1beea0250e33093362899af4f360289dab8e6f04a4a5d320546816b62a0225b0464e2e49e5391b3f67bf1be5fb777b336db9f999a1ff1d1e2023672a1f28ceff27db8d115cf71de31ace31db47d66a529de90ca2e17fd66e6d048c30fb814224e61a7dec343419871d070ed9d4fe8de05cd61fcd43e0bde9924848c1d38296f3a0e528c7e6f81e203b1f2f5e6c4b82530b8e302521e07dcbcf4a252eb97d94bf80c9c234f24505fcafe98e4021728af2480144b949243af46bd62c3078d4c6b0d712eb25edd70c39152a80e14a127a14854426516921c80801eb3d2bf504ced8034bcf095eb212a92e7912df88780612d63f5f37a80451dcdbde819d95f7481e8b56af7d1ce9217e4d7e9a362b22379401e71e25495240cee82f89fd3f29157740ee23b93f9f2f0fc12038e98bf463fc85d509704ea0fe333e54bc3a0fac16962ffafea8b2a10ae961cf12537f2edfea731c92041f999096c05a66bb6ad75df7db4ab524d0730f0592d7a2fbb3b0044918fa00ea9d9e6ba2a5248588103e4dec74e80cff3a42050b2186b4817723c298138c2503b8a39ddb32a14587229cf94933e3fd1c4c3a0d8793ab7c354709c4a33c3e948dd6c5827be7b282a8a2f555c5492e635548271b7fc962c849d1d053964d205e6288d188fe119107b2878ffe182e0396c8f8872bb1f0db65c5e9ea6ef527313599b29c7e820532ed50a356af3246536c0a8f071c20d48876a3e2b5782e8055d4bfea7caa31f2c3a9816071b70b3b2499c3f37c1fab4a5a07462d8f3219d457b5eb7c36c6bd9105b259bf8627e18e3af4650dfc0ba3306f9cccd0f8b31f5bb6ec8de445915a183a1f5f773d0625f30945aba4f50a3d94b5569d3f053ebd08ef2e8aac477f533fe102c9f0b9804c8933cb95f33328d5cb6e986e3a5d7872b79398ee57fa83dbaf2294a57bce122167126c9b63721464c8eab88e60ef3e448b49edadc7d5e31763d83121af77b9bc1b521f5d6a0a2abb4314cf8fa737c1daf925bfae2459b47d5c43f9a9e3148f19df647a15798c134e9225d8ccbefbd90094962347f758241da5cffa1e406e2ffab12aff2da9bc2e85492a255b44e5ff7d09dc16f8d8aee36d2bba3d9b0a5d6b794a5478771bb70446cd5bcd0fc45e7e9d6587b220972fbbb757359a98df9b731ddf7d36acfc0009e77671648d7e09c987fe7778a1c57d7b3b52e3410664bb9aecec35ccb39fe81ba42d1b28bb951c44a1a87da187a23df55d5086fcde81de5303810b4308c04802e08559a52421fae1680c3705a8db0b213c3306f45cd3f7bff37b3c7387188713723713e7b95dd8b4f21fe8923a855047b5fe6f30613d005ecb152cc5cac09d18ef2c575c23f3ac10f1c3507fe2f4eff9b53c29a98e24386032eb5c62f66bc920e55d5be8625b8aafdbb6374a85d22d61d3d0359efd88cd729cfff0809bc39f155a7c9f755669785a1a9da8e4a51322b62387a8bde98ee4612f9da3957dea7827bd9646cd86947dcd0cb6dfb4afd89ce6d1a9b9d6c547bf4d45be9f07a7a01823bbe6bbff643d8b0b50b3f79ba354671ed8f342b6d8b612c5de1438d7a3f615),
      //[1300633067792667740851197998552728163078912135282962223512949070409098715333, 556863, 556863]
      //)

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      )
        .to.emit(summa, "ProofOfSolvencySubmitted")
        .withArgs(exchangeIdHash, mstRoot);
    });

    it("should revert if a signature is invalid", async () => {
      //Invalid signature
      cexSignatures[0] =
        "0x9a9f2dd5ad8242b8feb5ad19e6f5cc87693bc2335ed849c8f9fa908e49c047d0250d001da1d1a83fed254171f1c686e83482b9b927702768efdaafac7375eac91d";

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("ECDSA: invalid signature");
    });

    it("should revert if the signer is invalid", async () => {
      //Invalid signer (account #3)
      cexSignatures[0] =
        "0x2cb485683668d6a9e68b27763fb40bffe6953c7ba81490f28d1b39584778568d481bca493437d9c0f2c3f0ccd989cdde746eef49faa3d6b5a4f924107684383b1b";

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("Invalid signer for ETH address");
    });

    it("should revert if not all signatures are provided", async () => {
      cexSignatures.pop();

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWith("CEX addresses and signatures count mismatch");
    });

    it("should revert if actual ETH balance is less than the proven balance", async () => {
      balancesToProve[0] = (await ethers.provider.getBalance(address1))
        .add(await ethers.provider.getBalance(address2))
        .add(BigNumber.from(1000));

      await expect(
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
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
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
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
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
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
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
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
        summa.submitProofOfSolvency(
          exchangeId,
          cexAddresses,
          cexSignatures,
          erc20ContractAddresses,
          balancesToProve,
          mstRoot,
          proof
        )
      ).to.be.revertedWithoutReason();
    });
  });
});
