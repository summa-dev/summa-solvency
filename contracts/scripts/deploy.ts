import { ethers } from "hardhat";
import hre from "hardhat";

type Deployment = {
  address: string;
};

type Deployments = {
  [network: number]: Deployment;
};

async function main() {
  const verifier = await ethers.deployContract(
    "src/SolvencyVerifier.sol:Verifier"
  );
  await verifier.deployed();

  const summa = await ethers.deployContract("Summa", [verifier.address]);

  await summa.deployed();

  console.log(`Summa deployed to ${summa.address}`);

  let deploymentsJson: Deployments = {};
  const fs = require("fs");
  try {
    const deploymentsRaw = fs.readFileSync(
      "../backend/src/contracts/deployments.json",
      "utf8"
    );
    deploymentsJson = JSON.parse(deploymentsRaw);
    // Removing the previous deployment from the JSON file
    if (deploymentsJson[hre.network.config.chainId ?? 0])
      delete deploymentsJson[hre.network.config.chainId ?? 0];
  } catch (error) {
    console.log("No previous deployments found");
  }
  // Adding the new deployment to the previous deployments, indexed by network ID
  const newDeployment = {
    // Getting the contract address
    address: summa.address,
  };
  const deployments = {
    ...deploymentsJson,
    [hre.network.config.chainId ?? 0]: newDeployment,
  };
  const deploymentsStringified = JSON.stringify(deployments);
  //Save the contract address to a JSON file in backend src directory
  fs.writeFileSync(
    "../backend/src/contracts/deployments.json",
    deploymentsStringified
  );

  //TODO copy the ABI from `artifacts/src/Summa.sol/Summa.json` to `backend/src/contracts/contractAbi.json`

  // const abi = JSON.parse(summa.interface.format(FormatTypes.json).toString());
  // console.log(abi);
  // let abiJson: any = {};
  // try {
  //   const abiRaw = fs.readFileSync("../backend/src/contracts/contractAbi.json");
  //   abiJson = JSON.parse(abiRaw);
  //   if (abiJson[hre.network.config.chainId ?? 0])
  //     delete abiJson[hre.network.config.chainId ?? 0];
  // } catch (error) {
  //   console.log("No previous ABI found");
  // }
  // const abiNew = {
  //   [hre.network.config.chainId ?? 0]: abi,
  // };
  // const abiFinal = {
  //   ...abiJson,
  //   ...abiNew,
  // };
  // const abiStringified = JSON.stringify(abiFinal);
  // //Save the ABIs
  // fs.writeFileSync("../backend/src/contracts/contractAbi.json", abiStringified);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
