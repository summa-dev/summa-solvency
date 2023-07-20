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

  //Copy the ABI from `artifacts/src/Summa.sol/Summa.json` to `backend/src/contracts/Summa.json`
  const abi = require("../artifacts/src/Summa.sol/Summa.json");
  const abiStringified = JSON.stringify(abi);
  fs.writeFileSync("../backend/src/contracts/Summa.json", abiStringified);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
