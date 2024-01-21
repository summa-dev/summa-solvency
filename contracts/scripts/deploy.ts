import { ethers } from "hardhat";
import hre from "hardhat";

type Deployment = {
  address: string;
};

type Deployments = {
  [network: number]: Deployment;
};

async function main() {
  const inclusionVerifier = await ethers.deployContract(
    "src/InclusionVerifier.sol:Verifier"
  );
  await inclusionVerifier.deployed();

  // The number of levels of the Merkle sum tree
  const mstLevels = 4;
  //The number of cryptocurrencies supported by the Merkle sum tree
  const currenciesCount = 2;
  // The number of bytes used to represent the balance of a cryptocurrency in the Merkle sum tree
  const balanceByteRange = 8;
  const summa = await ethers.deployContract("Summa", [
    inclusionVerifier.address,
    mstLevels,
    currenciesCount,
    balanceByteRange,
  ]);

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

  //Copy the ABIs from `artifacts/src/*` to `backend/src/contracts/*`
  copyAbi(fs, "Summa", "Summa");
  copyAbi(fs, "InclusionVerifier", "Verifier");
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

function copyAbi(fs: any, filename: string, contractName: string) {
  const abi = require(`../artifacts/src/${filename}.sol/${contractName}.json`);
  const abiStringified = JSON.stringify(abi);
  fs.writeFileSync(
    `../backend/src/contracts/abi/${filename}.json`,
    abiStringified
  );
}
