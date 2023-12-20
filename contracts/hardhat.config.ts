import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter";
import "solidity-coverage";
import * as dotenv from "dotenv";

dotenv.config();
module.exports = {
  defaultNetwork: "hardhat",
  networks: {
    localhost: {
      chainId: 31337,
      url: "http://127.0.0.1:8545",
    },
    hardhat: {},
    // goerli: {
    //   chainId: 5,
    //   url: process.env.GOERLI_URL,
    //   accounts: [process.env.GOERLI_PRIVATE_KEY],
    // },
  },
  gasReporter: {
    currency: "USD",
    gasPrice: 30,
  },
  solidity: {
    compilers: [
      {
        version: "0.8.18",
        settings: {
          evmVersion: "istanbul",
          optimizer: {
            enabled: true,
            runs: 200,
          },
          viaIR: true,
        },
      },
    ],
  },
  paths: {
    sources: "src",
    tests: "test",
    cache: "cache",
    artifacts: "artifacts",
    out: "build/out",
  },
};
