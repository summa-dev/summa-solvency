# Summa Smart contract

Testing:

```shell
npx hardhat node
REPORT_GAS=true npx hardhat test
```

Deploying:

```shell
npx hardhat run scripts/deploy.ts --network localhost
```

The deployment script will copy the contract ABIs from the ./artifacts/src/ to the [backend subproject](./../backend/src/contracts/abi/). The backend buildscript will then be able to generate the updated contract interfaces (see the [backend readme](./../backend/README.md)).
