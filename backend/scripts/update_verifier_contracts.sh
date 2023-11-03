#!/bin/bash
set -e

# Build the verifier contracts
echo "1. Building verifier contracts"
cd ../zk_prover
cargo run --release --example gen_inclusion_verifier
cargo run --release --example gen_solvency_verifier

# Deploy contracts to local environment
echo "2. Deploying contracts to local environment"
cd ../contracts
npm install
npx hardhat node &
HARDHAT_PID=$!
sleep 5
npx hardhat run scripts/deploy.ts --network localhost

# Generate interface files for Backend
echo "3. Generating interface files for Backend"
cd ../backend
cargo build

# Wrap up
echo "Terminate hardhat node"
kill $HARDHAT_PID
