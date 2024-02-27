#!/bin/bash
set -e

# Build the verifier contract
echo "1. Building verifier contracts"
cd ../zk_prover
cargo run --release --bin generate_verifier

# Generate Commitment and Proofs for Encoded Polynomials
echo "2. Generate Commitment and Proofs for Encoded Polynomials"
cd ../zk_prover
cargo run --release --bin generate_commitment_and_proofs

# Deploy contracts to local environment
echo "3. Deploying contracts to local environment"
cd ../contracts
npm install
npx hardhat node &
HARDHAT_PID=$!
sleep 5
npx hardhat run scripts/deploy.ts --network localhost

# Generate interface files for Backend
echo "4. Generating interface files for Backend"
cd ../backend
cargo build

# Wrap up
echo "Terminate hardhat node"
kill $HARDHAT_PID
