# TODO

## Build a Grand Sum Polynomial Construction Verifier Contract

A `gen_solidity_verifier.rs` script is provided to generate a solidity contract that can be used to verify the proof of the grand sum polynomial construction. The script can be run as follows:

```
cargo run --release --example gen_solidity_verifier
```

The script will generate a new `Halo2Verifier.sol` contract in `/generated`.
