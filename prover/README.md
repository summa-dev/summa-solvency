# Summa V3: Hyperplonk Prover

## Motivation

## Usage

To build, test and print the circuits, execute

```
cargo build
cargo test --release --features dev-graph
```

## Benchmarks

The following benchmarks are available in the `kzg` module:

- `grand sum proof`: the time to generate a ZK-SNARK proof of the grand sum with a range check of every balance;
  To run the benchmarks with the default full configuration of the circuit (range check enabled), use the following command:

```shell
cargo bench
```
