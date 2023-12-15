//! This crate contains the cryptogarphic primitives for implementing proof of solvency protocol.
//! The tooling being used to generate the zkSNARKs is [Halo2 PSE Fork](https://github.com/privacy-scaling-explorations/halo2).

#![feature(generic_const_exprs)]

/// Zk circuit subcomponents aka chips.
pub mod chips;
/// Zk circuits with a full prover and verifier. A circuit can be viewed as an assembly of chips.
pub mod circuits;
/// Utilities to build the merkle sum tree data structure. No zk proof in here.
pub mod merkle_sum_tree;
