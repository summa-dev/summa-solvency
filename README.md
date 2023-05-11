# Circuits - Halo2

This repository contains the Halo2 circuit implementation for the Proof of Solvency protocol. 

This library makes use of the [PSE Fork of Halo2](https://github.com/privacy-scaling-explorations/halo2).

## Usage

`cargo build`
`cargo test --features dev-graph -- --nocapture`

## Chips

- [Poseidon](#Poseidon)
- [Less Than](#Less-Than)
- [Merkle Sum Tree](#Merkle-Sum-Tree)

### Poseidon

Helper chip that performs a Poseidon hash leveraging the gadget provided by the Halo2 Library.

### Less Than

This LessThan Chip is imported from the [ZK-evm circuits gadgets](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/main/gadgets/src/less_than.rs). The LessThan Chip takes two values that are part of the witness (`lhs` and `rhs`) and returns 1 if `lhs < rhs` and 0 otherwise.

#### Configuration

The LessThan Chip Configuration contains: 

- 1 advice column `lt` that denotes the result of the comparison: 1 if `lhs < rhs` and 0 otherwise
- An array of `diff` advice columns of length N_BYTES. It is basically the difference between `lhs` and `rhs` expressed in 8-bit chunks.
- An field element `range` that denotes the range, expressed in bits, in which both `lhs` and `rhs` are expected to be. This is calculated as `2^N_BYTES * 8` where `N_BYTES` is the number of bytes that we want to use to represent the values `lhs` and `rhs`.

The configure function takes as input the lhs and rhs virtual cells from a higher level chip and enforces the following gate:

`lhs - rhs - diff + (lt * range) = 0`

Note that the gate enforces inside this child chip, the constraint is dependent on the value of some cells passed from an higher level chip. The parent chip and the child chip are sharing a region. That's why the `assign` function inside the `LTChip` takes as input the `region` rather than the `layouter` as usual.

The assignment function takes as input the lhs and rhs values and assigns the values to the columns such that:

- `lhs < rhs` bool is assigned to the `lt` advice column
- if `lhs < rhs`, `lhs - rhs + range` is assigned to the `diff` advice columns
- else `lhs - rhs` is assigned to the `diff` advice columns

Again, note that the assignment function doesn't take assigned value of type `Value<F>` but simple values of type `F` where F is a generic Field Element. This example makes clear the difference between `assignment` and `setting constraints`. The assignment function is responsible for assigning values to the columns. You can perform the assignemnt starting from values that are not necessarily computed from the circuit itself. The constraint function is responsible for setting the constraints between the columns, this process is prior and independent to the assignment/witness generation.

Now the custom gate should make more sense. Considering an example where `lhs = 5` and `rhs = 10` and N_BYTES is 1. Range would be 256 and diff would be a single advice column containing the value 251. The gate would be:

    `5 - 10 - 251 + (1 * 256) = 0`

Considering an example where `lhs = 10` and `rhs = 5` and N_BYTES is 1. Range would be 256 and diff would be a single advice column containing the value 5. The gate would be:

    `10 - 5 - 5 + (0 * 256) = 0`

The [`less_than_v2` circuit](./src/circuits/less_than_v2.rs) contains the instruction on how to use the LessThan Chip in a higher level circuit. The only added gate is that the `check` value in the advice column of the higher level circuit (which is the expected result of the comparison) should be equal to the `lt` value in the advice column of the LessThan Chip.

Lastly, let's consider a case where lhs lies outside the range. For example `lhs = 1` and `rhs = 257` and N_BYTES is 1. Diff is a single advice column but it can't represent the value 256 in 8 bits!

### Merkle Sum Tree 

This chip is the parent chip that makes use of the LessThan Chip and the Poseidon Chip.

The peculiarity of a Merkle Sum Tree are that:

- Each node inside the tree (both Leaf Nodes and Middle Nodes) contains an hash and a value.
- Each Leaf Node contains a hash and a value.
- Each Middle Node contains a hash and a value where hash is equal to `Hash(left_child_hash, left_child_sum, right_child_hash, right_child_sum)` and value is equal to `left_child_sum + right_child_sum`.

A level inside the tree consists of the following region inside the chip:

For the level 0 of the tree:

| a                | b                     | c               |    d              |   e        |  bool_selector | swap_selector |  sum_selector | lt_selector
| --               | -                     | --              |   ---             |  ---       |    --          | ---           |  ---          | ---
| leaf_hash        | leaf_balance          | element_hash    |element_balance    | index      |        1       | 1             |  0            | 0
| input_left_hash  | input_left_balance    | input_right_hash|input_right_balance|computed_sum|     0          | 0             |  1            | 0

At row 0, we assign the leaf_hash, the leaf_balance, the element_hash (from `path_element_hashes`), the element_balance (from `path_element_balances`) and the bit (from `path_indices`). At this row we turn on `bool_selector` and `swap_selector`.

At row 1, we assign the input_left_hash, the input_right_balance, the input_right_hash, the input_right_balance and the digest. 
At this row we activate the `poseidon_chip` and call the `hash` function on that by passing as input cells `[input_left_hash, input_left_balance, input_right_hash, input_right_balance]`. This function will return the assigned cell containing the `computed_hash`.

The chip contains 4 custom gates: 

- If the `bool_selector` is on, checks that the value inside the c column is either 0 or 1
- If the `swap_selector` is on, checks that the swap on the next row is performed correctly according to the `bit`
- If the `sum_selector` is on, checks that the sum between the `input_left_balance` and the `input_right_balance` is equal to the `computed_sum`
- If the `lt_selector` is on activates the lt chip and verifies the `check` from the current config is equal to the `lt` from the lt chip. Note that the `check` of the chip is set to constant 1.
- checks that the `computed_hash` is equal to the hash of the `input_left_hash`, the `input_left_balance`, the `input_right_hash` and the `input_right_balance`. This hashing is enabled by the `poseidon_chip`.

For the other levels of the tree:

| a                         | b                       | c              |    d              |   e         | bool_selector | swap_selector | sum_selector | lt_selector 
| --                        | -                       | --             |   ---             |  ---        |  --           | ---           |  ---         | ---
| computed_hash_prev_level  | computed_sum_prev_level | element_hash   |element_balance    | index       |      1        | 1             |  0           | 0
| input_left_hash           | input_left_balance      |input_right_hash|input_right_balance|computed_sum |     0         | 0             |  1           | 0 

When moving to the next level of the tree, the `computed_hash_prev_level` is copied from the `computed_hash` of the previous level. While the `computed_sum_prev_level` is copied from the `computed_sum` at the previous level.

After the last level of the tree is being computed:

| a                         | b                       | c              |    d              |   e         | bool_selector | swap_selector | sum_selector | lt_selector
| --                        | -                       | --             |   ---             |  ---        |  --           | ---           |  ---         | ---
| computed_sum              | total_assets            | check (=1)     |              -    | -           |      0        | 0             |  0           | 1

It copies the computed sum from the previous row. It also copies the `total_assets` from the instance. It sets the check to be equal to 1. By enabling the lt_selector, it activates the lt chip and verifies that the `computed_sum` is less than `total_assets`

Furthermore, the chip contains four permutation check:

- Verfies that the `leaf_hash` is equal to the `leaf_hash` passed as (public) value to the instance column
- Verfies that the `leaf_balance` is equal to the `leaf_balance` passed as (public) value to the instance column
- Verifies that the last `computed_hash` is equal to the (expected) `root` of the tree which is passed as (public) value to the instance column
- Verifies that the last `computed_sum` is equal to the (expected) `balance_sum` of the tree which is passed as (public) value to the instance column

## Benchmarking 

The benchmarking included the following areas:

- Merkle Sum Tree Generation 
- Verification Key Gen
- Proving Key Gen
- ZK Proof Generation
- ZK Proof Verification

In order to run the benchmarking, we provide a set of dummy `username, balance` entries formatted in csv files. The csv files can be downloaded as follows 

``` 
cd benches/csv
wget https://csv-files-summa.s3.eu-west-1.amazonaws.com/csv/csv_files.zip
unzip csv_files.zip
```

The csv folder will contain files named as `entry_2_4.csv` to `entry_2_27.csv`. 2^4 or 2^27 is the number of entries in the file that will be used to feed the merkle sum tree and, eventually, the zk prover.

To run the benches 

`cargo bench` 

Note that by default the function will run the benchmarking for all the csv files from the power of 2 until the power of 27. You can change the range of the benchmarking by changing the `MIN_POWER` and `MAX_POWER` constants inside the `benches/full_solvency_flow.rs` file.
