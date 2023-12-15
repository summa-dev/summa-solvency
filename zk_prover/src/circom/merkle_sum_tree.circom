pragma circom 2.0.3;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/mux1.circom";

/*
Inputs:
---------
- left_balances[N_CURRENCIES] : Balances of the left node
- right_balances[N_CURRENCIES] : Balances of the right node

Outputs:
---------
- out_balances[N_CURRENCIES] : Each element of `out_balances` is the sum of the corresponding elements in left_balances and right_balances. 
Ex. out_balances[0] = left_balances[0] + right_balances[0]

Functionality:
--------------
1. Constraint each input balance to be within the range [0, N_BYTES]
2. Perform the summation of two balances

Notes:
------
- The range check is performed only on the input of the summation. The range check on the output of the summation will be performed in the next level of the tree. 
When the output will be used as an input to another summation. When the next level is the root, the range check is performed outside of the Summer template

*/  

template Summer(N_CURRENCIES, N_BYTES) {
    signal input left_balances[N_CURRENCIES];
    signal input right_balances[N_CURRENCIES];
    signal output out_balances[N_CURRENCIES];

    component left_in_range[N_CURRENCIES];
    component right_in_range[N_CURRENCIES];

    for (var i = 0; i < N_CURRENCIES; i++) {
        left_in_range[i] = Num2Bits(8*N_BYTES);
        right_in_range[i] = Num2Bits(8*N_BYTES);

        left_in_range[i].in <== left_balances[i];
        right_in_range[i].in <== right_balances[i];

        out_balances[i] <== left_balances[i] + right_balances[i];
    }
}

/*
Inputs:
---------
- left_hash: Hash of the left node
- left_balances[N_CURRENCIES] : Balances of the left node
- right_hash: Hash of the right node
- right_balances[N_CURRENCIES] : Balances of the right node
- s: binary selector

Outputs:
---------
- swapped_left_hash: left_hash if s = 0, right_hash if s = 1
- swapped_left_balances[N_CURRENCIES]: left_balances if s = 0, right_balances if s = 1
- swapped_right_hash: right_hash if s = 0, left_hash if s = 1
- swapped_right_balances[N_CURRENCIES]: right_balances if s = 0, left_balances if s = 1

Parameters:
------------
- N_CURRENCIES: number of currencies for each user

Functionality:
--------------
1. Perform the swapping of two nodes belonging to a level of the merkle sum tree according to the binary selector s
2. Constraint that s is either 0 or 1
*/

template Swapper(N_CURRENCIES) {
    signal input left_hash;
    signal input left_balances[N_CURRENCIES];
    signal input right_hash;
    signal input right_balances[N_CURRENCIES];
    signal input s;
    signal output swapped_left_hash;
    signal output swapped_left_balances[N_CURRENCIES];
    signal output swapped_right_hash;
    signal output swapped_right_balances[N_CURRENCIES];

    s * (1 - s) === 0;

    component mux = MultiMux1(2 + 2*N_CURRENCIES);
    
    mux.c[0][0] <== left_hash;

    for (var i = 0; i < N_CURRENCIES; i++) {
        mux.c[1 + i][0] <== left_balances[i];
    }

    mux.c[1 + N_CURRENCIES][0] <== right_hash;

    for (var i = 0; i < N_CURRENCIES; i++) {
        mux.c[2 + N_CURRENCIES + i][0] <== right_balances[i];
    }

    mux.c[0][1] <== right_hash;

    for (var i = 0; i < N_CURRENCIES; i++) {
        mux.c[1 + i][1] <== right_balances[i];
    }

    mux.c[1 + N_CURRENCIES][1] <== left_hash;

    for (var i = 0; i < N_CURRENCIES; i++) {
        mux.c[2 + N_CURRENCIES + i][1] <== left_balances[i];
    }

    mux.s <== s;

    swapped_left_hash <== mux.out[0];

    for (var i = 0; i < N_CURRENCIES; i++) {
        swapped_left_balances[i] <== mux.out[1 + i];
    }

    swapped_right_hash <== mux.out[1 + N_CURRENCIES];

    for (var i = 0; i < N_CURRENCIES; i++) {
        swapped_right_balances[i] <== mux.out[2 + N_CURRENCIES + i];
    }
}

/*
Inputs:
---------
- left_hash: Hash of the left node
- left_balances[N_CURRENCIES] : Balances of the left node
- right_hash: Hash of the right node
- right_balances[N_CURRENCIES] : Balances of the right node

Outputs:
---------
- hash: poseidon hash of (left_hash, left_balances[0], ..., left_balances[N_CURRENCIES - 1], right_hash, right_balances[0], ..., right_balances[N_CURRENCIES - 1])

Parameters:
------------
- N_CURRENCIES: number of currencies for each user

Functionality:
--------------
1. Perform the hashing of two nodes belonging to a level of the merkle sum tree
*/

template Hasher(N_CURRENCIES) {
    signal input left_hash;
    signal input left_balances[N_CURRENCIES];
    signal input right_hash;
    signal input right_balances[N_CURRENCIES];
    signal output hash;

    // 1.
    component hasher = Poseidon(2 + 2*N_CURRENCIES);

    hasher.inputs[0] <== left_hash;

    for (var i = 0; i < N_CURRENCIES; i++) {
        hasher.inputs[1 + i] <== left_balances[i];
    }

    hasher.inputs[1 + N_CURRENCIES] <== right_hash;

    for (var i = 0; i < N_CURRENCIES; i++) {
        hasher.inputs[2 + N_CURRENCIES + i] <== right_balances[i];
    }

    hash <== hasher.out;
}


/*
Inputs:
---------
- leaf_hash: hash of the leaf node that we want to prove inclusion for
- leaf_balances[N_CURRENCIES]: balances of the leaf node that we want to prove inclusion for
- path_element_hashes[LEVELS]: hashes of elements of the merkle path
- path_element_balances[LEVELS][N_CURRENCIES]: balances of the elements of the merkle path
- path_indices[LEVELS]: binary selector that indicates whether given path_element is on the left or right side of merkle path

Outputs:
---------
- root_hash: root hash of the resulting merkle sum tree

Parameters:
------------
- LEVELS: number of levels in the merkle sum tree
- N_CURRENCIES: number of currencies for each user
- N_BYTES: range of the balances of the users

Functionality:
--------------
1. For each level of the tree, perform the summation between the balances of the two nodes
2. For each level of the tree, perform the swapping of the nodes according to the binary selector
3. For each level of the tree, perform the hashing of the two swapped nodes
4. At the latest level, perform the range check on the root balances

Notes:
------
- The summer is performed before the swapper because the swap doesn't influence the summation.
*/
template MerkleSumTreeInclusion(LEVELS, N_CURRENCIES, N_BYTES) {
    signal input leaf_hash;
    signal input leaf_balances[N_CURRENCIES];
    signal input path_element_hashes[LEVELS];
    signal input path_element_balances[LEVELS][N_CURRENCIES];
    signal input path_indices[LEVELS];

    signal output root_hash;

    component summers[LEVELS];
    component swappers[LEVELS];
    component hashers[LEVELS];

    for (var i = 0; i < LEVELS; i++) {
        // 1.
        summers[i] = Summer(N_CURRENCIES, N_BYTES);

        summers[i].left_balances <== i == 0 ? leaf_balances : summers[i - 1].out_balances;
        summers[i].right_balances <== path_element_balances[i];

        // 2.
        swappers[i] = Swapper(N_CURRENCIES);

        swappers[i].left_hash <== i == 0 ? leaf_hash : hashers[i - 1].hash;
        swappers[i].left_balances <== i == 0 ? leaf_balances : summers[i - 1].out_balances;
        swappers[i].right_hash <== path_element_hashes[i];
        swappers[i].right_balances <== path_element_balances[i];
        swappers[i].s <== path_indices[i];

        // 3.
        hashers[i] = Hasher(N_CURRENCIES);

        hashers[i].left_hash <== swappers[i].swapped_left_hash;
        hashers[i].left_balances <== swappers[i].swapped_left_balances;
        hashers[i].right_hash <== swappers[i].swapped_right_hash;
        hashers[i].right_balances <== swappers[i].swapped_right_balances;

    }

    // 4. 
    component root_balance_in_range[N_CURRENCIES];

    for (var i = 0; i < N_CURRENCIES; i++) {
        root_balance_in_range[i] = Num2Bits(8*N_BYTES);
        root_balance_in_range[i].in <== summers[LEVELS - 1].out_balances[i];
    }

    root_hash <== hashers[LEVELS - 1].hash;
}