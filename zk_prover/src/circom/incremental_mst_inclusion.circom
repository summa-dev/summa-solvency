pragma circom 2.0.3;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./merkle_sum_tree.circom";

/*
Inputs:
---------
- step_in[2] : `user_state_prev` and `liabilities_state_prev` from the previous step of the IVC
- username: username of the user whose inclusion in the merkle sum tree we want to prove
- user_balances[N_CURRENCIES]: balances of the user whose inclusion in the merkle sum tree we want to prove
- path_element_hashes[LEVELS]: hashes of elements of the merkle path
- path_element_balances[LEVELS][N_CURRENCIES]: balances of the elements of the merkle path
- path_indices[LEVELS]: binary selector that indicates whether given path_element is on the left or right side of merkle path

Outputs:
---------
- step_out[2] : `user_state_cur` and `liabilities_state_cur`, namely the resulting states after the IVC step. 
    - `user_state_cur` is equal to H(`user_state_prev`, `leaf_hash`)
    - `liabilities_state_cur` is equal to H(`liabilities_state_prev`, `root_hash`)

Parameters:
------------
- LEVELS: number of levels in the merkle sum tree
- N_CURRENCIES: number of currencies for each user
- N_BYTES: range of the balances of the users

Functionality:
--------------
1. Starting from the username and balances of the user, compute the `leaf_hash`
2. Starting from `user_state_prev` and `leaf_hash`, compute `user_state_cur` as H(`user_state_prev`, `leaf_hash`)
3. Starting from the `leaf_hash` and the Merkle Proof, compute the `root_hash` of the resulting Merkle Sum Tree
4. Starting from `liabilities_state_prev` and `root_hash`, compute `liabilities_state_cur` as H(`liabilities_state_prev`, `root_hash`)
*/
template IncrementalMstInclusion (LEVELS, N_CURRENCIES, N_BYTES) {
    signal input step_in[2];

    signal input username;
    signal input user_balances[N_CURRENCIES];
    signal input path_element_hashes[LEVELS];
    signal input path_element_balances[LEVELS][N_CURRENCIES];
    signal input path_indices[LEVELS];

    signal output step_out[2];

    // 1.
    component build_leaf_hash = Poseidon(1 + N_CURRENCIES);
    build_leaf_hash.inputs[0] <== username;
    for (var i = 0; i < N_CURRENCIES; i++) {
        build_leaf_hash.inputs[i + 1] <== user_balances[i];
    }

    // 2.
    component build_user_state_cur = Poseidon(2);
    build_user_state_cur.inputs[0] <== step_in[0];
    build_user_state_cur.inputs[1] <== build_leaf_hash.out;

    // 3.
    component check_inclusion = MerkleSumTreeInclusion(LEVELS, N_CURRENCIES, N_BYTES);

    check_inclusion.leaf_hash <== build_leaf_hash.out;
    check_inclusion.leaf_balances <== user_balances;
    check_inclusion.path_element_hashes <== path_element_hashes;
    check_inclusion.path_element_balances <== path_element_balances;
    check_inclusion.path_indices <== path_indices;

    // 4.
    component build_liabilities_state_cur = Poseidon(2);
    build_liabilities_state_cur.inputs[0] <== step_in[1];
    build_liabilities_state_cur.inputs[1] <== check_inclusion.root_hash;

    step_out[0] <== build_user_state_cur.out;
    step_out[1] <== build_liabilities_state_cur.out;
}

component main { public [step_in] } = IncrementalMstInclusion(4, 2, 14);

