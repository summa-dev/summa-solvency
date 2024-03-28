// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract GrandSumVerifier {
    // Calldata positions for proofs
    uint256 internal constant       PROOF_LEN_CPTR = 0x64;
    uint256 internal constant           PROOF_CPTR = 0x84;

    // Memory positions for the verifying key.
    // The memory location starts at 0x200 due to the maximum operation on the ec_pairing function being 0x180, marking the maximum memory location used
    uint256 internal constant             N_INV_MPTR = 0x220;
    uint256 internal constant             LHS_X_MPTR = 0x240;
    uint256 internal constant             LHS_Y_MPTR = 0x260;
    uint256 internal constant              G1_X_MPTR = 0x280;
    uint256 internal constant              G1_Y_MPTR = 0x2a0;
    uint256 internal constant            G2_X_1_MPTR = 0x2c0;
    uint256 internal constant            G2_X_2_MPTR = 0x2e0;
    uint256 internal constant            G2_Y_1_MPTR = 0x300;
    uint256 internal constant            G2_Y_2_MPTR = 0x320;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x340;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x360;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x380;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x3a0;



    function verifyProof(
        address vk,
        bytes calldata proof,
        uint256[] calldata values
    ) public returns (bool) {
        assembly {
            // Check if EC point (x, y) is on the curve.
            // if the point is on the affine plane, it then returns updated (success).
            function check_ec_point(success, proof_cptr, q) -> ret {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret := and(success, lt(x, q))
                ret := and(ret, lt(y, q))
                ret := and(ret, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            // Copy part of the verifying key contract into memory.
            extcodecopy(vk, N_INV_MPTR, 0x40, 0x020)
            // The address 0x02a0(= 0x160 + 0x140) indicates the memory location to which `neg_s_g2` points in the verifying key contract
            extcodecopy(vk, G1_X_MPTR, 0x160, 0x140)

            // The proof length should be divisible by `0x80` bytes, equivalent to four words.
            //
            // The proof is structured as follows: 
            //  2W * n: Commitment points in the SNARK proof.
            //  2W * n: Points in the opening proof.
            //  1W    : Length of evaluation values. 
            //  1W * n: Evaluation values.
            //
            // Where W is refers to a Word, which is 32 bytes.
            // And 'n' denotes the number of commitments as well as the number of evaluation values.
            let proof_length := calldataload(PROOF_LEN_CPTR)

            // Ensure the proof length is divisible by `0x80`, accommodating the structured data layout.
            success := and(success, eq(0, mod(proof_length, 0x80)))
            if iszero(success) {
                mstore(0, "Invalid proof length")
                revert(0, 0x20)
            }

            // Load the length of evaluation values, positioned after the proof data.
            let evaluation_values_length_pos := add(add(PROOF_LEN_CPTR, proof_length), 0x20)
            let evaluation_values_length := calldataload(evaluation_values_length_pos)
            
            // The proof length should match 4 times the length of the evaluation values.
            success := and(success, eq(4, div(proof_length, mul(evaluation_values_length, 0x20))))
            if iszero(success) {
                mstore(0, "Number of evaluation mismatch")
                revert(0, 0x20)
            }

            for { let i := 0 } lt(i, evaluation_values_length) { i := add(i, 1) } {
                let shift_pos := mul(i, 0x20)
                let double_shift_pos := mul(shift_pos, 2) // for next point
                let total_balance := calldataload(add(evaluation_values_length_pos, add(shift_pos, 0x20)))

                // The `z` is evaluated with 'total_balance' multiply by `N_INV`
                // The `N_INV` is equivalent to `Fp::from(poly_length).invert().unwrap()` as input on the `open_grand_sums` function in Rust implementation.
                let z := mulmod(total_balance, mload(N_INV_MPTR), r)
                let minus_z := sub(r, z)

                // Assign values on memory for multiplication
                mstore(0x80, mload(G1_X_MPTR))
                mstore(0xa0, mload(G1_Y_MPTR))
                success := and(success, ec_mul_tmp(success, minus_z))
                
                // Performaing `c_g_to_minus_z := c + g_to_minus_z`
                // `c` is equivalent to `commitment` as input on the `open_grand_sums` function.
                // the values of 'g_to_minus_z` is already located at 0x80 and 0xa0 in the previous step 
                let commitment_proof_pos := add(add(PROOF_CPTR, div(proof_length, 2)), double_shift_pos)
                success := check_ec_point(success, commitment_proof_pos, q)

                let lhs_x := calldataload(commitment_proof_pos)            // C_X
                let lhs_y := calldataload(add(commitment_proof_pos, 0x20)) // C_Y
                success := ec_add_tmp(success, lhs_x, lhs_y)

                // Store LHS_X and LHS_Y to memory
                mstore(LHS_X_MPTR, mload(0x80))
                mstore(LHS_Y_MPTR, mload(0xa0))

                // Checking from calldata for grand sum proof
                let proof_pos := add(PROOF_CPTR, double_shift_pos)
                success := check_ec_point(success, proof_pos, q)

                let rhs_x := calldataload(proof_pos) // PI_X
                let rhs_y := calldataload(add(proof_pos, 0x20)) // PI_Y
                success := and(success, ec_pairing(success, mload(LHS_X_MPTR), mload(LHS_Y_MPTR), rhs_x, rhs_y))
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, success)
            return(0x00, 0x20)
        }
    }
}
