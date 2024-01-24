// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Verifier {
    uint256 internal constant  TOTAL_PROOF_LEN_CPTR = 0x64;
    uint256 internal constant      SNARK_PROOF_CPTR = 0x84;
    uint256 internal constant        PROOF_LEN_CPTR = 0x1584;
    uint256 internal constant            PROOF_CPTR = 0x1604;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x0ac4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x0b44;

    uint256 internal constant                VK_MPTR = 0x09a0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x09a0;
    uint256 internal constant                 K_MPTR = 0x09c0;
    uint256 internal constant             N_INV_MPTR = 0x09e0;
    uint256 internal constant             OMEGA_MPTR = 0x0a00;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0a20;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0a40;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x0a60;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0a80;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x0aa0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x0ac0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x0ae0;
    uint256 internal constant              G1_X_MPTR = 0x0b00;
    uint256 internal constant              G1_Y_MPTR = 0x0b20;
    uint256 internal constant            G2_X_1_MPTR = 0x0b40;
    uint256 internal constant            G2_X_2_MPTR = 0x0b60;
    uint256 internal constant            G2_Y_1_MPTR = 0x0b80;
    uint256 internal constant            G2_Y_2_MPTR = 0x0ba0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x0bc0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x0be0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0c00;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0c20;

    uint256 internal constant THETA_MPTR = 0x0f00;
    uint256 internal constant  BETA_MPTR = 0x0f20;
    uint256 internal constant GAMMA_MPTR = 0x0f40;
    uint256 internal constant     Y_MPTR = 0x0f60;
    uint256 internal constant     X_MPTR = 0x0f80;
    uint256 internal constant  ZETA_MPTR = 0x0fa0;
    uint256 internal constant    NU_MPTR = 0x0fc0;
    uint256 internal constant    MU_MPTR = 0x0fe0;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1000;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x1020;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x1040;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x1060;
    uint256 internal constant             X_N_MPTR = 0x1080;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x10a0;
    uint256 internal constant          L_LAST_MPTR = 0x10c0;
    uint256 internal constant         L_BLIND_MPTR = 0x10e0;
    uint256 internal constant             L_0_MPTR = 0x1100;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x1120;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x1140;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x1160;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1180;
    uint256 internal constant          R_EVAL_MPTR = 0x11a0;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x11c0;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x11e0;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1200;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x1220;

    function verifyProof(
        address vk,
        bytes calldata proof,
        uint256[] calldata instances
    ) public view returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
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

            {
                // Copy vk into memory
                extcodecopy(vk, VK_MPTR, 0x00, 0x0560)

                // Check valid length of proof
                success := and(success, eq(0x1600, calldataload(TOTAL_PROOF_LEN_CPTR)))
                if iszero(success) {
                    mstore(0, "Invalid proof length")
                    revert(0, 0x20)
                }
                // Check valid length of snark proof
                success := and(success, eq(0xe0, calldataload(PROOF_LEN_CPTR)))
                if iszero(success) {
                    mstore(0, "Invalid snark proof length")
                    revert(0, 0x20)
                }
            }

            // TODO: implement verify proof of advice polynomial openings

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}
