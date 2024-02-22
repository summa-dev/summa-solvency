// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(
                0x0000,
                0x0f4282e55a789d94ea57d4e200623dabb7ea67c998749f0370c890ab9ee6883f
            ) // vk_digest
            mstore(
                0x0020,
                0x0000000000000000000000000000000000000000000000000000000000000011
            ) // k
            mstore(
                0x0040,
                0x30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801
            ) // n_inv
            mstore(
                0x0060,
                0x304cd1e79cfa5b0f054e981a27ed7706e7ea6b06a7f266ef8db819c179c2c3ea
            ) // omega
            mstore(
                0x0080,
                0x193586da872cdeff023d6ab2263a131b4780db8878be3c3b7f8f019c06fcb0fb
            ) // omega_inv
            mstore(
                0x00a0,
                0x299110e6835fd73731fb3ce6de87151988da403c265467a96b9cda0d7daa72e4
            ) // omega_inv_to_l
            mstore(
                0x00c0,
                0x0000000000000000000000000000000000000000000000000000000000000001
            ) // num_instances
            mstore(
                0x00e0,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // has_accumulator
            mstore(
                0x0100,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // acc_offset
            mstore(
                0x0120,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // num_acc_limbs
            mstore(
                0x0140,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // num_acc_limb_bits
            mstore(
                0x0160,
                0x0000000000000000000000000000000000000000000000000000000000000001
            ) // g1_x
            mstore(
                0x0180,
                0x0000000000000000000000000000000000000000000000000000000000000002
            ) // g1_y
            mstore(
                0x01a0,
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            ) // g2_x_1
            mstore(
                0x01c0,
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            ) // g2_x_2
            mstore(
                0x01e0,
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            ) // g2_y_1
            mstore(
                0x0200,
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            ) // g2_y_2
            mstore(
                0x0220,
                0x26186a2d65ee4d2f9c9a5b91f86597d35f192cd120caf7e935d8443d1938e23d
            ) // neg_s_g2_x_1
            mstore(
                0x0240,
                0x30441fd1b5d3370482c42152a8899027716989a6996c2535bc9f7fee8aaef79e
            ) // neg_s_g2_x_2
            mstore(
                0x0260,
                0x16f363f103c80d7bbc8ad3c6867e0822bbc6000be91a4689755c7df40221c145
            ) // neg_s_g2_y_1
            mstore(
                0x0280,
                0x2b1cbb3e521edf5a622d82762a44a5e63f1e50b332d71154a4a7958d6011deff
            ) // neg_s_g2_y_2
            mstore(
                0x02a0,
                0x1404a2d17cd02c8f9fd79d74ac73c67d1881e62c6af354fa74d235c5e37dacfe
            ) // fixed_comms[0].x
            mstore(
                0x02c0,
                0x2c1e30781f735e7977820d4ca9145010e28dcc808ee0f1e976477289057b7aec
            ) // fixed_comms[0].y
            mstore(
                0x02e0,
                0x1b20314062560deca1b1bada262dbe3352a521ea2ef8973476cb7ad6f588c59d
            ) // permutation_comms[0].x
            mstore(
                0x0300,
                0x244ac9f0848be84d5a85e3c4e62e2a371ac7be27d68202ef3fe79541021ab99d
            ) // permutation_comms[0].y
            mstore(
                0x0320,
                0x2b1f7e2148bfab601e68f2e8133b9d05c10a9526d686b356b761eaa3713a70ba
            ) // permutation_comms[1].x
            mstore(
                0x0340,
                0x013345ea09966b06e4ae7d7e2919ddbb6e3f7e645aea515375ed729bff644dc5
            ) // permutation_comms[1].y
            mstore(
                0x0360,
                0x27a7a66087a8c17b00ffb7fe9b76ba2199ca308bcb0ad100fa181886d6c9b936
            ) // permutation_comms[2].x
            mstore(
                0x0380,
                0x23bc951a3c4307384bdec5d61be122a19c933db3266d6327a472e5203a9f785a
            ) // permutation_comms[2].y
            mstore(
                0x03a0,
                0x0743ea40f14084db2673217283aa053f986896ee7c181f52118442e99c452974
            ) // permutation_comms[3].x
            mstore(
                0x03c0,
                0x0203e3493a2594ece57d22cc75dd081ac68271ec7c758153cfd2152bfb5c19e3
            ) // permutation_comms[3].y

            return(0, 0x03e0)
        }
    }
}
