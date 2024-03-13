// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(0x0000, 0x1cf97aa0b615d06f7fde34ae5bc74ff9cacc8143a00eaf0e6b24673afa484eb3) // vk_digest
            mstore(0x0020, 0x0000000000000000000000000000000000000000000000000000000000000011) // k
            mstore(0x0040, 0x30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801) // n_inv
            mstore(0x0060, 0x304cd1e79cfa5b0f054e981a27ed7706e7ea6b06a7f266ef8db819c179c2c3ea) // omega
            mstore(0x0080, 0x193586da872cdeff023d6ab2263a131b4780db8878be3c3b7f8f019c06fcb0fb) // omega_inv
            mstore(0x00a0, 0x299110e6835fd73731fb3ce6de87151988da403c265467a96b9cda0d7daa72e4) // omega_inv_to_l
            mstore(0x00c0, 0x0000000000000000000000000000000000000000000000000000000000000001) // num_instances
            mstore(0x00e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
            mstore(0x0100, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
            mstore(0x0120, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
            mstore(0x0140, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
            mstore(0x0160, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
            mstore(0x0180, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
            mstore(0x01a0, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
            mstore(0x01c0, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
            mstore(0x01e0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
            mstore(0x0200, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
            mstore(0x0220, 0x26186a2d65ee4d2f9c9a5b91f86597d35f192cd120caf7e935d8443d1938e23d) // neg_s_g2_x_1
            mstore(0x0240, 0x30441fd1b5d3370482c42152a8899027716989a6996c2535bc9f7fee8aaef79e) // neg_s_g2_x_2
            mstore(0x0260, 0x16f363f103c80d7bbc8ad3c6867e0822bbc6000be91a4689755c7df40221c145) // neg_s_g2_y_1
            mstore(0x0280, 0x2b1cbb3e521edf5a622d82762a44a5e63f1e50b332d71154a4a7958d6011deff) // neg_s_g2_y_2
            mstore(0x02a0, 0x1404a2d17cd02c8f9fd79d74ac73c67d1881e62c6af354fa74d235c5e37dacfe) // fixed_comms[0].x
            mstore(0x02c0, 0x2c1e30781f735e7977820d4ca9145010e28dcc808ee0f1e976477289057b7aec) // fixed_comms[0].y
            mstore(0x02e0, 0x2dd3fd59098a5b4b4a616568bb6ba1a1e4c40e4b0df9ae94e37944d55ab651cf) // permutation_comms[0].x
            mstore(0x0300, 0x25680c3525ba04435a9034d6e69c96de5133edfe37c226d3e31b60eff6b34ef0) // permutation_comms[0].y
            mstore(0x0320, 0x0fd3d99b713606a4c586c6d187477c5eb79a43f78c7d8424a67be4ce624fa6af) // permutation_comms[1].x
            mstore(0x0340, 0x20af9ec4f24f0568465c7f138f69fac5e917ba5f669550cae7977fcde9fc657d) // permutation_comms[1].y
            mstore(0x0360, 0x27a7a66087a8c17b00ffb7fe9b76ba2199ca308bcb0ad100fa181886d6c9b936) // permutation_comms[2].x
            mstore(0x0380, 0x23bc951a3c4307384bdec5d61be122a19c933db3266d6327a472e5203a9f785a) // permutation_comms[2].y
            mstore(0x03a0, 0x0743ea40f14084db2673217283aa053f986896ee7c181f52118442e99c452974) // permutation_comms[3].x
            mstore(0x03c0, 0x0203e3493a2594ece57d22cc75dd081ac68271ec7c758153cfd2152bfb5c19e3) // permutation_comms[3].y
            mstore(0x03e0, 0x0f85936c44708409e3e9fb5e2a7ea6604b06997f0ac7fd488e3f147e05a88dbe) // permutation_comms[4].x
            mstore(0x0400, 0x0497fbb7c4436dcf36ede6a30ad62e016e059a11a6548eb6980edeb2f1052133) // permutation_comms[4].y
            mstore(0x0420, 0x1ec1a20141b6698f374aada55f23b891e4c6f6504cdcdec40c5ec89f326b8640) // permutation_comms[5].x
            mstore(0x0440, 0x108ee8c0651cead83eb9e988873c5b62a74fe0775d0464fcca86c0ac61b9b92e) // permutation_comms[5].y
            mstore(0x0460, 0x101b50c385e07bb24f828dee5eba4619413bb28ee278c03901a58a8b58f90ab8) // permutation_comms[6].x
            mstore(0x0480, 0x11dbc30794b04c6fc1c68c59556fd092bb59479bc6cc8cb4879d961a6b2dfa94) // permutation_comms[6].y
            mstore(0x04a0, 0x1c517c335ad634422ef2eb5f615926e875afa9e9c589abf528d315a8a586b22d) // permutation_comms[7].x
            mstore(0x04c0, 0x1220b1b13c91e8115106144bc417d4d3e6a9de3fb70406e68b4a5fd8a92f4327) // permutation_comms[7].y
            mstore(0x04e0, 0x0cbaead666e172b1801b7ad17c3450ea2ce7d53c1e392cedf05023e59e53c95a) // permutation_comms[8].x
            mstore(0x0500, 0x0ce200ab515efc390c459e0b492c15a50024c57fa70768c18389924e1e72982b) // permutation_comms[8].y
            mstore(0x0520, 0x0f09c585dc376dd0d5962c76ae444dc1cc3de9780f4fbdd5105a7040500d60ba) // permutation_comms[9].x
            mstore(0x0540, 0x13587a1e4799ba72f1d95e47a4e377086b83e5189903566e7422119ed28eba59) // permutation_comms[9].y
            mstore(0x0560, 0x1122e985f75fc0589295cbaf54c0da7f36a7f184d83876f0fa9fdc2dbbd715cb) // permutation_comms[10].x
            mstore(0x0580, 0x0da0508aab9cf7c8772ed21fcb6851480f8c3c328b7fb722e3a1cecd0c867e02) // permutation_comms[10].y
            mstore(0x05a0, 0x019e46ed071e9723ab7a68eb3c0d7bbd1df026e4f35acb67cc7cfe269e12deb0) // permutation_comms[11].x
            mstore(0x05c0, 0x1c19aac276e0a65d2c5bb219e9020124a0bf3d3bbaa8758abd2e6d40895923ed) // permutation_comms[11].y

            return(0, 0x05e0)
        }
    }
}