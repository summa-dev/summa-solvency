// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(0x0000, 0x00996ed64113d5d86f42caab0f3d25466b0856015472de4bb809f168aabc2567) // vk_digest
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
            mstore(0x0320, 0x1a224e6aeb9bb7de12c761fd1f49a733ff410c3f772aad6a2ec3c4decad43307) // permutation_comms[1].x
            mstore(0x0340, 0x300a66b376af1187694e25dbcea3aac63114716af822fd4661519adbf9c649e9) // permutation_comms[1].y
            mstore(0x0360, 0x27a7a66087a8c17b00ffb7fe9b76ba2199ca308bcb0ad100fa181886d6c9b936) // permutation_comms[2].x
            mstore(0x0380, 0x23bc951a3c4307384bdec5d61be122a19c933db3266d6327a472e5203a9f785a) // permutation_comms[2].y
            mstore(0x03a0, 0x0743ea40f14084db2673217283aa053f986896ee7c181f52118442e99c452974) // permutation_comms[3].x
            mstore(0x03c0, 0x0203e3493a2594ece57d22cc75dd081ac68271ec7c758153cfd2152bfb5c19e3) // permutation_comms[3].y
            mstore(0x03e0, 0x0f85936c44708409e3e9fb5e2a7ea6604b06997f0ac7fd488e3f147e05a88dbe) // permutation_comms[4].x
            mstore(0x0400, 0x0497fbb7c4436dcf36ede6a30ad62e016e059a11a6548eb6980edeb2f1052133) // permutation_comms[4].y
            mstore(0x0420, 0x0dcbacf368c01f61375c242e35edab12a22147e9d46bf685fb75454d60f5edbc) // permutation_comms[5].x
            mstore(0x0440, 0x17720c95139aa3f5dec5b6bd56082f8deded2e4a1425d0a91e2743dd294fdc9c) // permutation_comms[5].y
            mstore(0x0460, 0x284ac053d96a33fca69eca00e16eea75ad1bf008d2a742fc846ac73d17d46d73) // permutation_comms[6].x
            mstore(0x0480, 0x14f45666a26b8d472186dbf78e606a82891e0f122a54264418cfe2615003dfb9) // permutation_comms[6].y
            mstore(0x04a0, 0x1c517c335ad634422ef2eb5f615926e875afa9e9c589abf528d315a8a586b22d) // permutation_comms[7].x
            mstore(0x04c0, 0x1220b1b13c91e8115106144bc417d4d3e6a9de3fb70406e68b4a5fd8a92f4327) // permutation_comms[7].y
            mstore(0x04e0, 0x0cbaead666e172b1801b7ad17c3450ea2ce7d53c1e392cedf05023e59e53c95a) // permutation_comms[8].x
            mstore(0x0500, 0x0ce200ab515efc390c459e0b492c15a50024c57fa70768c18389924e1e72982b) // permutation_comms[8].y
            mstore(0x0520, 0x1d4848e8db74251fd01e018fedb71ca8e04c41746474ad4b4a39da132f86f30b) // permutation_comms[9].x
            mstore(0x0540, 0x148a2252b7b6a07e21aa1bc5b1cc4826ac7f4a7a3e29fb7399dd7029d4bdaf27) // permutation_comms[9].y

            return(0, 0x0560)
        }
    }
}