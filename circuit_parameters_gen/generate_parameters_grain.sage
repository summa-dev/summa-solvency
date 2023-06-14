# Credit: https://github.com/daira/pasta-hadeshash/blob/master/code/generate_parameters_grain.sage
#!/usr/bin/env sage

# Remark: This script contains functionality for GF(2^n), but currently works only over GF(p)! A few small adaptations are needed for GF(2^n).
from sage.rings.polynomial.polynomial_gf2x import GF2X_BuildIrred_list

# Note that R_P is increased to the closest multiple of t
# GF(p), alpha=3, N = 1536, n = 64, t = 24, R_F = 8, R_P = 42: sage generate_parameters_grain.sage 1 0 64 24 8 42 0xfffffffffffffeff
# GF(p), alpha=5, N = 1524, n = 254, t = 6, R_F = 8, R_P = 60: sage generate_parameters_grain.sage 1 0 254 6 8 60 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
# GF(p), x^(-1), N = 1518, n = 253, t = 6, R_F = 8, R_P = 60: sage generate_parameters_grain.sage 1 1 253 6 8 60 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed

# GF(p), alpha=5, N = 765, n = 255, t = 3, R_F = 8, R_P = 57: sage generate_parameters_grain.sage 1 0 255 3 8 57 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
# GF(p), alpha=5, N = 1275, n = 255, t = 5, R_F = 8, R_P = 60: sage generate_parameters_grain.sage 1 0 255 5 8 60 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
# GF(p), alpha=5, N = 762, n = 254, t = 3, R_F = 8, R_P = 57: sage generate_parameters_grain.sage 1 0 254 3 8 57 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
# GF(p), alpha=5, N = 1270, n = 254, t = 5, R_F = 8, R_P = 60: sage generate_parameters_grain.sage 1 0 254 5 8 60 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

FIELD = None
SBOX = None
FIELD_SIZE = None
NUM_CELLS = None
R_F_FIXED = None
R_P_FIXED = None
PRIME_NUMBER = None
F = None
INIT_SEQUENCE = None

def grain_sr_generator():
    bit_sequence = INIT_SEQUENCE
    for _ in range(0, 160):
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        
    while True:
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        while new_bit == 0:
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        yield new_bit
grain_gen = grain_sr_generator()
        
def grain_random_bits(num_bits):
    random_bits = [next(grain_gen) for i in range(0, num_bits)]
    # random_bits.reverse() ## Remove comment to start from least significant bit
    random_int = int("".join(str(i) for i in random_bits), 2)
    return random_int

def init_generator(field, sbox, n, t, R_F, R_P):
    # Generate initial sequence based on parameters
    bit_list_field = [_ for _ in (bin(FIELD)[2:].zfill(2))]
    bit_list_sbox = [_ for _ in (bin(SBOX)[2:].zfill(4))]
    bit_list_n = [_ for _ in (bin(FIELD_SIZE)[2:].zfill(12))]
    bit_list_t = [_ for _ in (bin(NUM_CELLS)[2:].zfill(12))]
    bit_list_R_F = [_ for _ in (bin(R_F)[2:].zfill(10))]
    bit_list_R_P = [_ for _ in (bin(R_P)[2:].zfill(10))]
    bit_list_1 = [1] * 30
    global INIT_SEQUENCE
    INIT_SEQUENCE = bit_list_field + bit_list_sbox + bit_list_n + bit_list_t + bit_list_R_F + bit_list_R_P + bit_list_1
    INIT_SEQUENCE = [int(_) for _ in INIT_SEQUENCE]

def generate_constants(field, n, t, R_F, R_P, prime_number):
    round_constants = []
    num_constants = (R_F + R_P) * t

    if field == 0:
        for i in range(0, num_constants):
            random_int = grain_random_bits(n)
            round_constants.append(random_int)
    elif field == 1:
        for i in range(0, num_constants):
            random_int = grain_random_bits(n)
            while random_int >= prime_number:
                # print("[Info] Round constant is not in prime field! Taking next one.")
                random_int = grain_random_bits(n)
            round_constants.append(random_int)
    return round_constants

def print_hex(c, last, rust=False):
    c = int(c)
    hex_str = ""
    if rust:
        hex_str += "        Fp::from_raw([\n"
        for i in range(0, FIELD_SIZE, 64):
            hex_str += "            0x%04x_%04x_%04x_%04x,\n" % tuple([(c >> j) & 0xFFFF for j in range(i+48, i-1, -16)])
        hex_str += "        ]),\n"
    else:
        hex_length = (FIELD_SIZE + 3)//4 + 2 # +2 for "0x"
        hex_str += "{0:#0{1}x}".format(c, hex_length) + ("" if last else ", ")
    return hex_str

def print_round_constants(round_constants, n, t, field, R_F, R_P, rust=False, file_name="./../src/chips/poseidon/poseidon_params.rs"):
    num_round_constants = len(round_constants)
    assert num_round_constants % t == 0
    rounds = num_round_constants // t  # R_F + R_P
    with open(file_name, 'w') as f:
        f.write("//! This file was generated by running generate_params.py\n")
        f.write("//! Number of round constants: {}\n".format(num_round_constants))

        if field == 0:
            f.write("//! Round constants for GF(2^n):\n")
        elif field == 1:
            f.write("//! Round constants for GF(p):\n")
        if rust:
            f.write("//! Parameters for using rate {} Poseidon with the BN256 field.\n".format(t - 1))
            f.write("//! Patterned after [halo2_gadgets::poseidon::primitives::fp]\n")
            f.write("//! The parameters can be reproduced by running the following Sage script from\n")
            f.write("//! [this repository](https://github.com/daira/pasta-hadeshash):\n")
            f.write("//!\n//! ```text\n//! $ sage generate_parameters_grain.sage 1 0 254 {} {} {} 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 --rust\n//! ```\n//!\n".format(t, R_F, R_P))
            f.write("//! where 1 means 'prime field', 0 means 'non-negative sbox', 254 is the bitsize\n//! of the field, {} is the Poseidon width (rate + 1), {} is the number of full\n//! rounds, {} is the number of partial rounds.\n//! More info here => https://hackmd.io/@letargicus/SJOvx48Nn\n".format(t, R_F, R_P))
            f.write("use halo2_proofs::halo2curves::bn256::Fr as Fp;\n")
            f.write("pub(crate) const ROUND_CONSTANTS: [[Fp; {}]; {}] = [\n".format(t, rounds))
        
        for r in range(rounds):
            f.write("    [\n" if rust else "    [")
            for (i, entry) in enumerate(round_constants[r*t : (r+1)*t]):
                f.write(print_hex(entry, i == t-1, rust=rust))
            f.write("    ],\n" if rust else "],\n")
        if rust:
            f.write("];\n")

def create_mds_p(n, t):
    M = matrix(F, t, t)

    # Sample random distinct indices and assign to xs and ys
    while True:
        flag = True
        rand_list = [F(grain_random_bits(n)) for _ in range(0, 2*t)]
        while len(rand_list) != len(set(rand_list)): # Check for duplicates
            rand_list = [F(grain_random_bits(n)) for _ in range(0, 2*t)]
        xs = rand_list[:t]
        ys = rand_list[t:]
        # xs = [F(ele) for ele in range(0, t)]
        # ys = [F(ele) for ele in range(t, 2*t)]
        for i in range(0, t):
            for j in range(0, t):
                if (flag == False) or ((xs[i] + ys[j]) == 0):
                    flag = False
                else:
                    entry = (xs[i] + ys[j])^(-1)
                    M[i, j] = entry
        if flag == False:
            continue
        return M

def generate_vectorspace(round_num, M, M_round, NUM_CELLS):
    t = NUM_CELLS
    s = 1
    V = VectorSpace(F, t)
    if round_num == 0:
        return V
    elif round_num == 1:
        return V.subspace(V.basis()[s:])
    else:
        mat_temp = matrix(F)
        for i in range(0, round_num-1):
            add_rows = []
            for j in range(0, s):
                add_rows.append(M_round[i].rows()[j][s:])
            mat_temp = matrix(mat_temp.rows() + add_rows)
        r_k = mat_temp.right_kernel()
        extended_basis_vectors = []
        for vec in r_k.basis():
            extended_basis_vectors.append(vector([0]*s + list(vec)))
        S = V.subspace(extended_basis_vectors)

        return S

def subspace_times_matrix(subspace, M, NUM_CELLS):
    t = NUM_CELLS
    V = VectorSpace(F, t)
    subspace_basis = subspace.basis()
    new_basis = []
    for vec in subspace_basis:
        new_basis.append(M * vec)
    new_subspace = V.subspace(new_basis)
    return new_subspace

# Returns True if the matrix is considered secure, False otherwise
def algorithm_1(M, NUM_CELLS):
    t = NUM_CELLS
    s = 1
    r = floor((t - s) / float(s))

    # Generate round matrices
    M_round = []
    for j in range(0, t+1):
        M_round.append(M^(j+1))

    for i in range(1, r+1):
        mat_test = M^i
        entry = mat_test[0, 0]
        mat_target = matrix.circulant(vector([entry] + ([F(0)] * (t-1))))

        if (mat_test - mat_target) == matrix.circulant(vector([F(0)] * (t))):
            return [False, 1]

        S = generate_vectorspace(i, M, M_round, t)
        V = VectorSpace(F, t)

        basis_vectors= []
        for eigenspace in mat_test.eigenspaces_right(format='galois'):
            if (eigenspace[0] not in F):
                continue
            vector_subspace = eigenspace[1]
            intersection = S.intersection(vector_subspace)
            basis_vectors += intersection.basis()
        IS = V.subspace(basis_vectors)

        if IS.dimension() >= 1 and IS != V:
            return [False, 2]
        for j in range(1, i+1):
            S_mat_mul = subspace_times_matrix(S, M^j, t)
            if S == S_mat_mul:
                print("S.basis():\n", S.basis())
                return [False, 3]

    return [True, 0]

# Returns True if the matrix is considered secure, False otherwise
def algorithm_2(M, NUM_CELLS):
    t = NUM_CELLS
    s = 1

    V = VectorSpace(F, t)
    trail = [None, None]
    test_next = False
    I = range(0, s)
    I_powerset = list(sage.misc.misc.powerset(I))[1:]
    for I_s in I_powerset:
        test_next = False
        new_basis = []
        for l in I_s:
            new_basis.append(V.basis()[l])
        IS = V.subspace(new_basis)
        for i in range(s, t):
            new_basis.append(V.basis()[i])
        full_iota_space = V.subspace(new_basis)
        for l in I_s:
            v = V.basis()[l]
            while True:
                delta = IS.dimension()
                v = M * v
                IS = V.subspace(IS.basis() + [v])
                if IS.dimension() == t or IS.intersection(full_iota_space) != IS:
                    test_next = True
                    break
                if IS.dimension() <= delta:
                    break
            if test_next == True:
                break
        if test_next == True:
            continue
        return [False, [IS, I_s]]

    return [True, None]

# Returns True if the matrix is considered secure, False otherwise
def algorithm_3(M, NUM_CELLS):
    t = NUM_CELLS
    s = 1

    V = VectorSpace(F, t)

    l = 4*t
    for r in range(2, l+1):
        next_r = False
        res_alg_2 = algorithm_2(M^r, t)
        if res_alg_2[0] == False:
            return [False, None]

        # if res_alg_2[1] == None:
        #     continue
        # IS = res_alg_2[1][0]
        # I_s = res_alg_2[1][1]
        # for j in range(1, r):
        #     IS = subspace_times_matrix(IS, M, t)
        #     I_j = []
        #     for i in range(0, s):
        #         new_basis = []
        #         for k in range(0, t):
        #             if k != i:
        #                 new_basis.append(V.basis()[k])
        #         iota_space = V.subspace(new_basis)
        #         if IS.intersection(iota_space) != iota_space:
        #             single_iota_space = V.subspace([V.basis()[i]])
        #             if IS.intersection(single_iota_space) == single_iota_space:
        #                 I_j.append(i)
        #             else:
        #                 next_r = True
        #                 break
        #     if next_r == True:
        #         break
        # if next_r == True:
        #     continue
        # return [False, [IS, I_j, r]]
    
    return [True, None]

def generate_matrix(FIELD, FIELD_SIZE, NUM_CELLS):
    if FIELD == 0:
        print("Matrix generation not implemented for GF(2^n).")
        exit(1)
    elif FIELD == 1:
        mds_matrix = create_mds_p(FIELD_SIZE, NUM_CELLS)
        result_1 = algorithm_1(mds_matrix, NUM_CELLS)
        result_2 = algorithm_2(mds_matrix, NUM_CELLS)
        result_3 = algorithm_3(mds_matrix, NUM_CELLS)
        while result_1[0] == False or result_2[0] == False or result_3[0] == False:
            mds_matrix = create_mds_p(FIELD_SIZE, NUM_CELLS)
            result_1 = algorithm_1(mds_matrix, NUM_CELLS)
            result_2 = algorithm_2(mds_matrix, NUM_CELLS)
            result_3 = algorithm_3(mds_matrix, NUM_CELLS)
        return mds_matrix

def invert_matrix(M):
    MS = MatrixSpace(F, NUM_CELLS, NUM_CELLS, sparse=False)
    return MS.matrix(M).inverse()

def print_matrix(M, t, rust=False, file_name="./../src/chips/poseidon/poseidon_params.rs"):
    # 'a' for append mode
    with open(file_name, 'a') as f:
        for row in range(t):
            f.write("    [\n" if rust else "")
            for (i, entry) in enumerate(M[row]):
                f.write(print_hex(entry, i == t-1, rust=rust))
            f.write("    ]," if rust else "],")
        f.write("\n];\n")

def print_linear_layer(M, n, t, rust=False, file_name="./../src/chips/poseidon/poseidon_params.rs"):
    # 'a' for append mode
    with open(file_name, 'a') as f:
        f.write("// n: {}\n".format(n))
        f.write("// t: {}\n".format(t))
        f.write("// N: {}\n".format(n * t))
        f.write("// Result Algorithm 1:\n")
        f.write("// {}\n".format(algorithm_1(M, NUM_CELLS)))
        f.write("// Result Algorithm 2:\n")
        f.write("// {}\n".format(algorithm_2(M, NUM_CELLS)))
        f.write("// Result Algorithm 3:\n")
        f.write("// {}\n".format(algorithm_3(M, NUM_CELLS)))
        f.write("// Prime number: {}\n".format("0x" + hex(PRIME_NUMBER)))
        
        f.write("// MDS matrix:\n")
        f.write("pub(crate) const MDS: [[Fp; {}]; {}] = [\n".format(t, t) if rust else "")

    print_matrix(M, t, rust=rust, file_name=file_name)

    with open(file_name, 'a') as f:
        f.write("// Inverse MDS matrix:\n")
        f.write("pub(crate) const MDS_INV: [[Fp; {}]; {}] = [\n".format(t, t) if rust else "")

    print_matrix(invert_matrix(M), t, rust=rust, file_name=file_name)
    
def main(args):
    if len(args) < 7:
        print("Usage: sage generate_parameters_grain.sage <field> <s_box> <field_size> <num_cells> <R_F> <R_P> (<prime_number_hex>) <filename> [--rust]")
        print("field = 1 for GF(p)")
        print("s_box = 0 for x^alpha, s_box = 1 for x^(-1)")
        return

    # Parameters
    global FIELD, SBOX, FIELD_SIZE, NUM_CELLS, R_F_FIXED, R_P_FIXED, PRIME_NUMBER, F

    FIELD = int(args[0]) # 0 .. GF(2^n), 1 .. GF(p)
    SBOX = int(args[1]) # 0 .. x^alpha, 1 .. x^(-1)
    FIELD_SIZE = int(args[2]) # n
    NUM_CELLS = int(args[3]) # t
    R_F_FIXED = int(args[4])
    R_P_FIXED = int(args[5])

    PRIME_NUMBER = 0
    if FIELD == 0:
        args = args[6:]
    elif FIELD == 1 and len(args) < 7:
        print("Please specify a prime number (in hex format)!")
        return
    elif FIELD == 1 and len(args) >= 7:
        PRIME_NUMBER = int(args[6], 16) # e.g. 0xa7, 0xFFFFFFFFFFFFFEFF, 0xa1a42c3efd6dbfe08daa6041b36322ef
        args = args[7:]

    F = GF(PRIME_NUMBER)

    file_name = args[0]
    rust = '--rust' in args

    # Init
    init_generator(FIELD, SBOX, FIELD_SIZE, NUM_CELLS, R_F_FIXED, R_P_FIXED)

    # Round constants
    round_constants = generate_constants(FIELD, FIELD_SIZE, NUM_CELLS, R_F_FIXED, R_P_FIXED, PRIME_NUMBER)
    print_round_constants(round_constants, FIELD_SIZE, NUM_CELLS, FIELD, R_F_FIXED, R_P_FIXED, rust=rust, file_name=file_name)

    # Matrix
    linear_layer = generate_matrix(FIELD, FIELD_SIZE, NUM_CELLS)
    print_linear_layer(linear_layer, FIELD_SIZE, NUM_CELLS, rust=rust, file_name=file_name)

if __name__ == "__main__":
    main(sys.argv[1:])