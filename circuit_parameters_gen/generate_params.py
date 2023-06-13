import os
from calc_round_numbers import get_parameters

# Parameters
p = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001

# First, set the parameters for the Merkle tree leaf hasher
# One hash and num_assets assets per Merkle tree node, plus 1 for the Poseidon "width" parameter
num_assets = 2
t = 7
M = 128

# Call the function and get the parameters
t, M, alpha, security_margin, R_F, R_P, min_sbox_cost, min_size_cost = get_parameters(
    p, t, 5, M, True
)

# Round R_P up to the nearest multiple of t
R_P = ((R_P + t - 1) // t) * t

# Add one more t if partial rounds number is not even
if R_P % 2 != 0:
    R_P += t

command = f"sage generate_parameters_grain.sage 1 0 254 {t} {R_F} {R_P} 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 './../src/chips/poseidon/poseidon_params.rs' --rust"
os.system(command)


def generate_spec(t, alpha, R_F, R_P, file_name):
    with open(file_name, "w") as f:
        f.write("//! This file was generated by running generate_params.py\n")
        f.write(
            "//! Specification for rate {} Poseidon using the BN256 curve.".format(
                t - 1
            )
        )
        f.write("\n")
        f.write(
            "//! Patterned after [halo2_gadgets::poseidon::primitives::P128Pow5T3]\n"
        )

        f.write("use crate::chips::poseidon::poseidon_params;\n")
        f.write("use halo2_gadgets::poseidon::primitives::*;\n")
        f.write("use halo2_proofs::arithmetic::Field;\n")
        f.write("use halo2_proofs::halo2curves::bn256::Fr as Fp;\n")
        f.write("\n")
        f.write("#[derive(Debug, Clone, Copy)]\n")
        f.write("pub struct PoseidonSpec;\n")
        f.write("\n")
        f.write("pub(crate) type Mds<Fp, const T: usize> = [[Fp; T]; T];\n")
        f.write("\n")
        f.write("impl Spec<Fp, {}, {}> for PoseidonSpec {{\n".format(t, t - 1))
        f.write("    fn full_rounds() -> usize {\n")
        f.write("        {}\n".format(R_F))
        f.write("    }\n")
        f.write("\n")
        f.write("    fn partial_rounds() -> usize {\n")
        f.write("        {}\n".format(R_P))
        f.write("    }\n")
        f.write("\n")
        f.write("    fn sbox(val: Fp) -> Fp {\n")
        f.write("        val.pow_vartime([{}])\n".format(alpha))
        f.write("    }\n")
        f.write("\n")
        f.write("    fn secure_mds() -> usize {\n")
        f.write("        unimplemented!()\n")
        f.write("    }\n")
        f.write("\n")
        f.write(
            "    fn constants() -> (Vec<[Fp; {}]>, Mds<Fp, {}>, Mds<Fp, {}>) {{\n".format(
                t, t, t
            )
        )
        f.write("        (\n")
        f.write("            poseidon_params::ROUND_CONSTANTS[..].to_vec(),\n")
        f.write("            poseidon_params::MDS,\n")
        f.write("            poseidon_params::MDS_INV,\n")
        f.write("        )\n")
        f.write("    }\n")
        f.write("}\n")


file_name = "./../src/chips/poseidon/poseidon_spec.rs"
generate_spec(t, alpha, R_F, R_P, file_name)


def generate_params(num_assets, file_name):
    with open(file_name, "w") as f:
        f.write("//! This file was generated by running generate_params.py\n")
        f.write(
            "// The number of CEX asset balances for each user account\n".format(
                num_assets
            )
        )
        f.write("pub const N_ASSETS: usize = {};\n".format(num_assets))
        f.write(
            "// A Merkle sum tree helper dimension parameter used to lay out the cells deoending on the number of assets\n"
        )
        f.write("pub const MST_WIDTH: usize = 3 * (1 + N_ASSETS);\n")
        f.write(
            "// Poseidon hasher parameter for Length used in MST nodes (nodes take left hash, left assets, right hash, right assets as inputs)\n"
        )
        f.write("pub const L_NODE: usize = 2 * (1 + N_ASSETS);\n")
        f.write(
            "// Poseidon hasher parameter for Length used in MST entries (aka levaes, they only take one hash and one set of assets as input)\n"
        )
        f.write("pub const L_ENTRY: usize = 1 + N_ASSETS;\n")


file_name = "./../src/merkle_sum_tree/params.rs"
generate_params(num_assets, file_name)


# Print the results
def print_results(t, M, alpha, security_margin, R_F, R_P, min_sbox_cost, min_size_cost):
    print(f"t = {t}")
    print(f"M = {M}")
    print(f"alpha = {alpha}")
    print(f"security_margin = {security_margin}")
    print(f"R_F = {R_F}")
    print(f"R_P = {R_P}")
    print(f"min_sbox_cost = {min_sbox_cost}")
    print(f"min_size_cost = {min_size_cost}")


print_results(t, M, alpha, security_margin, R_F, R_P, min_sbox_cost, min_size_cost)
