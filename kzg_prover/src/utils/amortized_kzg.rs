use halo2_proofs::{
    arithmetic::{best_fft, kate_division, Field},
    halo2curves::{
        bn256::{Bn256, Fr as Fp, G1Affine, G2Affine, Gt, G1},
        group::{prime::PrimeCurveAffine, Curve, Group},
        pairing::{Engine, PairingCurveAffine},
    },
    poly::{
        commitment::{Blind, CommitmentScheme, Params, ParamsProver},
        kzg::commitment::ParamsKZG,
        Coeff, EvaluationDomain, Polynomial,
    },
};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

/// Commit to a polynomial using the KZG commitment scheme
///
/// # Arguments
///
/// * `params` - The KZG parameters
/// * `poly` - The polynomial to commit to
///
/// # Returns
///
/// * The commitment to the polynomial as the G1 point
pub fn commit_kzg(params: &ParamsKZG<Bn256>, poly: &Polynomial<Fp, Coeff>) -> G1 {
    params.commit(poly, Blind::default())
}

/// Computes the polynomial h(X) for the amortized KZG algorithm as per FK23
/// https://eprint.iacr.org/2023/033
///
/// # Arguments
///
/// * `params` - The KZG parameters
/// * `f_poly` - The polynomial to compute the amortized opening proof for
///
/// # Returns
///
/// * The polynomial h(X) as a vector of G1 points
pub fn compute_h(params: &ParamsKZG<Bn256>, f_poly: &Polynomial<Fp, Coeff>) -> Vec<G1> {
    // Double the polynomial length, thus K + 1
    let double_domain = EvaluationDomain::new(1, params.k() + 1);

    let d: usize = f_poly.len(); // Degree of the polynomial

    // Extract s_commitments from ParamsKZG, reverse and extend with neutral elements
    let s_commitments_reversed = params
        .get_g()
        .par_iter()
        .rev()
        .map(PrimeCurveAffine::to_curve)
        .collect::<Vec<_>>();

    let mut y: Vec<G1> = vec![G1::identity(); 2 * d];
    y[..d].copy_from_slice(&s_commitments_reversed[..d]);

    // Prepare coefficients vector and zero-pad at the beginning
    let mut v = vec![Fp::zero(); 2 * d];
    v[d..(2 * d)].copy_from_slice(f_poly);

    let nu = double_domain.get_omega(); // 2d-th root of unity

    rayon::join(
        || best_fft(&mut y, nu, (2 * d).trailing_zeros()), // Perform the step 1 FFT from FK23, §2.2
        || best_fft(&mut v, nu, (2 * d).trailing_zeros()), // Perform the step 2 FFT from FK23, §2.2
    );

    // Perform the Hadamard product (FK23, §2.2, step 3)
    let u: Vec<G1> = y
        .par_iter()
        .zip(v.par_iter())
        .map(|(&y, &v)| y * v)
        .collect();

    let nu_inv = nu.invert().unwrap(); // Inverse of 2d-th root of unity
    let mut h = u;
    // Perform inverse FFT on h (FK23, §2.2, step 4)
    best_fft(&mut h, nu_inv, (2 * d).trailing_zeros());

    // Scale the result by the size of the vector (part of the iFFT)
    let n_inv = Fp::from(2 * d as u64).invert().unwrap();
    h.par_iter_mut().map(|h| *h *= n_inv).collect::<Vec<_>>();

    // Truncate to get the first d coefficients (FK23, §2.2, step 5)
    h.truncate(d);

    h
}

/// Compute the naive KZG opening proof
/// J Thaler, Proofs, Arguments, and Zero-Knowledge, §15.2, p. 233
/// KZG proof π is a proof of f(y) = z: π[f(y) = z] = C_Ty, where C_Ty is a commitment to a polynomial Ty(X) = (f(X)−z)/(X−y) and y is the challenge
///
/// # Arguments
///
/// * `params` - The KZG parameters
/// * `domain` - The domain for the polynomial
/// * `f_poly` - The polynomial to compute the opening proof for
/// * `y` - The challenge
/// * `z` - The value of the polynomial at the challenge
///
/// # Returns
///
/// * The KZG opening proof as a G1 point
pub fn create_naive_kzg_proof<
    Scheme: CommitmentScheme<Curve = halo2_proofs::halo2curves::bn256::G1Affine, Scalar = Fp>,
>(
    params: &ParamsKZG<Bn256>,
    domain: &EvaluationDomain<Fp>,
    f_poly: &Polynomial<<Scheme as CommitmentScheme>::Scalar, Coeff>,
    y: Fp,
    z: Fp,
) -> G1 {
    let numerator = f_poly - z;
    let mut t_y_vals = kate_division(&numerator.to_vec(), y);
    // The resulting degree is one less than the degree of the numerator, so we need to pad it with zeros back to the original polynomial size
    t_y_vals.resize(f_poly.len(), Fp::ZERO);
    let t_y = domain.coeff_from_vec(t_y_vals);
    commit_kzg(params, &t_y)
}

/// Verify the naive KZG proof
/// J Thaler, Proofs, Arguments, and Zero-Knowledge, §15.2, eq. 15.2, p. 233
/// e(c·g^(−z),g) = e(π,g^τ ·g^(−y)), y is the challenge
///
/// # Arguments
///
/// * `params` - The KZG parameters
/// * `c` - The commitment to the polynomial
/// * `pi` - The KZG opening proof
/// * `y` - The challenge
/// * `z` - The value of the polynomial at the challenge
///
/// # Returns
///
/// * True if the proof is valid, false otherwise
pub fn verify_kzg_proof(params: &ParamsKZG<Bn256>, c: G1, pi: G1, y: &Fp, z: &Fp) -> bool
where
    G1Affine: PairingCurveAffine<Pair = G2Affine, PairingResult = Gt>,
{
    let g_to_minus_z = G1Affine::generator() * &(-z);
    let c_g_to_minus_z: G1 = c + g_to_minus_z;
    let left_side = Bn256::pairing(&c_g_to_minus_z.to_affine(), &G2Affine::generator());

    let g_to_minus_y = G2Affine::generator() * (-y);
    let g_tau = params.s_g2();
    let g_tau_g_to_minus_y = g_tau + g_to_minus_y;
    let right_side = Bn256::pairing(&pi.to_affine(), &g_tau_g_to_minus_y.to_affine());

    left_side == right_side
}
