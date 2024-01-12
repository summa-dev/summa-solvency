use halo2_proofs::{
    arithmetic::{best_fft, eval_polynomial, kate_division, Field},
    halo2curves::{
        bn256::{Bn256, Fr as Fp, G1Affine, G1},
        group::{prime::PrimeCurveAffine, Curve, Group},
    },
    poly::{
        commitment::{Blind, CommitmentScheme, ParamsProver},
        kzg::commitment::ParamsKZG,
        Coeff, EvaluationDomain, Polynomial,
    },
};

pub fn commit_kzg(params: &ParamsKZG<Bn256>, poly: &Polynomial<Fp, Coeff>) -> G1 {
    params.commit(poly, Blind::default())
}

/// Computes the polynomial h(X) for the batch KZG algorithm.
pub fn compute_h(
    params: &ParamsKZG<Bn256>,
    f_poly: &Polynomial<Fp, Coeff>,
    double_domain: &EvaluationDomain<Fp>,
) -> Vec<G1Affine> {
    let d = f_poly.len(); // Degree of the polynomial

    println!("d: {}", d);
    // Extract s_commitments from ParamsKZG and extend with neutral elements
    let mut s_commitments_reversed = params
        .get_g()
        .iter()
        .map(PrimeCurveAffine::to_curve)
        .collect::<Vec<_>>();
    s_commitments_reversed.reverse();

    let mut s_fft: Vec<G1> = vec![G1::identity(); 2 * d];
    s_fft[..d].copy_from_slice(&s_commitments_reversed[..d]);

    // Prepare coefficients vector and zero-pad at the beginning
    let mut c_fft = vec![Fp::zero(); 2 * d];
    //Create a reversed copy of the polynomial
    // let mut f_reversed = f_poly.to_vec();
    // f_reversed.reverse();
    c_fft[d..(2 * d)].copy_from_slice(&f_poly);

    println!("c_fft and s_fft assigned");
    let nu = double_domain.get_omega(); // 2d-th root of unity
    let s_len = s_fft.len();
    println!("performing FFT on s");
    best_fft(&mut s_fft, nu, s_len.trailing_zeros());
    let c_len = c_fft.len();
    println!("performing FFT on c");
    best_fft(&mut c_fft, nu, c_len.trailing_zeros());

    println!("Computing powers of nu");
    // Compute powers of nu
    let mut nu_powers = vec![Fp::one(); 2 * d];
    for i in 1..(2 * d) {
        nu_powers[i] = nu_powers[i - 1] * nu;
    }

    println!("Performing Hadamard product");
    // Perform the Hadamard product
    let u: Vec<G1> = s_fft
        .iter()
        .zip(c_fft.iter())
        .zip(nu_powers.iter())
        .map(|((&s, &c), &nu_power)| s * c * nu_power)
        .collect();

    // Perform inverse FFT
    let nu_inv = nu.invert().unwrap(); // Inverse of 2d-th root of unity
    let mut h = u;
    let h_len = h.len();
    println!("Performing inverse FFT on h");
    best_fft(&mut h, nu_inv, h_len.trailing_zeros());

    // Scale the result by the size of the vector (part of the iFFT)
    let n_inv = Fp::from(h_len as u64).invert().unwrap();
    h.iter_mut().for_each(|h| *h *= n_inv);

    // Truncate to get the first d coefficients
    h.truncate(d);

    h.iter().map(|h| h.to_affine()).collect()
}

//KZG proof π is a proof of f(y) = z: π[f(y) = z] = C_Ty, where C_Ty is a commitment to a polynomial Ty(X) = (f(X)−z)/(X−y)
pub fn create_standard_kzg_proof<
    Scheme: CommitmentScheme<Curve = halo2_proofs::halo2curves::bn256::G1Affine, Scalar = Fp>,
>(
    params: &ParamsKZG<Bn256>,
    domain: &EvaluationDomain<Fp>,
    f_poly: &Polynomial<<Scheme as CommitmentScheme>::Scalar, Coeff>,
    y: Fp,
) -> G1 {
    let z = eval_polynomial(&f_poly, y);
    let numerator = f_poly - z;
    let mut t_y_vals = kate_division(&numerator.to_vec(), y);
    // The resulting degree is one less than the degree of the numerator, so we need to pad it with zeros back to the original polynomial size
    t_y_vals.resize(f_poly.len(), Fp::ZERO);
    let t_y = domain.coeff_from_vec(t_y_vals);
    commit_kzg(params, &t_y)
}
