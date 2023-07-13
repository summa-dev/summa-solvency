use std::fs::File;

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp},
    plonk::{keygen_pk, keygen_vk, Circuit},
    poly::commitment::Params,
    poly::kzg::commitment::ParamsKZG,
};

use snark_verifier_sdk::CircuitExt;

use super::snapshot::SetupArtifcats;

pub fn generate_setup_artifacts<C: Circuit<Fp> + CircuitExt<Fp>>(
    params_path: &str,
    k: u32,
    circuit: C,
) -> Result<SetupArtifcats, &'static str> {
    let metadata = std::fs::metadata(params_path.clone());

    if metadata.is_err() {
        Err("ptau file not found, download the ptau from https://github.com/han0110/halo2-kzg-srs")
    } else {
        let mut params_fs = File::open(params_path).expect("couldn't load params");
        let template_params =
            ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params");

        let mut params = template_params;

        if params.k() < k {
            return Err("k is too large for the given params");
        }

        if params.k() > k {
            params.downsize(k);
        }

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        Ok((params, pk, vk))
    }
}
