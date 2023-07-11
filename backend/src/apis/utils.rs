use halo2_proofs::{
    halo2curves::bn256::Bn256, poly::commitment::Params, poly::kzg::commitment::ParamsKZG,
};
use std::fs::File;

pub fn get_params(k: u32) -> Result<ParamsKZG<Bn256>, &'static str> {
    let ptau_path = format!("ptau/hermez-raw-{}", k);

    let metadata = std::fs::metadata(ptau_path.clone());

    if metadata.is_err() {
        Err("ptau file not found, download the ptau from https://github.com/han0110/halo2-kzg-srs, for {ptau_path}")
    } else {
        let mut params_fs = File::open(ptau_path).expect("couldn't load params");
        let params = ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params");
        Ok(params)
    }
}
