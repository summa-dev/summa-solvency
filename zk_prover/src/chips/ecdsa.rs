// Patterned after [halo2wrong ECDSA](https://github.com/privacy-scaling-explorations/halo2wrong/blob/master/ecdsa/src/ecdsa.rs)
use ecdsa::ecdsa::EcdsaConfig;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*};

#[derive(Debug, Clone)]
pub struct EcdsaConfigWithInstance {
    pub ecdsa_config: EcdsaConfig,
}

impl EcdsaConfigWithInstance {
    pub fn expose_limbs_to_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        pk_x_limbs: Vec<AssignedCell<Fp, Fp>>,
        pk_y_limbs: Vec<AssignedCell<Fp, Fp>>,
        x_row_start: usize,
        y_row_start: usize,
    ) -> Result<(), Error> {
        // loop over pk_x_limbs and pk_y_limbs and expose them to instance column
        for i in 0..4 {
            layouter.constrain_instance(
                pk_x_limbs[i].cell(),
                self.ecdsa_config.main_gate_config.instance,
                x_row_start + i,
            )?;
            layouter.constrain_instance(
                pk_y_limbs[i].cell(),
                self.ecdsa_config.main_gate_config.instance,
                y_row_start + i,
            )?;
        }

        Ok(())
    }
}
