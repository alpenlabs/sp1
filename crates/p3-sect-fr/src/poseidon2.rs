//! Diffusion matrix for SECT
//!
//! Reference: https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs

use std::sync::OnceLock;

use p3_field::AbstractField;
use p3_poseidon2::{matmul_internal, DiffusionPermutation};
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};

use crate::SectFr;

#[inline]
fn get_diffusion_matrix_3() -> &'static [SectFr; 3] {
    static MAT_DIAG3_M_1: OnceLock<[SectFr; 3]> = OnceLock::new();
    MAT_DIAG3_M_1.get_or_init(|| [SectFr::one(), SectFr::one(), SectFr::two()])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffusionMatrixSECT;

impl<AF: AbstractField<F = SectFr>> Permutation<[AF; 3]> for DiffusionMatrixSECT {
    fn permute_mut(&self, state: &mut [AF; 3]) {
        matmul_internal::<SectFr, AF, 3>(state, *get_diffusion_matrix_3());
    }
}

impl<AF: AbstractField<F = SectFr>> DiffusionPermutation<AF, 3> for DiffusionMatrixSECT {}

#[cfg(test)]
mod tests {
    use crate::{
        params::{POSEIDON2_SECT_PARAMS, RC3},
        FpSECT as ark_FpBN256,
    };
    use ff::PrimeField;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixHL};
    use rand::Rng;
    use zkhash::{
        ark_ff::{BigInteger, PrimeField as ark_PrimeField},
        poseidon2::poseidon2::Poseidon2 as Poseidon2Ref,
    };

    use super::*;
    use crate::FFSectFr;

    fn sect_from_ark_ff(input: ark_FpBN256) -> SectFr {
        let bytes = input.into_bigint().to_bytes_le();

        let mut res = <FFSectFr as PrimeField>::Repr::default();

        for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
            *digit = bytes[i];
        }

        let value = FFSectFr::from_repr(res);

        if value.is_some().into() {
            SectFr { value: value.unwrap() }
        } else {
            panic!("Invalid field element")
        }
    }

    /// external_round_constants and internal_round_constants are the generated values used in RC3
    #[test]
    fn test_poseidon2_sect() {
        const WIDTH: usize = 3;
        const D: u64 = 5;
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 56;

        type F = SectFr;

        let mut rng = rand::thread_rng();

        // Poiseidon2 reference implementation from zkhash repo.
        let poseidon2_ref = Poseidon2Ref::new(&POSEIDON2_SECT_PARAMS);

        // Copy over round constants from zkhash.
        let mut round_constants: Vec<[F; WIDTH]> = RC3
            .iter()
            .map(|vec| {
                vec.iter().cloned().map(sect_from_ark_ff).collect::<Vec<_>>().try_into().unwrap()
            })
            .collect();

        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = round_constants;
        // Our Poseidon2 implementation.
        let poseidon2: Poseidon2<SectFr, Poseidon2ExternalMatrixHL, DiffusionMatrixSECT, WIDTH, D> =
            Poseidon2::new(
                ROUNDS_F,
                external_round_constants,
                Poseidon2ExternalMatrixHL,
                ROUNDS_P,
                internal_round_constants,
                DiffusionMatrixSECT,
            );

        // Generate random input and convert to both Goldilocks field formats.
        let input_ark_ff = rng.gen::<[ark_FpBN256; WIDTH]>();
        let input: [SectFr; 3] = input_ark_ff
            .iter()
            .cloned()
            .map(sect_from_ark_ff)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Run reference implementation.
        let output_ref = poseidon2_ref.permutation(&input_ark_ff);

        let expected: [F; WIDTH] = output_ref
            .iter()
            .cloned()
            .map(sect_from_ark_ff)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Run our implementation.
        let mut output = input;
        poseidon2.permute_mut(&mut output);

        assert_eq!(output, expected);
    }
}
