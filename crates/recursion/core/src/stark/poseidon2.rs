use ff::PrimeField as FFPrimeField;
use p3_bls12_fr::{Bls12Fr, FFBls12Fr};
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bls12::FpBLS12 as ark_FpBLS12,
    poseidon2::poseidon2_instance_bls12::RC3,
};

fn bn254_from_ark_ff(input: ark_FpBLS12) -> Bls12Fr {
    let bytes = input.into_bigint().to_bytes_le();

    let mut res = <FFBls12Fr as ff::PrimeField>::Repr::default();

    for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
        *digit = bytes[i];
    }

    let value = FFBls12Fr::from_repr(res);

    if value.is_some().into() {
        Bls12Fr { value: value.unwrap() }
    } else {
        panic!("Invalid field element")
    }
}

pub fn bn254_poseidon2_rc3() -> Vec<[Bls12Fr; 3]> {
    RC3.iter()
        .map(|vec| {
            vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap()
        })
        .collect()
}

pub fn bn254_poseidon2_rc4() -> Vec<[Bls12Fr; 4]> {
    RC3.iter()
        .map(|vec| {
            let result: [Bls12Fr; 3] =
                vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap();
            [result[0], result[1], result[2], result[2]]
        })
        .collect()
}
