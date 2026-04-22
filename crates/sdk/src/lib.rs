//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://docs.succinct.xyz/docs/sp1/getting-started/install) section
//! in the official SP1 documentation for a quick start guide.

#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_assert)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::explicit_iter_loop)]
#![warn(missing_docs)]

pub mod artifacts;
pub mod client;
pub mod cpu;
pub mod cuda;
pub mod env;
pub mod install;
#[cfg(feature = "network")]
pub mod network;
pub mod utils;

// Re-export the client.
pub use crate::client::ProverClient;

// Re-export the provers.
pub use crate::{cpu::CpuProver, cuda::CudaProver, env::EnvProver};

#[cfg(feature = "network")]
pub use crate::network::{
    prover::NetworkProver,
    signer::{NetworkSigner, NetworkSignerError},
};

// Re-export the proof and prover traits.
pub mod proof;
pub use proof::*;
pub mod prover;

pub use prover::{Prover, SP1VerificationError};

// Re-export the build utilities and executor primitives.
pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, Executor, HookEnv, SP1Context, SP1ContextBuilder};

// Re-export the machine/prover primitives.
pub use sp1_core_machine::io::SP1Stdin;
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    HashableKey, ProverMode, SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};

// Re-export the utilities.
pub use utils::setup_logger;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_serialize::CanonicalSerialize;
    use num_bigint::BigUint;
    use sp1_primitives::io::SP1PublicValues;

    use crate::{utils, Prover, ProverClient, SP1Stdin};

    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_, _) = client.execute(elf, &stdin).run().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, &stdin).run().unwrap();
    }

    #[should_panic]
    #[test]
    fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, &stdin).cycle_limit(1).run().unwrap();
    }

    #[test]
    fn test_e2e_core() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, &stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[test]
    fn test_e2e_io_override() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::HELLO_WORLD_ELF;

        let mut stdout = Vec::new();

        // Generate proof & verify.
        let stdin = SP1Stdin::new();
        let _ = client.execute(elf, &stdin).stdout(&mut stdout).run().unwrap();

        assert_eq!(stdout, b"Hello, world!\n");
    }

    #[test]
    fn test_e2e_compressed() {
        utils::setup_logger();
        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, &stdin).compressed().run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    // RUST_LOG=info cargo test --release --package sp1-sdk --lib -- tests::test_e2e_prove_groth16
    // --exact --nocapture
    #[test]
    fn test_e2e_prove_groth16() {
        use p3_field::PrimeField;
        utils::setup_logger();
        use sp1_prover::HashableKey;

        let client = ProverClient::builder().cpu().build();
        let elf = test_artifacts::FIBONACCI_BLAKE3_ELF;
        let (pk, vk) = client.setup(elf);
        // This is as far as we go during compile time
        // With these we can obtain groth16 verifying key and SP1_VKEY_HASH
        // Since our groth16 verifier remains same for any program statement,
        // groth16 vkey is constant and is present in sp1_verifier::GROTH16_VK_BYTES
        // while SP1 VKEY depends upon program statement and can be computed using
        let sp1_vkey_hash = pk.vk.hash_bn254().as_canonical_biguint();

        tracing::info!("sp1_vkey_hash {:?}", sp1_vkey_hash);
        // Private Inputs; doesn't matter for the verifier
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let proof: crate::SP1ProofWithPublicValues =
            client.prove(&pk, &stdin).groth16().run().unwrap();
        tracing::info!("sp1 raw public values {:?}", proof.public_values);
        // Note SP1 public values and raw public values are different; SP1_pub = hash_fr(raw_pub)
        client.verify(&proof, &vk).unwrap();

        let proof_bytes = proof.bytes(); // first 4 bytes of proof here is from groth16_vkey_hash

        use zkaleido_sp1_groth16_verifier::Groth16Proof;
        let gnark_groth16_proof = Groth16Proof::from_uncompressed_bytes(&proof_bytes[4..]).unwrap();
        let gnark_compressed_bytes: [u8; _] = gnark_groth16_proof.to_gnark_compressed_bytes();
        tracing::info!("gnark compressed proof bytes {:?}", gnark_compressed_bytes);

        // same uncompressed proof bytes can also be presented as ark proof
        // In this block we verify proof with ark-groth16
        {
            let ark_proof: ark_groth16::Proof<ark_bn254::Bn254> =
                sp1_verifier::load_ark_proof_from_bytes(&proof_bytes[4..]).unwrap();

            let ark_vkey: ark_groth16::VerifyingKey<ark_bn254::Bn254> =
                sp1_verifier::load_ark_groth16_verifying_key_from_bytes(
                    &sp1_verifier::GROTH16_VK_BYTES,
                )
                .unwrap();

            let mut ark_proof_bytes = vec![];
            ark_proof.serialize_compressed(&mut ark_proof_bytes).unwrap();

            tracing::info!("ark proof bytes {:?}", &ark_proof_bytes);

            let mut ark_vkey_bytes = vec![];
            ark_vkey.serialize_compressed(&mut ark_vkey_bytes).unwrap();

            let pvk: ark_groth16::PreparedVerifyingKey<ark_bn254::Bn254> = ark_vkey.clone().into();
            let public_inputs = match proof.proof {
                sp1_stark::SP1Proof::Groth16(gproof) => {
                    let expected_vk_hash = BigUint::from_str(&gproof.public_inputs[0]).unwrap();
                    assert_eq!(sp1_vkey_hash, expected_vk_hash);
                    let expected_public_values_hash =
                        BigUint::from_str(&gproof.public_inputs[1]).unwrap();
                    [expected_vk_hash.into(), expected_public_values_hash.into()]
                }
                _ => panic!(),
            };

            let verified = ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
                &pvk,
                &ark_proof,
                &public_inputs,
            )
            .unwrap();
            assert!(verified);
            tracing::info!("ark format groth16 vk {:?}", ark_vkey_bytes);
        }
    }

    #[test]
    fn test_e2e_prove_plonk_mock() {
        utils::setup_logger();
        let client = ProverClient::builder().mock().build();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let proof = client.prove(&pk, &stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}

#[cfg(all(feature = "cuda", not(sp1_ci_in_progress)))]
mod deprecated_check {
    #[deprecated(
        since = "4.0.0",
        note = "The `cuda` feature is deprecated, as the CudaProver is now supported by default."
    )]
    #[allow(unused)]
    fn cuda_is_deprecated() {}

    /// Show a warning if the `cuda` feature is enabled.
    #[allow(unused, deprecated)]
    fn show_cuda_warning() {
        cuda_is_deprecated();
    }
}
