//! # SP1 CPU Prover
//!
//! A prover that uses the CPU to execute and prove programs.

pub mod builder;
pub mod execute;
pub mod prove;

use anyhow::Result;
use execute::CpuExecuteBuilder;
use prove::CpuProveBuilder;
use sp1_core_executor::{SP1Context, SP1ContextBuilder, SP1ReduceProof};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    components::CpuProverComponents,
    verify::{verify_groth16_bn254_public_inputs, verify_plonk_bn254_public_inputs},
    Groth16Bn254Proof, PlonkBn254Proof, SP1CoreProofData, SP1ProofWithMetadata, SP1Prover,
    SP1PublicValues,
};
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, SP1CoreOpts, SP1ProverOpts};

use crate::{
    install::try_install_circuit_artifacts, prover::verify_proof, Prover, SP1Proof, SP1ProofMode,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1VerificationError, SP1VerifyingKey,
};

/// A prover that uses the CPU to execute and prove programs.
pub struct CpuProver {
    pub(crate) prover: SP1Prover<CpuProverComponents>,
    pub(crate) mock: bool,
}

impl CpuProver {
    /// Creates a new [`CpuProver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new [`CpuProver`] in mock mode.
    #[must_use]
    pub fn mock() -> Self {
        Self { prover: SP1Prover::new(), mock: true }
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// The builder is used for both the [`crate::cpu::CpuProver`] and [`crate::CudaProver`] client
    /// types.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{include_elf, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &SP1Stdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: &self.prover,
            elf,
            stdin: stdin.clone(),
            context_builder: SP1ContextBuilder::default(),
        }
    }

    /// Creates a new [`CpuProveBuilder`] for proving a program on the CPU.
    ///
    /// # Details
    /// The builder is used for only the [`crate::cpu::CpuProver`] client type.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{include_elf, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).core().run();
    /// ```
    /// # Fields
    ///     - `init_with_compressed`: if true, stdin should include compressed proof, else raw
    ///       pulbic inputs as it was previously
    /// The purpose of `init_with_compressed` is to make it possible to have the heavy part of the
    /// proving, which includes core and compressed proof generation, be done in SP1 cluster,
    /// while the cheaper part, which is generating SNARK, be done locally. This is necessary in
    /// our use case because our fork only makes change to the `OuterProof` (wrapping SNARK) and
    /// not the Inner Proof.
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: &SP1Stdin) -> CpuProveBuilder<'a> {
        CpuProveBuilder {
            prover: self,
            mode: SP1ProofMode::Core,
            pk,
            stdin: stdin.clone(),
            context_builder: SP1ContextBuilder::default(),
            core_opts: SP1CoreOpts::default(),
            recursion_opts: SP1CoreOpts::recursion(),
            mock: self.mock,
            init_with_compressed: false,
        }
    }

    /// `input_is_compressed_proof` is set to true when the user has passed compressed proof
    /// directly as input.
    pub(crate) fn prove_impl<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
        mode: SP1ProofMode,
        input_is_compressed_proof: bool,
    ) -> Result<SP1ProofWithPublicValues> {
        tracing::info!("input_is_compressed_proof {input_is_compressed_proof}");
        // If true, read compressed proof from stdin
        let (reduce_proof, public_values) = if input_is_compressed_proof {
            let compressed_proof_bytes = &stdin.buffer;
            assert_eq!(compressed_proof_bytes.len(), 1);
            let reduce_proof: SP1ReduceProof<BabyBearPoseidon2> =
                serde_json::from_slice(&compressed_proof_bytes[0])?;
            // here, the user has directly passed the compressed proof as input to be wrapped,
            // he already possesses SP1PublicValues while generating the compressed proof itself,
            // so you can return empty
            (reduce_proof, SP1PublicValues::default())
        } else {
            // If false, compute compressed proof
            let program = self.prover.get_program(&pk.elf).unwrap();

            // If we're in mock mode, return a mock proof.
            if self.mock {
                return self.mock_prove_impl(pk, stdin, context, mode);
            }

            // Generate the core proof.
            let proof: SP1ProofWithMetadata<SP1CoreProofData> =
                self.prover.prove_core(&pk.pk, program, stdin, opts, context)?;
            tracing::info!("public values {:?}", proof.public_values);
            if mode == SP1ProofMode::Core {
                return Ok(SP1ProofWithPublicValues::new(
                    SP1Proof::Core(proof.proof.0),
                    proof.public_values,
                    self.version().to_string(),
                ));
            }

            // Generate the compressed proof.
            let deferred_proofs =
                stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
            let public_values = proof.public_values.clone();
            let reduce_proof: SP1ReduceProof<BabyBearPoseidon2> =
                self.prover.compress(&pk.vk, proof, deferred_proofs, opts)?;
            if mode == SP1ProofMode::Compressed {
                return Ok(SP1ProofWithPublicValues::new(
                    SP1Proof::Compressed(Box::new(reduce_proof)),
                    public_values,
                    self.version().to_string(),
                ));
            };
            // return public_values as well so that it can be returned alongside wrapped proof
            (reduce_proof, public_values)
        };

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts)?;

        // Generate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts)?;

        // Generate the gnark proof.
        match mode {
            SP1ProofMode::Groth16 => {
                let groth16_bn254_artifacts =
                    sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                        &outer_proof.vk,
                        &outer_proof.proof,
                    );

                let _sect_witness = self.prover.wrap_sect(outer_proof, &groth16_bn254_artifacts);
                Ok(SP1ProofWithPublicValues::new(
                    SP1Proof::Core(vec![]),
                    public_values, /* return raw public values as it will be needed to verify
                                    * public input again r1cs witness */
                    self.version().to_string(),
                ))
            }
            SP1ProofMode::Plonk => {
                let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                    sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                        &outer_proof.vk,
                        &outer_proof.proof,
                    )
                } else {
                    try_install_circuit_artifacts("plonk")
                };
                let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);
                Ok(SP1ProofWithPublicValues::new(
                    SP1Proof::Plonk(proof),
                    SP1PublicValues::default(),
                    self.version().to_string(),
                ))
            }
            _ => unreachable!(),
        }
    }

    pub(crate) fn mock_prove_impl<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        context: SP1Context<'a>,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        let (public_values, _, _) = self.prover.execute(&pk.elf, stdin, context)?;
        Ok(SP1ProofWithPublicValues::create_mock_proof(pk, public_values, mode, self.version()))
    }

    fn mock_verify(
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        match &bundle.proof {
            SP1Proof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
                verify_plonk_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(SP1VerificationError::Plonk)
            }
            SP1Proof::Groth16(Groth16Bn254Proof { public_inputs, .. }) => {
                verify_groth16_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(SP1VerificationError::Groth16)
            }
            _ => Ok(()),
        }
    }
}

impl Prover<CpuProverComponents> for CpuProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let (pk, _, _, vk) = self.prover.setup(elf);
        (pk, vk)
    }

    fn inner(&self) -> &SP1Prover<CpuProverComponents> {
        &self.prover
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove_impl(pk, stdin, SP1ProverOpts::default(), SP1Context::default(), mode, false)
    }

    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        if self.mock {
            tracing::warn!("using mock verifier");
            return Self::mock_verify(bundle, vkey);
        }
        verify_proof(self.inner(), self.version(), bundle, vkey)
    }
}

impl Default for CpuProver {
    fn default() -> Self {
        let prover = SP1Prover::new();
        Self { prover, mock: false }
    }
}
