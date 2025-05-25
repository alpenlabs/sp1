use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField32};
use p3_sect_fr::SectFr;

use sp1_recursion_compiler::ir::{Builder, Config, Felt, Var};
use sp1_recursion_core::{DIGEST_SIZE, NUM_BITS};

use sp1_stark::Word;

/// Convert 8 BabyBear words into a SectFr field element by shifting by 28 bits each time. The last
/// word becomes the least significant bits.
#[allow(dead_code)]
pub fn babybears_to_bn254(digest: &[BabyBear; 8]) -> SectFr {
    let mut result = SectFr::zero();
    for word in digest.iter() {
        // Since BabyBear prime is less than 2^31, we can shift by 28 bits each time and still be
        // within the SectFr field, we truncate the top 3 bits everytime.
        // so total size of result in the end is 8 x 28 = 224 bits
        result *= SectFr::from_canonical_u64(1 << 28); // shift by 28
        let masked_val_u32 = word.as_canonical_u32() & 0x0FFFFFFF; // mask top 3-bits
        result += SectFr::from_canonical_u32(masked_val_u32); // add 28 bits
    }
    result
}

/// Convert 32 BabyBear bytes into a SectFr field element. All byte's most significant 1 bit is masked (truncated)
#[allow(dead_code)]
pub fn babybear_bytes_to_bn254(bytes: &[BabyBear; 32]) -> SectFr {
    let mut result = SectFr::zero();
    for byte in bytes.iter() {
        result *= SectFr::from_canonical_u32(128); // shift by 7 bits
        let masked = byte.as_canonical_u32() & 0x7f;
        debug_assert!(masked < 128);
        result += SectFr::from_canonical_u32(masked); // add 7-bit
    }
    result
}

#[allow(dead_code)]
pub fn felts_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    digest: &[Felt<C::F>; DIGEST_SIZE],
) -> Var<C::N> {
    let var_2_28: Var<_> = builder.constant(C::N::from_canonical_u32(1 << 28));
    let result = builder.constant(C::N::zero());
    let zero_var: Var<_> = builder.constant(C::N::zero());

    for (i, word) in digest.iter().enumerate() {
        let all_bits: Vec<Var<C::N>> = builder.num2bits_f_circuit(*word);
        for j in 0..3 {
            // mask 30, 29, 28'th positions leaving 0-27 untouched; thus masking all but 28 bits
            builder.assign(all_bits[NUM_BITS - j - 1], zero_var);
        }
        let word_var = builder.bits2num_v_circuit(&all_bits);
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_28 + word_var);
        }
    }
    result
}

#[allow(dead_code)]
pub fn felt_bytes_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    bytes: &[Felt<C::F>; 32],
) -> Var<C::N> {
    let var_128: Var<_> = builder.constant(C::N::from_canonical_u32(128));
    let zero_var: Var<_> = builder.constant(C::N::zero());
    let result = builder.constant(C::N::zero());
    for (i, byte) in bytes.iter().enumerate() {
        let byte_bits = builder.num2bits_f_circuit(*byte);
        // mask top 1-bit
        for j in 0..1 {
            builder.assign(byte_bits[8 - j - 1], zero_var);
        }
        let byte_var = builder.bits2num_v_circuit(&byte_bits);
        if i == 0 {
            builder.assign(result, byte_var);
        } else {
            builder.assign(result, result * var_128 + byte_var);
        }
    }
    result
}

#[allow(dead_code)]
pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    words.iter().flat_map(|w| w.0).collect::<Vec<_>>()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use sp1_core_machine::utils::{run_test_machine_with_prover, setup_logger};
    use sp1_recursion_compiler::circuit::{AsmCompiler, AsmConfig};

    use sp1_recursion_compiler::ir::DslIrBlock;
    use sp1_recursion_core::{machine::RecursionAir, Runtime};
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, InnerChallenge, InnerVal, MachineProver,
    };

    use crate::witness::WitnessBlock;

    type SC = BabyBearPoseidon2;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// A simplified version of some code from `recursion/core/src/stark/mod.rs`.
    /// Takes in a program and runs it with the given witness and generates a proof with a variety
    /// of machines depending on the provided test_config.
    pub(crate) fn run_test_recursion_with_prover<P: MachineProver<SC, RecursionAir<F, 3>>>(
        block: DslIrBlock<AsmConfig<F, EF>>,
        witness_stream: impl IntoIterator<Item = WitnessBlock<AsmConfig<F, EF>>>,
    ) {
        setup_logger();

        let compile_span = tracing::debug_span!("compile").entered();
        let mut compiler = AsmCompiler::<AsmConfig<F, EF>>::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        compile_span.exit();

        let config = SC::default();

        let run_span = tracing::debug_span!("run the recursive program").entered();
        let mut runtime = Runtime::<F, EF, _>::new(program.clone(), config.perm.clone());
        runtime.witness_stream.extend(witness_stream);
        tracing::debug_span!("run").in_scope(|| runtime.run().unwrap());
        assert!(runtime.witness_stream.is_empty());
        run_span.exit();

        let records = vec![runtime.record];

        // Run with the poseidon2 wide chip.
        let proof_wide_span = tracing::debug_span!("Run test with wide machine").entered();
        let wide_machine = RecursionAir::<_, 3>::compress_machine(SC::default());
        let (pk, vk) = wide_machine.setup(&program);
        let prover = P::new(wide_machine);
        let pk = prover.pk_to_device(&pk);
        let result = run_test_machine_with_prover::<_, _, P>(&prover, records.clone(), pk, vk);
        proof_wide_span.exit();

        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn run_test_recursion(
        block: DslIrBlock<AsmConfig<F, EF>>,
        witness_stream: impl IntoIterator<Item = WitnessBlock<AsmConfig<F, EF>>>,
    ) {
        run_test_recursion_with_prover::<CpuProver<_, _>>(block, witness_stream)
    }
}
