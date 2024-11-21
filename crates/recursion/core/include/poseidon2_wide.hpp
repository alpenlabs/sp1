#pragma once

#include "poseidon2.hpp"
#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_wide {
using namespace poseidon2;

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_external_round(
    const F* external_rounds_state, F* sbox, size_t r, F* next_state) {
  F round_state[WIDTH];
  if (r == 0) {
    // external_linear_layer_immut
    F temp_round_state[WIDTH];
    for (size_t i = 0; i < WIDTH; i++) {
      temp_round_state[i] = external_rounds_state[r * WIDTH + i];
    }
    external_linear_layer<F>(temp_round_state);
    for (size_t i = 0; i < WIDTH; i++) {
      round_state[i] = temp_round_state[i];
    }
  } else {
    for (size_t i = 0; i < WIDTH; i++) {
      round_state[i] = external_rounds_state[r * WIDTH + i];
    }
  }

  size_t round = r < NUM_EXTERNAL_ROUNDS / 2 ? r : r + NUM_INTERNAL_ROUNDS;
  F add_rc[WIDTH];
  for (size_t i = 0; i < WIDTH; i++) {
    add_rc[i] = round_state[i] + F(F::to_monty(RC_16_30_U32[round][i]));
  }

  F sbox_deg_3[WIDTH];
  F sbox_deg_7[WIDTH];
  for (size_t i = 0; i < WIDTH; i++) {
    sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
    sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * add_rc[i];
  }

  if (sbox != nullptr) {
    for (size_t i = 0; i < WIDTH; i++) {
      sbox[r * WIDTH + i] = sbox_deg_3[i];
    }
  }

  for (size_t i = 0; i < WIDTH; i++) {
    next_state[i] = sbox_deg_7[i];
  }
  external_linear_layer<F>(next_state);
}

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_internal_rounds(
    const F* internal_rounds_state, F* internal_rounds_s0, F* sbox,
    F* ret_state) {}

template <class F>
__SP1_HOSTDEV__ void event_to_row(const F* input, F* external_rounds_state,
                                  F* internal_rounds_state,
                                  F* internal_rounds_s0, F* external_sbox,
                                  F* internal_sbox, F* output_state) {
  for (size_t i = 0; i < WIDTH; i++) {
    external_rounds_state[i] = input[i];
  }

  for (size_t r = 0; r < NUM_EXTERNAL_ROUNDS / 2; r++) {
    F next_state[WIDTH];
    populate_external_round<F>(external_rounds_state, external_sbox, r,
                               next_state);
    if (r == NUM_EXTERNAL_ROUNDS / 2 - 1) {
      for (size_t i = 0; i < WIDTH; i++) {
        internal_rounds_state[i] = next_state[i];
      }
    } else {
      for (size_t i = 0; i < WIDTH; i++) {
        external_rounds_state[(r + 1) * WIDTH + i] = next_state[i];
      }
    }

    for (size_t r = NUM_EXTERNAL_ROUNDS / 2; r < NUM_EXTERNAL_ROUNDS; r++) {
      F next_state[WIDTH];
      populate_external_round<F>(external_rounds_state, external_sbox, r,
                                 next_state);
      if (r == NUM_EXTERNAL_ROUNDS - 1) {
        for (size_t i = 0; i < WIDTH; i++) {
          output_state[i] = next_state[i];
        }
      } else {
        for (size_t i = 0; i < WIDTH; i++) {
          external_rounds_state[(r + 1) * WIDTH + i] = next_state[i];
        }
      }
    }
  }

  F ret_state[WIDTH];
  populate_internal_rounds<F>(internal_rounds_state, internal_rounds_s0,
                              internal_sbox, ret_state);
  size_t row = NUM_EXTERNAL_ROUNDS / 2;
  for (size_t i = 0; i < WIDTH; i++) {
    external_rounds_state[row * WIDTH + i] = ret_state[i];
  }
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const Poseidon2SkinnyInstr<F>& instr,
                                  Poseidon2PreprocessedColsWide<F>& cols) {
  for (size_t i = 0; i < WIDTH; i++) {
    cols.input[i] = instr.addrs.input[i];
    cols.output[i] = MemoryAccessColsChips<F>{.addr = instr.addrs.output[i],
                                              .mult = instr.mults[i]};
  }
  cols.is_real_neg = F::zero() - F::one();
}
}  // namespace sp1_recursion_core_sys::poseidon2_wide
