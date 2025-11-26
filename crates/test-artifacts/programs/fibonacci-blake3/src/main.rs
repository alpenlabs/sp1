//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let n: u32 = sp1_zkvm::io::read();
    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a: u32 = 0;
    let mut b: u32 = 1;

    let mut cs: Vec<u32> = vec![];
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
        cs.push(c);
    }
    cs = cs[cs.len() - 8..].to_vec();
    let cs: [u32; 8] = cs.try_into().unwrap();
    sp1_zkvm::io::commit(&a);
    sp1_zkvm::io::commit(&cs);
}
