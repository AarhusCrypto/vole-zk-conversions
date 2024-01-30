# Implementation of Mixed Arithmetic from Low-Degree PRGs

Here we give an overview of our additions and modifications for the paper "Low-Bandwidth Mixed
Arithmetic in VOLE-Based ZK from Low-Degree PRGs".

Our baseline that we compare against is the ["Edabits" implementation](edabits.rs) which has already
been part of swanky and was created for the [Appenzeller to Brie (A2B)
paper](https://eprint.iacr.org/2021/750).
Note that we used the codename `Cheddabits` for the implementation of our new protocols.

Our implementation was created on the same level ob abstraction, but we did not integrate it with
the higher-level functionality of diet-mac-and-cheese such as the `dietmc_ski` and `dietmc_0p`
programs (e.g., to evaluate SIEVE IR), since we wanted to compare the performance of the conversion
protocols directly without any overhead of handling circuits and IR.

## Our Modifications and Additions

- [`homcom.rs`](homcom.rs) contains with `FComProver/Verifier` the existing main functionality to work with
  VOLE-based commitments. Here, we only added functionality to precompute a given number of VOLEs
  and to gather statistics such as the number of VOLEs used and the number of VOLE extensions that
  have been performed. We also made minor performance optimizations.

- [`hd_quicksilver.rs`](hd_quicksilver.rs) contains a new implementation of higher-degree
  QuickSilver (`FcomProver`/`FComVerifier` only allowed to verify degree-2 multiplications) to
  verify arbitrary constant-degree polynomial constraints as well as QuickSilver-based range proofs.

- [`conv.rs`](conv.rs) contains new traits `ConvProverT`/`ConvVerifierT` that abstract the
  verification of arithmetic-Boolean conversions.

- [`trunc.rs`](trunc.rs) contains analogously new traits `FPMProverT`/`FPMVerifierT` to abstract the
  verification of fixed-point multiplication/truncation.

- [`edabits.rs`](edabits.rs) contains the existing implementation of conversion check via the A2B
  Edabits protocol in `ProverConv`/`VerifierConv`. We modified the implementation to implement the
  aforementioned conversion traits, added functionality to verify fixed-point multiplications,
  and compute the number of VOLEs needed for each operation

- [`cheddabits.rs`](cheddabits.rs) contains the new setup protocols for the PRG seeds (Version 1 and
  Version 2), i.e., random bits that are consistently committed over both F2 and Fp (see Section 3.2
  of our paper).

- [`cheddaprg.rs`](cheddaprg.rs) contains the new implementation of the low-degree PRGs using the
  TSPA and the XOR<sub>4</sub>MAJ<sub>7</sub> predicates (see Section 4.2 of our paper). The PRGs
  are evaluated on committed seeds to non-interactively produce higher-degree QuickSilver
  commitments to the output bits.

- [`cheddaconv.rs`](cheddaconv.rs) contains the new implementation of our conversion and fixed-point
  multiplication protocols based on the low-degree PRGs (see Section 4.3 of our paper).

- [`benchmark_tools.rs`](benchmark_tools.rs) contains auxiliary functionality to run our benchmarks
  and to collect metadata.
