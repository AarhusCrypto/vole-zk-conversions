# **swanky**: A suite of rust libraries for secure multi-party computation

**swanky** provides a suite of rust libraries for doing secure multi-party
computation (MPC).

* **fancy-garbling**: Boolean and arithmetic garbled circuits.
  * **twopac**: Two-party garbled-circuit-based secure computation.
* **humidor**: Implementation of the Ligero zero knowledge proof system.
* **keyed_arena**: Bump allocator which allows for random access to its allocations.
* **ocelot**: Oblivious transfer and oblivious PRFs.
* **popsicle**: Private-set intersection.
* **scuttlebutt**: Core MPC-related primitives used by various **swanky** libraries.
* **simple-arith-circuit**: Simple flat arithmetic circuit representation.

# A Note on Security

**swanky** is currently considered **prototype** software. Do not deploy it in
production, or trust it with sensitive data.

# Generating Documentation

To generate documentation, please use `etc/rustdoc.py` in lieu of `cargo doc`.

# License

MIT License

# Contributors

- Brent Carmer <bcarmer@galois.com>
- Ben Hamlin <hamlinb@galois.com>
- Alex J. Malozemoff <amaloz@galois.com>
- Benoit Razet <benoit.razet@galois.com>
- Marc Rosen <marc@galois.com>

# Acknowledgments

This material is based upon work supported by the ARO and DARPA under Contract
No. W911NF-15-C-0227 and by DARPA and SSC Pacific under Contract No.
N66001-15-C-4070.

Any opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of
the ARO, SSC Pacific, and DARPA.

Copyright © 2019 Galois, Inc.
