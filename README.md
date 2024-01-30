# Low-Bandwidth Mixed Arithmetic in VOLE-Based ZK from Low-Degree PRGs

This is the implementation of our paper

"Low-Bandwidth Mixed Arithmetic in VOLE-Based ZK from Low-Degree PRGs"
by *Amit Agarwal, Carsten Baum, Lennart Braun, and Peter Scholl*.
[Eurocrypt 2025](https://eurocrypt.iacr.org/2025/).
<!-- [ePrint](https://eprint.iacr.org/2025/TODO). -->

The implementation is based on commit
[ca5d6b7](https://github.com/GaloisInc/swanky/commit/ca5d6b755abce97fb14713de699eb4217bcb0341) of
the swanky framework (which was the HEAD of the `dev` branch on 2024-01-17).
The original README.md of swanky can be found [here](README-swanky.md).



Our implementation is part of the [`diet-mac-and-cheese`](diet-mac-and-cheese/) crate.
We give an overview of our additions and modifications in the [here](diet-mac-and-cheese/src/README.md).

## Build and Test

The implementation was developed and tested under Linux on an x86-64 CPU with AVX2 and Rust 1.81.

The software expects a Git repository to be present.
So if you download the software as .tar.gz/.zip archive instead of cloning the Git repository,
please initialize a Git repository and create a dummy commit:
```shell
git init
git commit -m dummy --allow-empty
```


To build and execute all tests of swanky run
(or first change into the [`diet-mac-and-cheese/`](diet-mac-and-cheese/) subdirectory to only run the
corresponding subset of tests):
```shell
cargo test
```

To build the benchmarking application, run:
```shell
cargo build --release --example=bench
```


## Benchmarking and Analyzing the Data

### The `bench` Program

The benchmarks are implemented
[here](diet-mac-and-cheese/examples/bench.rs)
and you can run the benchmark program as follows:
```shell
cargo run --release --example=bench -- <subcommand> <options>
# or using the relative path to the binary (if already built)
./target/debug/examples/bench <subcommand> <options>
```
In the following examples, we will just write `bench` for brevity.

Use
```shell
bench help
# or
bench help <subcommand>
```
to get detailed usage information.
The two subcommands relevant for our benchmarks are `conv` and `fpm` for the conversion and
fixed-point multiplication benchmarks, respectively.
In the following we describe the most important options.

#### Common Options
- `--party <...>` which party to run
    - `prover` or `verifier` runs only the respective party and communicated to the other party via
      `TCP/IP`
    - `both` runs both parties in separate threads, communicating through a UNIX socket
- `--repetitions` how often the whole benchmark should be repeated
- `--json` if the output should be given in JSON instead of being human readable
- `--protocol <...>` select the protocol to use to verify the conversions/fixed-point multiplications
    - `edabits`: The protocol from BBMRS21 (CCS'21) our base line
    - `cheddabits-v1-tspa`: Our protocol with TSPA predicate and version 1 seed setup
    - `cheddabits-v2-tspa`: with TSPA predicate and version 2 seed setup
    - `cheddabits-v1-xor4maj7`: with Xor4Maj7 predicate and version 1 seed setup
    - `cheddabits-v2-xor4maj7`: with Xor4Maj7 predicate and version 2 seed setup

    (NB: version 1 and 2 does not make a difference for fixed-point multiplication)

#### Network Options
To connect to the other party (if not running `both` parties in the same process), use the following
set of options:
- `--listen` to listen for incoming connections
- `--host <HOST>` to set which address to listen on/to connect to (default: `localhost`)
- `--port <PORT>` to set which port to listen on/to connect to (default: `1337`)
- `--connect-timeout-seconds <SECONDS>` to set how long to try connecting before aborting (default: `100`)


#### `conv` Options
- ` --num <NUM>` how many conversions to verify
- ` --bit-size <BITS>` the size of each conversion

#### `fpm` Options
- ` --num <NUM>` how many fixed-point multiplications to verify
- ` --integer-size <BITS>` the bit-size of the integer part of a fixed-point number
- ` --fraction-size <BITS>` the bit-size of the fractional part of a fixed-point number


#### Example Output

```shell
# run in first terminal
bench conv --party prover --listen --protocol cheddabits-v1-xor4maj7 --num 4096 --bit-size 16 --repetitions 3
# run in second terminal
bench conv --party verifier --protocol cheddabits-v1-xor4maj7 --num 4096 --bit-size 16 --repetitions 3 --json
```

<details>
<summary>Prover's output</summary>

```
Startup time: 172ns
results: BenchmarkResult {
    repetitions: 3,
    party: "Prover",
    network_options: NetworkOptions {
        listen: true,
        host: "localhost",
        port: 1337,
        connect_timeout_seconds: 100,
    },
    meta_data: BenchmarkMetaData {
        hostname: "machine",
        username: "user",
        timestamp: "2025-03-07T16:32:52+01:00",
        cmdline: [
            "../target/release/examples/bench",
            "conv",
            "--party",
            "prover",
            "--listen",
            "--protocol",
            "cheddabits-v1-xor4maj7",
            "--num",
            "4096",
            "--bit-size",
            "16",
            "--repetitions",
            "3",
        ],
        pid: 94881,
        git_version: "1a564cc527be1949e70c04f821e26b27dc91f76e-dirty",
    },
    protocol_stats: [
        Conversion(
            ConversionStats {
                protocol: CheddabitsV1Xor4Maj7,
                num: 4096,
                bit_size: 16,
                time_stats: [
                    TimeStats {
                        init_time: 578.553679ms,
                        voles_time: 309.777587ms,
                        commit_time: 1.965454ms,
                        check_time: 775.238158ms,
                    },
                    TimeStats {
                        init_time: 555.850705ms,
                        voles_time: 196.692759ms,
                        commit_time: 1.950376ms,
                        check_time: 775.358086ms,
                    },
                    TimeStats {
                        init_time: 506.32201ms,
                        voles_time: 199.292973ms,
                        commit_time: 1.929788ms,
                        check_time: 763.061634ms,
                    },
                ],
                comm_stats: CommStats {
                    init_kb_sent: 1044.5615234375,
                    init_kb_received: 181.0361328125,
                    voles_kb_sent: 515.8173828125,
                    voles_kb_received: 1008.2080078125,
                    voles_f2_stats: FComStats {
                        num_voles_used: 0,
                        num_vole_extensions_performed: 1,
                    },
                    voles_fp_stats: FComStats {
                        num_voles_used: 0,
                        num_vole_extensions_performed: 1,
                    },
                    commit_kb_sent: 32.0,
                    commit_kb_received: 0.0,
                    commit_f2_stats: FComStats {
                        num_voles_used: 65536,
                        num_vole_extensions_performed: 0,
                    },
                    commit_fp_stats: FComStats {
                        num_voles_used: 4096,
                        num_vole_extensions_performed: 0,
                    },
                    check_kb_sent: 16.8388671875,
                    check_kb_received: 5.2705078125,
                    check_f2_stats: FComStats {
                        num_voles_used: 1186,
                        num_vole_extensions_performed: 0,
                    },
                    check_fp_stats: FComStats {
                        num_voles_used: 1078,
                        num_vole_extensions_performed: 0,
                    },
                },
            },
        ),
    ],
}
```
</details>
<details>
<summary>Verifier's output in JSON</summary>

```json
{
  "repetitions": 3,
  "party": "Verifier",
  "network_options": {
    "listen": false,
    "host": "localhost",
    "port": 1337,
    "connect_timeout_seconds": 100
  },
  "meta_data": {
    "hostname": "machine",
    "username": "user",
    "timestamp": "2025-03-07T16:32:54+01:00",
    "cmdline": [
      "../target/release/examples/bench",
      "conv",
      "--party",
      "verifier",
      "--protocol",
      "cheddabits-v1-xor4maj7",
      "--num",
      "4096",
      "--bit-size",
      "16",
      "--repetitions",
      "3",
      "--json"
    ],
    "pid": 94884,
    "git_version": "1a564cc527be1949e70c04f821e26b27dc91f76e-dirty"
  },
  "protocol_stats": [
    {
      "Conversion": {
        "protocol": "CheddabitsV1Xor4Maj7",
        "num": 4096,
        "bit_size": 16,
        "time_stats": [
          {
            "init_time": {
              "secs": 0,
              "nanos": 578151899
            },
            "voles_time": {
              "secs": 0,
              "nanos": 302861015
            },
            "commit_time": {
              "secs": 0,
              "nanos": 41021430
            },
            "check_time": {
              "secs": 0,
              "nanos": 814705993
            }
          },
          {
            "init_time": {
              "secs": 0,
              "nanos": 555155599
            },
            "voles_time": {
              "secs": 0,
              "nanos": 195929395
            },
            "commit_time": {
              "secs": 0,
              "nanos": 41273196
            },
            "check_time": {
              "secs": 0,
              "nanos": 815317857
            }
          },
          {
            "init_time": {
              "secs": 0,
              "nanos": 505466672
            },
            "voles_time": {
              "secs": 0,
              "nanos": 198314748
            },
            "commit_time": {
              "secs": 0,
              "nanos": 40481408
            },
            "check_time": {
              "secs": 0,
              "nanos": 803548037
            }
          }
        ],
        "comm_stats": {
          "init_kb_sent": 181.0361328125,
          "init_kb_received": 1044.5615234375,
          "voles_kb_sent": 1008.2080078125,
          "voles_kb_received": 515.8173828125,
          "voles_f2_stats": {
            "num_voles_used": 0,
            "num_vole_extensions_performed": 1
          },
          "voles_fp_stats": {
            "num_voles_used": 0,
            "num_vole_extensions_performed": 1
          },
          "commit_kb_sent": 0.0,
          "commit_kb_received": 32.0,
          "commit_f2_stats": {
            "num_voles_used": 65536,
            "num_vole_extensions_performed": 0
          },
          "commit_fp_stats": {
            "num_voles_used": 4096,
            "num_vole_extensions_performed": 0
          },
          "check_kb_sent": 5.2705078125,
          "check_kb_received": 16.8388671875,
          "check_f2_stats": {
            "num_voles_used": 1186,
            "num_vole_extensions_performed": 0
          },
          "check_fp_stats": {
            "num_voles_used": 1078,
            "num_vole_extensions_performed": 0
          }
        }
      }
    }
  ]
}
```
</details>


### Running Benchmarks

All scripts mentioned in this section are located in the [`scripts/`](scripts/) directory.
To run benchmarks for a large set of parameters, we provide [`run_conv.sh`](scripts/run_conv.sh) and
[`run_fpm.sh`](scripts/run_fpm.sh).
In our case, we execute the benchmarks on the same physical server using the [`tc` (traffic
control)](https://man.archlinux.org/man/tc.8) utility to simulate different network settings.

The benchmark scripts use [`tc.sh`](scripts/tc.sh) to switch between the LAN/WAN settings.
Note that the parameters and the RTT and throughput measured with `ping` and `iperf3` can differ
slightly.
We used the latter to find the right tc parameters.
To use `tc` you need additional permissions, so make sure you are allowed to use `sudo`.
The scripts will ask you for your password.

To run the benchmarks, please make sure the `bench` binary is build (using `--release` mode as described above).
Then open two terminals, change into the [`scripts/`](scripts/) directory, and run:
```shell
./run_conv.sh prover    # in the first terminal
./run_conv.sh verifier  # in the second terminal
```
and similarly for `run_fpm.sh`.
The benchmark results will be printed to the screen and also saved in the
[`scripts/results/`](scripts/results/) subdirectory:
```
ls results/
conv__party=prover_protocol=cheddabits-v1-tspa__bit-size=16__num=1024__network=lan__time=2025-03-07T13:18:04,692669286+01:00.json
conv__party=prover_protocol=cheddabits-v1-tspa__bit-size=16__num=1024__network=wan__time=2025-03-07T15:40:01,233233066+01:00.json
conv__party=prover_protocol=cheddabits-v1-tspa__bit-size=16__num=256__network=lan__time=2025-03-07T13:17:42,070965340+01:00.json
...
```

### Analyzing Benchmark Results

Again we have two scripts `analyze_conv.py` and `anaylze_fpm.py` which use a somewhat recent version
of pandas (tested with v2.2.3) which aggregate the JSON files into pandas dataframes and print to
the terminal:
```shell
./analyze_conv.py results/
./analyze_fpm.py results/
```


## License

The swanky framework and our modifications are licensed under an MIT license.
