[//]: # (SPDX-License-Identifier: CC-BY-4.0)
#   slhdsa-c
[![License: Apache](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A portable C90 implementation of SLH-DSA ("Stateless Hash-Based Digital Signature Standard") as described in [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205).

* Supports all 12 parameter sets in FIPS 205, both "pure" and "internal" functions (without recompiling for various parameter sets), as well as prehash modes.
* Self-contained implementation without external dependencies. Can be easily included into applications.
* Passes NIST ACVP tests (all 1248 test cases currently in the default set.) Simple test wrapper included.
* ACVP tests for prehash modes with: SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA2-512/224, SHA2-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256

This code was derived from [SLotH](https://github.com/slh-dsa/sloth) driver code written by Markku-Juhani O. Saarinen between 2023 and 2025. This source code has been relicensed and donated to the slhdsa-c project.

| FIPS 205 Name      | Cat | PK |  SK |   Sig |
|--------------------|-----|----|-----|-------|
| SLH-DSA-SHA2-128s  |  1  | 32 |  64 |  7856 |
| SLH-DSA-SHAKE-128s |  1  | 32 |  64 |  7856 |
| SLH-DSA-SHA2-128f  |  1  | 32 |  64 | 17088 |
| SLH-DSA-SHAKE-128f |  1  | 32 |  64 | 17088 |
| SLH-DSA-SHA2-192s  |  3  | 48 |  96 | 16224 |
| SLH-DSA-SHAKE-192s |  3  | 48 |  96 | 16224 |
| SLH-DSA-SHA2-192f  |  3  | 48 |  96 | 35664 |
| SLH-DSA-SHAKE-192f |  3  | 48 |  96 | 35664 |
| SLH-DSA-SHA2-256s  |  5  | 64 | 128 | 29792 |
| SLH-DSA-SHAKE-256s |  5  | 64 | 128 | 29792 |
| SLH-DSA-SHA2-256f  |  5  | 64 | 128 | 49856 |
| SLH-DSA-SHAKE-256f |  5  | 64 | 128 | 49856 |

## Status

slhdsa-c is work in progress. **WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A
PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA.** Once we have the first stable version,
this notice will be removed.


##  Building and Running Known Answer Tests

The implementation in this directory includes the necessary hash functions and, hence, has no external library dependencies. On a Linux system, you can typically use `make` to build the test wrapper executable `xfips205`.

```console
$ make
gcc -Wall -Wextra -Werror=unused-result -Wpedantic -Werror -Wmissing-prototypes -Wshadow -Wpointer-arith -Wredundant-decls -Wno-long-long -Wno-unknown-pragmas -O3 -fomit-frame-pointer -std=c99 -pedantic -c sha2_256.c -o sha2_256.o
...
-O3 -fomit-frame-pointer -std=c99 -pedantic -o xfips205 sha2_256.o sha2_512.o sha3_api.o sha3_f1600.o slh_dsa.o slh_prehash.o slh_sha2.o slh_shake.o test/xfips205.o
```

###	Running the ACVP tests

[`test/acvp_client.py`](test/acvp_client.py) implement ACVP tests and can also be executed through `make test`.
The ACVP version can be specified by passing the `--version` argument to the [`test/acvp_client.py`](test/acvp_client.py). 
The static test vectors are automatically fetched from NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) repository on first execution.s

```console
$ make test
python3 test/acvp_client.py
Using ACVP test vectors version v1.1.0.40
Running 1248 tests with 16 parallel jobs
[PASS] keyGen SLH-DSA-SHA2-128s [1] slh_keygen_internal()
...
[PASS] sigVer SLH-DSA-SHAKE-256s [497] slh_verify_internal()

=== test summary ===
PASS: 1248
FAIL: 0
ALL GOOD!
```

##  Structure of the implementation

External applications should include `slh_dsa.h` and optionally `slh_prehash.h` if prehash modes are required, and link the files in the `slhdsa-c` directory (not `test`).

```
slhdsa-c
├── LICENSE             # "MIT or Apache 2.0" licenses
├── Makefile            # generic makefile
├── plat_local.h        # macros for rotations, endianness
├── README.md           # this file
├── sha2_256.c          # SHA2-256 core implementation
├── sha2_512.c          # SHA2-512 core implementation
├── sha2_api.h          # SHA2 hash API
├── sha3_api.c          # SHA3/SHAKE core implementation
├── sha3_api.h          # SHA2 hash API
├── sha3_f1600.c        # Keccak-f1600 permutation for SHA3
├── slh_adrs.h          # SLH-DSA address manipulation
├── slh_dsa.c           # implementation file for internal and pure functions
├── slh_dsa.h           # SLH-DSA API (include this externally)
├── slh_param.h         # SLH-DSA parameter set / instantiation structure
├── slh_prehash.c       # implementation of the pre-hash wrapper
├── slh_prehash.h       # HashSLH API (include this externally if you need it)
├── slh_sha2.c          # SLH-DSA instantiation for SHA2 hash family
├── slh_shake.c         # SLH-DSA instantiation for SHA3/SHAKE hash family
├── slh_var.h           # internal SLH-DSA context structure
└── test                # testing stuff (not for application)
    ├── Makefile        # makefile for local test tasks
    ├── acvp_client.py  # ACVP client
    └── xfips205.c      # command-line test harness
```

