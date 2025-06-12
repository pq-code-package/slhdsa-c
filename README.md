[//]: # (SPDX-License-Identifier: CC-BY-4.0)
#   slhdsa-c

A portable C implementation of SLH-DSA ("Stateless Hash-Based Digital Signature Standard") as described in [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205).

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

##  Building and Running Known Answer Tests

The implementation in this directory includes the necessary hash functions and, hence, has no external library dependencies. On a Linux system, you can typically use `make` to build the test wrapper executable `xfips205`.

```console
$ make
gcc -Wall -Wextra -Werror=unused-result -Wpedantic -Werror -Wmissing-prototypes -Wshadow -Wpointer-arith -Wredundant-decls -Wno-long-long -Wno-unknown-pragmas -O3 -fomit-frame-pointer -std=c99 -pedantic -c sha2_256.c -o sha2_256.o
...
-O3 -fomit-frame-pointer -std=c99 -pedantic -o xfips205 sha2_256.o sha2_512.o sha3_api.o sha3_f1600.o slh_dsa.o slh_prehash.o slh_sha2.o slh_shake.o test/xfips205.o
```

###	Running the ACVP tests

The static test cases need to be initially fetched from NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) repository, which is instantiated as submodule `test/ACVP-Server`. The Makefile should be able to do this automatically in case the submodule has not been initialized, but this may take some time.

As a prerequisite you will require python3 and [gnu parallel](https://www.gnu.org/software/parallel) (a standard Linux package in most cases), which makes the full test run in less than 1 minute.

During the process, the script [`test/test_slhdsa.py`](test/test_slhdsa.py) will translate the test cases into a shell file `test/acvp_cases.sh`, which then contains test case feed for `xfips205`.

```console
$ make test
...
cat test/acvp_cases.sh | parallel --pipe bash | tee test.log
[PASS] sigGen SLH-DSA-SHA2-192f [22] slh_sign()
...
[PASS] sigGen SLH-DSA-SHAKE-192s [553] hash_slh_sign(SHAKE-128)
=== test summary ===
PASS: 1248
SKIP: 0
FAIL: 0
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
    ├── acvp_cases.sh   # precompiled ACVP test cases
    ├── ACVP-Server     # optional submodule (contains original test cases)
    ├── Makefile        # makefile for local test tasks
    ├── test_slhdsa.py  # parses JSON files into acvp_cases.sh
    └── xfips205.c      # command-line test harness
```

