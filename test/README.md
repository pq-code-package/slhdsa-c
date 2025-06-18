[//]: # (SPDX-License-Identifier: CC-BY-4.0)
#   slhdsa experimental parameter set smoke test

In addition to ACVP static test vector generation for slh-dsa-c, this directory also contains a basic "smoke test" for 264 "new" parameters in Tables 2--28 of [S. Fluhrer, Q. Dang, "Smaller Sphincs+", IACR ePrint 2024/018](https://eprint.iacr.org/2024/018).

##  new_param.csv

The main file `xcount.c` populates the appropriate data structures of
`slh_param_t` from values given in the command line and performs a basic smoke test: keypair generation, signature generation, signature
verification with a valid signature, and signature verification with a bad
message. It reports a comma-separated line:
```
alg_id, pk, sk, sig, keygen, sign, vfy_ok, vfy_fail
```

Where:
*   `alg_id`: Parameter set name. `A-1 (2**20)` indicates the label given in the above paper for the parameter set, and also that 2<sup>20</sup> = 1048576 signatures can be "fully" safely generated with it.
*   `pk`: Verification key size (32-64 bytes). This is 2n, where n is the security parameter.
*   `sk`: Signing key size (64-128 bytes). This is 4n, where n is the security parameter.
*   `sig`: Signature size (3072-49856 bytes) for the parameter set.
*   `keygen`: Key pair generation "time"
*   `sign`: Signature generation "time"
*   `vfy_ok`: Signature verification "time" (valid message)
*   `vfy_fail`: Signature verification "time" (wrong message)

These are collected to [`new_param.csv`](new_param.csv). This can be regenerated from the input file `new_param.txt` (extracted from the paper) by the scripts by running `make new_param.csv`. The process requires gnu parallel and can take 15 minutes on a typical PC.

### Notes

We report the actual number of hash calls rather than a calculated value, as in the above paper. Hence, there is variation between different runs. There is no great discrepancy -- this is just a practical validation of the methodology in the above paper.

The "time" field indicates the number of the core compression function (SHA2-256/512) or permutation (Keccak-f1600 in SHA3/SHAKE) invocations. There is a difference between SHAKE and SHA2, as SHA2 often requires more compression function calls for each hash.

In the case of SLH-DSA, there is no "early abort" in signature verification; hence, the values of `vfy_ok` and `vfy_fail` differ only due to the randomization of the process (mainly due to variations in Winternitz chain lengths).

