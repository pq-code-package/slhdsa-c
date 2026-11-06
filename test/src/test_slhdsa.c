/*
 * Copyright (c) The mldsa-native project authors
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* Functional tests for the SLH-DSA API: sign/verify round trips and the
 * rejection of modified inputs, for all parameter sets. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../../slh_dsa.h"
#include "../../slh_prehash.h"
#include "../../slh_sys.h"
#include "../notrandombytes/notrandombytes.h"

#include "test_common.h"

#ifndef NTESTS
#define NTESTS 1
#endif
#define MLEN 59
#define CTXLEN 1

/* Upper bounds over all parameter sets (SLH-DSA-*-256f) */
#define TEST_MAX_N 32
#define TEST_MAX_PK_BYTES (2 * TEST_MAX_N)
#define TEST_MAX_SK_BYTES (4 * TEST_MAX_N)
#define TEST_MAX_SIG_BYTES 49856

static const slh_param_t *const test_params[] = {
    &slh_dsa_sha2_128s,  &slh_dsa_shake_128s, &slh_dsa_sha2_128f,
    &slh_dsa_shake_128f, &slh_dsa_sha2_192s,  &slh_dsa_shake_192s,
    &slh_dsa_sha2_192f,  &slh_dsa_shake_192f, &slh_dsa_sha2_256s,
    &slh_dsa_shake_256s, &slh_dsa_sha2_256f,  &slh_dsa_shake_256f};
#define NUM_PARAMS (sizeof(test_params) / sizeof(test_params[0]))

/* Pre-hash functions; the i-th parameter set is tested with the i-th one,
 * so that every pre-hash function is used once per iteration. */
static const char *const test_prehash[] = {
    "SHA2-224",     "SHA2-256",     "SHA2-384",  "SHA2-512",
    "SHA2-512/224", "SHA2-512/256", "SHA3-224",  "SHA3-256",
    "SHA3-384",     "SHA3-512",     "SHAKE-128", "SHAKE-256"};
#define NUM_PREHASH (sizeof(test_prehash) / sizeof(test_prehash[0]))

/* RBG for slh_keygen(): SK.seed, SK.prf (and PK.seed) are secret. */
static int test_rbg(uint8_t *x, size_t xlen)
{
  int ret = randombytes(x, xlen);
  SLH_CT_TESTING_SECRET(x, xlen);
  return ret;
}

static int test_keypair(uint8_t *sk, uint8_t *pk, const slh_param_t *prm)
{
  size_t n = slh_pk_sz(prm) / 2;

  CHECK(slh_pk_sz(prm) <= TEST_MAX_PK_BYTES);
  CHECK(slh_sk_sz(prm) <= TEST_MAX_SK_BYTES);
  CHECK(slh_sig_sz(prm) <= TEST_MAX_SIG_BYTES);

  CHECK(slh_keygen(sk, pk, test_rbg, prm) == 0);

  /* PK.seed and PK.root are public */
  SLH_CT_TESTING_DECLASSIFY(pk, 2 * n);
  SLH_CT_TESTING_DECLASSIFY(sk + 2 * n, 2 * n);

  /* SK = SK.seed || SK.prf || PK.seed || PK.root */
  CHECK(memcmp(sk + 2 * n, pk, 2 * n) == 0);

  return 0;
}

static int test_sign_core(uint8_t *pk, uint8_t *sk, uint8_t *sig, uint8_t *m,
                          uint8_t *ctx, const slh_param_t *prm)
{
  uint8_t addrnd[TEST_MAX_N];
  size_t n = slh_pk_sz(prm) / 2;

  if (test_keypair(sk, pk, prm) != 0)
  {
    return 1;
  }
  CHECK(randombytes(ctx, CTXLEN) == 0);
  CHECK(randombytes(m, MLEN) == 0);
  CHECK(randombytes(addrnd, n) == 0);
  SLH_CT_TESTING_SECRET(addrnd, n);

  CHECK(slh_sign(sig, m, MLEN, ctx, CTXLEN, sk, addrnd, prm) ==
        slh_sig_sz(prm));
  SLH_CT_TESTING_DECLASSIFY(sig, slh_sig_sz(prm));

  if (slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx, CTXLEN, pk, prm) != 1)
  {
    printf("ERROR: verify\n");
    return 1;
  }

  return 0;
}

static int test_wrong_pk(const uint8_t *pk, const uint8_t *sig,
                         const uint8_t *m, const uint8_t *ctx,
                         const slh_param_t *prm)
{
  uint8_t pk_wrong[TEST_MAX_PK_BYTES];
  size_t idx;

  /* flip bit in public key */
  memcpy(pk_wrong, pk, slh_pk_sz(prm));
  CHECK(randombytes((uint8_t *)&idx, sizeof(size_t)) == 0);
  idx %= slh_pk_sz(prm);
  pk_wrong[idx] ^= 1;

  if (slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx, CTXLEN, pk_wrong, prm) !=
      0)
  {
    printf("ERROR: wrong_pk: verify\n");
    return 1;
  }
  return 0;
}

static int test_wrong_sig(const uint8_t *pk, const uint8_t *sig,
                          const uint8_t *m, const uint8_t *ctx,
                          const slh_param_t *prm)
{
  uint8_t sig_wrong[TEST_MAX_SIG_BYTES];
  size_t idx;

  /* flip bit in signature */
  memcpy(sig_wrong, sig, slh_sig_sz(prm));
  CHECK(randombytes((uint8_t *)&idx, sizeof(size_t)) == 0);
  idx %= slh_sig_sz(prm);
  sig_wrong[idx] ^= 1;

  if (slh_verify(m, MLEN, sig_wrong, slh_sig_sz(prm), ctx, CTXLEN, pk, prm) !=
      0)
  {
    printf("ERROR: wrong_sig: verify\n");
    return 1;
  }
  return 0;
}

static int test_wrong_msg(const uint8_t *pk, const uint8_t *sig,
                          const uint8_t *m, const uint8_t *ctx,
                          const slh_param_t *prm)
{
  uint8_t m_wrong[MLEN];
  size_t idx;

  /* flip bit in message */
  memcpy(m_wrong, m, MLEN);
  CHECK(randombytes((uint8_t *)&idx, sizeof(size_t)) == 0);
  idx %= MLEN;
  m_wrong[idx] ^= 1;

  if (slh_verify(m_wrong, MLEN, sig, slh_sig_sz(prm), ctx, CTXLEN, pk, prm) !=
      0)
  {
    printf("ERROR: wrong_msg: verify\n");
    return 1;
  }
  return 0;
}

static int test_wrong_ctx(const uint8_t *pk, const uint8_t *sig,
                          const uint8_t *m, const uint8_t *ctx,
                          const slh_param_t *prm)
{
  uint8_t ctx_wrong[CTXLEN];
  size_t idx;

  /* flip bit in ctx */
  memcpy(ctx_wrong, ctx, CTXLEN);
  CHECK(randombytes((uint8_t *)&idx, sizeof(size_t)) == 0);
  idx %= CTXLEN;
  ctx_wrong[idx] ^= 1;

  if (slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx_wrong, CTXLEN, pk, prm) !=
      0)
  {
    printf("ERROR: wrong_ctx: verify\n");
    return 1;
  }

  /* an empty context is not the same as a context of length 1 */
  if (slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx, 0, pk, prm) != 0)
  {
    printf("ERROR: wrong_ctx: verify (empty ctx)\n");
    return 1;
  }
  return 0;
}

static int test_wrong_sig_len(const uint8_t *pk, const uint8_t *sig,
                              const uint8_t *m, const uint8_t *ctx,
                              const slh_param_t *prm)
{
  /* Verification must reject these on the length alone */
  if (slh_verify(m, MLEN, sig, slh_sig_sz(prm) - 1, ctx, CTXLEN, pk, prm) !=
          0 ||
      slh_verify(m, MLEN, sig, slh_sig_sz(prm) + 1, ctx, CTXLEN, pk, prm) !=
          0 ||
      slh_verify(m, MLEN, sig, 0, ctx, CTXLEN, pk, prm) != 0)
  {
    printf("ERROR: wrong_sig_len: verify\n");
    return 1;
  }
  return 0;
}

/* A context string has at most 255 bytes */
static int test_ctx_too_long(const uint8_t *pk, const uint8_t *sk,
                             const uint8_t *sig, const uint8_t *m,
                             const slh_param_t *prm)
{
  uint8_t ctx_long[256];
  uint8_t sig_out[TEST_MAX_SIG_BYTES];

  memset(ctx_long, 0, sizeof(ctx_long));

  CHECK(slh_sign(sig_out, m, MLEN, ctx_long, 256, sk, NULL, prm) == 0);
  CHECK(slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx_long, 256, pk, prm) == 0);
  CHECK(hash_slh_sign(sig_out, m, MLEN, ctx_long, 256, "SHA2-256", sk, NULL,
                      prm) == 0);
  CHECK(hash_slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx_long, 256,
                        "SHA2-256", pk, prm) == 0);
  return 0;
}

static int test_sign(const slh_param_t *prm)
{
  uint8_t pk[TEST_MAX_PK_BYTES];
  uint8_t sk[TEST_MAX_SK_BYTES];
  uint8_t sig[TEST_MAX_SIG_BYTES];
  uint8_t m[MLEN];
  uint8_t ctx[CTXLEN];

  memset(sig, 0, sizeof(sig));
  if (test_sign_core(pk, sk, sig, m, ctx, prm) != 0)
  {
    return 1;
  }

  /* Negative tests on the signature just produced; signing is expensive. */
  return test_wrong_pk(pk, sig, m, ctx, prm) |
         test_wrong_sig(pk, sig, m, ctx, prm) |
         test_wrong_msg(pk, sig, m, ctx, prm) |
         test_wrong_ctx(pk, sig, m, ctx, prm) |
         test_wrong_sig_len(pk, sig, m, ctx, prm) |
         test_ctx_too_long(pk, sk, sig, m, prm);
}

static int test_sign_unaligned(const slh_param_t *prm)
{
  /* union with a uint64_t to make sure the arrays are aligned */
  union
  {
    uint64_t align;
    uint8_t pk[TEST_MAX_PK_BYTES + 1];
  } pk;
  union
  {
    uint64_t align;
    uint8_t sk[TEST_MAX_SK_BYTES + 1];
  } sk;
  union
  {
    uint64_t align;
    uint8_t sig[TEST_MAX_SIG_BYTES + 1];
  } sig;
  union
  {
    uint64_t align;
    uint8_t m[MLEN + 1];
  } m;
  union
  {
    uint64_t align;
    uint8_t ctx[CTXLEN + 1];
  } ctx;

  return test_sign_core(pk.pk + 1, sk.sk + 1, sig.sig + 1, m.m + 1, ctx.ctx + 1,
                        prm);
}

static int test_sign_pre_hash(const slh_param_t *prm, const char *ph,
                              const char *ph_other)
{
  uint8_t pk[TEST_MAX_PK_BYTES];
  uint8_t sk[TEST_MAX_SK_BYTES];
  uint8_t sig[TEST_MAX_SIG_BYTES];
  uint8_t m[MLEN];
  uint8_t ctx[CTXLEN];
  uint8_t addrnd[TEST_MAX_N];
  size_t n = slh_pk_sz(prm) / 2;

  if (test_keypair(sk, pk, prm) != 0)
  {
    return 1;
  }
  CHECK(randombytes(ctx, CTXLEN) == 0);
  CHECK(randombytes(m, MLEN) == 0);
  CHECK(randombytes(addrnd, n) == 0);
  SLH_CT_TESTING_SECRET(addrnd, n);

  CHECK(hash_slh_sign(sig, m, MLEN, ctx, CTXLEN, ph, sk, addrnd, prm) ==
        slh_sig_sz(prm));
  SLH_CT_TESTING_DECLASSIFY(sig, slh_sig_sz(prm));

  if (hash_slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx, CTXLEN, ph, pk,
                      prm) != 1)
  {
    printf("ERROR: pre_hash (%s): verify\n", ph);
    return 1;
  }

  /* Domain separation: neither pure nor another pre-hash function verify */
  CHECK(slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx, CTXLEN, pk, prm) == 0);
  CHECK(hash_slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx, CTXLEN, ph_other,
                        pk, prm) == 0);

  /* Unknown pre-hash functions must be rejected */
  CHECK(hash_slh_sign(sig, m, MLEN, ctx, CTXLEN, "SHA2-1", sk, addrnd, prm) ==
        0);
  CHECK(hash_slh_verify(m, MLEN, sig, slh_sig_sz(prm), ctx, CTXLEN, "SHA2-1",
                        pk, prm) == 0);

  return 0;
}

/* Empty message and context with NULL pointers, deterministic signing:
 * m and ctx may be NULL when their length is 0, and addrnd may be NULL. */
static int test_sign_empty_message(const slh_param_t *prm, const char *ph)
{
  uint8_t pk[TEST_MAX_PK_BYTES];
  uint8_t sk[TEST_MAX_SK_BYTES];
  uint8_t sig[TEST_MAX_SIG_BYTES];

  if (test_keypair(sk, pk, prm) != 0)
  {
    return 1;
  }

  CHECK(slh_sign(sig, NULL, 0, NULL, 0, sk, NULL, prm) == slh_sig_sz(prm));
  SLH_CT_TESTING_DECLASSIFY(sig, slh_sig_sz(prm));

  if (slh_verify(NULL, 0, sig, slh_sig_sz(prm), NULL, 0, pk, prm) != 1)
  {
    printf("ERROR: empty_message: verify\n");
    return 1;
  }

  /* Pre-hash of the empty message; a pure signature must not verify */
  CHECK(hash_slh_verify(NULL, 0, sig, slh_sig_sz(prm), NULL, 0, ph, pk, prm) ==
        0);

  return 0;
}

static int test_param_set(size_t j)
{
  const slh_param_t *prm = test_params[j];
  const char *ph = test_prehash[j % NUM_PREHASH];
  const char *ph_other = test_prehash[(j + 1) % NUM_PREHASH];
  unsigned i;
  int r;

  /* WARNING: Test-only
   * Normally, you would want to seed a PRNG with trustworthy entropy here.
   * Reset for every parameter set, so that each one sees the same inputs
   * whether it is tested on its own or together with the others. */
  randombytes_reset();

  for (i = 0; i < NTESTS; i++)
  {
    r = 0;
    r |= test_sign(prm);
    r |= test_sign_unaligned(prm);
    r |= test_sign_pre_hash(prm, ph, ph_other);
    r |= test_sign_empty_message(prm, ph);

    if (r)
    {
      printf("FAIL: %s\n", slh_alg_id(prm));
      return 1;
    }
  }

  printf("OK: %s\n", slh_alg_id(prm));
  fflush(stdout);
  return 0;
}

/* Usage: test_slhdsa            test all parameter sets
 *        test_slhdsa <alg_id>   test one, e.g. SLH-DSA-SHA2-128s
 *        test_slhdsa --list     print the alg_id of all parameter sets
 * Testing one parameter set at a time allows running them in parallel. */
/* Prototype for a re-#define'd main, to satisfy -Wmissing-prototypes. */
#if defined(main)
int main(int argc, char **argv);
#endif
int main(int argc, char **argv)
{
  size_t j;

  if (argc == 1)
  {
    for (j = 0; j < NUM_PARAMS; j++)
    {
      if (test_param_set(j) != 0)
      {
        return 1;
      }
    }
    return 0;
  }

  if (argc == 2 && strcmp(argv[1], "--list") == 0)
  {
    for (j = 0; j < NUM_PARAMS; j++)
    {
      printf("%s\n", slh_alg_id(test_params[j]));
    }
    return 0;
  }

  if (argc == 2)
  {
    for (j = 0; j < NUM_PARAMS; j++)
    {
      if (strcmp(argv[1], slh_alg_id(test_params[j])) == 0)
      {
        return test_param_set(j);
      }
    }
  }

  fprintf(stderr, "usage: %s [--list | <alg_id>]\n", argv[0]);
  return 1;
}
