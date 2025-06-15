/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === benchmarking code */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "my_dbg.h"

#include "../slh_dsa.h"
#include "../slh_prehash.h"
#include "../slh_var.h"

/* instrumentation */
extern uint64_t sha2_256_compress_count; /* sha2_256.c      */
extern uint64_t sha2_512_compress_count; /* sha2_512.c      */
extern uint64_t keccak_f1600_count;      /* sha3_f1600.c    */

/* FIPS 205 test targets */
static const slh_param_t *std_iut[] = {&slh_dsa_shake_128s,
                                       &slh_dsa_shake_128f,
                                       &slh_dsa_shake_192s,
                                       &slh_dsa_shake_192f,
                                       &slh_dsa_shake_256s,
                                       &slh_dsa_shake_256f,
                                       &slh_dsa_sha2_128s,
                                       &slh_dsa_sha2_128f,
                                       &slh_dsa_sha2_192s,
                                       &slh_dsa_sha2_192f,
                                       &slh_dsa_sha2_256s,
                                       &slh_dsa_sha2_256f,
                                       NULL};

uint64_t lcg_fill(void *buf, size_t buf_sz, uint64_t x)
{
  size_t i;

  for (i = 0; i < buf_sz; i++)
  {
    /*  arbitrary LCG parameters */
    /*  nuclear.llnl.gov/CNP/rng/rngman.pdf */
    x = 2862933555777941757 * x + 3037000493;
    ((uint8_t *)buf)[i] = x >> 56;
  }

  return x;
}

void hash_count_clear()
{
  sha2_256_compress_count = 0;
  sha2_512_compress_count = 0;
  keccak_f1600_count = 0;
}

uint64_t hash_count()
{
  uint64_t tot;
  tot = sha2_256_compress_count + sha2_512_compress_count + keccak_f1600_count;
  return tot;
}

int test_param(const slh_param_t *prm, uint64_t seed)
{
  uint8_t pk[128], sk[128], buf[128], msg[32];
  uint8_t sig[100000];
  size_t msg_sz = 0, pk_sz = 0, sk_sz = 0, sig_sz = 0;

  uint64_t keygen_h = 0, sign_h = 0, verify_h = 0, verify2_h = 0;

  memset(sk, 0x55, sizeof(sk));
  memset(pk, 0xaa, sizeof(pk));
  memset(sig, 0x33, sizeof(sig));

  seed = lcg_fill(buf, sizeof(buf), seed);
  seed = lcg_fill(msg, sizeof(msg), seed);

  msg_sz = 16;

  sig_sz = slh_sig_sz(prm);
  pk_sz = slh_pk_sz(prm);
  sk_sz = slh_sk_sz(prm);

  hash_count_clear();
  if (slh_keygen_internal(sk, pk, buf, buf + 32, buf + 64, prm))
  {
    printf("[FAIL] %s  slh_keygen_internal()\n", prm->alg_id);
    return 1;
  }
  keygen_h = hash_count();

  hash_count_clear();
  sig_sz = slh_sign_internal(sig, msg, msg_sz, sk, NULL, prm);
  if (sig_sz < slh_sig_sz(prm))
  {
    printf("[FAIL] %s  slh_sign_internal()\n", prm->alg_id);
    return 1;
  }
  sign_h = hash_count();

  hash_count_clear();
  if (!slh_verify_internal(msg, msg_sz, sig, sig_sz, pk, prm))
  {
    printf("[FAIL] %s  slh_verify_internal(valid) == 0\n", prm->alg_id);
    return 1;
  }
  verify_h = hash_count();

  /* sanity check -- make it fail */
  msg[0]++;

  hash_count_clear();
  if (slh_verify_internal(msg, msg_sz, sig, sig_sz, pk, prm))
  {
    printf("[FAIL] %s  slh_verify_internal(invalid) == 1\n", prm->alg_id);
    return 1;
  }
  verify2_h = hash_count();

  /* CSV format */
  printf("%s, %zu, %zu, %zu, %zu, %zu, %zu, %zu\n", prm->alg_id, pk_sz, sk_sz,
         sig_sz, keygen_h, sign_h, verify_h, verify2_h);
  fflush(stdout);

  return 0;
}

int std_smoke_test()
{
  int i;
  int pass = 0, fail = 0;

  for (i = 0; std_iut[i] != NULL; i++)
  {
    if (test_param(std_iut[i], i) == 0)
    {
      pass++;
    }
    else
    {
      fail++;
    }
  }

  /*
  printf("[%s] std_smoke_test():  PASS=%d  FAIL=%d\n",
         fail == 0 ? "PASS" : "FAIL", pass, fail);
  */
  
  return fail;
}

int new_smoke_test(const char *alg_id, const char *hash, uint32_t n, uint32_t h,
                   uint32_t d, uint32_t hp, uint32_t a, uint32_t k,
                   uint32_t lg_w, uint32_t m, uint64_t seed)
{
  int fail = 0;
  int hash_fam = 0;
  char name[256] = "<alg_id>";
  slh_param_t prm;

  memset(&prm, 0, sizeof(prm));
  snprintf(name, sizeof(name), "%s %s", alg_id, hash);

  /* some basic checks */

  if (n > SLH_MAX_N || k > SLH_MAX_K || hp > SLH_MAX_HP || a > SLH_MAX_A ||
      m > SLH_MAX_M)
  {
    printf("[FAIL] %s  invalid parameters\n", name);
    return 1;
  }

  if (strcmp(hash, "sha2") == 0 || strcmp(hash, "SHA2") == 0)
  {
    hash_fam = 2;
  }
  else if (strcmp(hash, "shake") == 0 || strcmp(hash, "SHAKE") == 0)
  {
    hash_fam = 3;
  }

  /*  copy hash implementation function pointers  */
  if (hash_fam == 2 && n == 16)
  {
    memcpy(&prm, &slh_dsa_sha2_128s, sizeof(slh_param_t));
  }
  else if (hash_fam == 2 && n == 24)
  {
    memcpy(&prm, &slh_dsa_sha2_192s, sizeof(slh_param_t));
  }
  else if (hash_fam == 2 && n == 32)
  {
    memcpy(&prm, &slh_dsa_sha2_256s, sizeof(slh_param_t));
  }
  else if (hash_fam == 3 && n == 16)
  {
    memcpy(&prm, &slh_dsa_shake_128s, sizeof(slh_param_t));
  }
  else if (hash_fam == 3 && n == 24)
  {
    memcpy(&prm, &slh_dsa_shake_192s, sizeof(slh_param_t));
  }
  else if (hash_fam == 3 && n == 32)
  {
    memcpy(&prm, &slh_dsa_shake_256s, sizeof(slh_param_t));
  }
  else
  {
    printf("[FAIL] %s  can't find instantation\n", name);
    return 1;
  }

  /*  fill over parameter data */
  prm.alg_id = name;
  prm.n = n;
  prm.h = h;
  prm.d = d;
  prm.hp = hp;
  prm.a = a;
  prm.k = k;
  prm.lg_w = lg_w;
  prm.m = m;

  /* smoke test */
  fail += test_param(&prm, seed);

  return fail;
}

const char usage[] = "USAGE: xcount par_id n h d h' a k lg_w m [SHA2/SHAKE] [seed]\n";

int main(int argc, char **argv)
{
  int fail = 0;
  int n, h, d, hp, a, k, lg_w, m;
  char *alg_id = "<id>";
  char *hash = "SHA2";
  uint64_t seed = 0;

  seed = (((uint64_t)time(NULL)) << 32) + ((uint64_t)getpid());

  if (argc <= 1)
  {
    fail += std_smoke_test();
    return fail;
  }
  if (argc < 10)
  {
    fprintf(stderr, "%s", usage);
    return 1;
  }

  alg_id = argv[1];
  n = atoi(argv[2]);
  h = atoi(argv[3]);
  d = atoi(argv[4]);
  hp = atoi(argv[5]);
  a = atoi(argv[6]);
  k = atoi(argv[7]);
  lg_w = atoi(argv[8]);
  m = atoi(argv[9]);

  if (argc >= 11)
  {
    hash = argv[10];
  }
  if (argc >= 12)
  {
    seed = (uint64_t)atoll(argv[11]);
  }

  if (n <= 0 || h <= 0 || d <= 0 || hp <= 0 || a <= 0 || k <= 0 || lg_w <= 0 ||
      m <= 0)
  {
    fprintf(stderr, "%s: invalid parameters.\n", argv[0]);
    return 1;
  }

  fail += new_smoke_test(alg_id, hash, n, h, d, hp, a, k, lg_w, m, seed);

  return fail;
}
