/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === Internal parameter definition structure. */

#ifndef _SLH_VAR_H_
#define _SLH_VAR_H_

#include "sha2_api.h"
#include "slh_param.h"

/* some structural sizes */

/* maximum parameter sizes over FIPS 205 and the SP 800-230 initial public
   draft; the draft sets hp, a and len, which FIPS 205 alone would leave at
   9, 14 and 2n + 3 */
#define SLH_MAX_N 32
#define SLH_MAX_LEN (4 * SLH_MAX_N + 5)
#define SLH_MAX_K 35
#define SLH_MAX_HP 22
#define SLH_MAX_A 25
#define SLH_MAX_M 49

/* context */
struct slh_var_s
{
  const slh_param_t *prm;
  uint8_t sk_seed[SLH_MAX_N];
  uint8_t sk_prf[SLH_MAX_N];
  uint8_t pk_seed[SLH_MAX_N];
  uint8_t pk_root[SLH_MAX_N];

  adrs_t *adrs;  /* regular pointer */
  adrs_t t_adrs; /* local ADRS buffer */

  /* precomputed values */
  sha2_256_t sha2_256_pk_seed;
  sha2_512_t sha2_512_pk_seed;
};

/* === Lower-level functions */

/* Core signing function (of a randomized digest) with initialized context. */
size_t slh_do_sign(slh_var_t *var, uint8_t *sig, const uint8_t *digest);

/* _SLH_VAR_H_ */
#endif
