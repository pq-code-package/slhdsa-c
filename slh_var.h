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
#define SLH_MAX_N 32
#define SLH_MAX_LEN (2 * SLH_MAX_N + 3)
#define SLH_MAX_K 35
#define SLH_MAX_M 49
#define SLH_MAX_HP 9
#define SLH_MAX_A 14

/* context */
struct slh_var_s
{
  const slh_param_t *prm;
  uint8_t sk_seed[SLH_MAX_N];
  uint8_t sk_prf[SLH_MAX_N];
  uint8_t pk_seed[SLH_MAX_N];
  uint8_t pk_root[SLH_MAX_N];

#ifdef SLOTH
  volatile adrs_t *adrs; /* hardware */
#else
  adrs_t *adrs; /* regular pointer */
#endif
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
