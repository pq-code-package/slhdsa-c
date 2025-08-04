// Copyright (c) The slhdsa-c project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "slh_var.h"

size_t wots_sign(slh_var_t *var, uint8_t *sig, const uint8_t *m);

void harness(void)
{
  slh_var_t *var;
  uint8_t *sig;
  uint8_t *m;
  wots_sign(var, sig, m);
}
