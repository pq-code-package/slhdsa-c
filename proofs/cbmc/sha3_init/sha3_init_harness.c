// Copyright (c) The slhdsa-c project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sha3_api.h>

void harness(void)
{
  sha3_var_t *c;
  size_t md_sz;
  sha3_init(c, md_sz);
}
