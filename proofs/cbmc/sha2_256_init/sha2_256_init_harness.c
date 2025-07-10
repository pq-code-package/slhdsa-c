// Copyright (c) The slhdsa-c project authors
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sha2_api.h>

void harness(void)
{
  sha2_256_t *sha;
  sha2_256_init(sha);
}
