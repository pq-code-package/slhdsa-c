/*
 * Copyright (c) The mldsa-native project authors
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*
 * Assertion helpers shared by the slhdsa-c test drivers.
 *
 * CHECK(cond) returns 1 from the enclosing function if cond is false,
 * after reporting the source location.
 */

#ifndef SLH_TEST_SRC_TEST_COMMON_H
#define SLH_TEST_SRC_TEST_COMMON_H

#include <stdio.h>

#define CHECK(x)                                              \
  do                                                          \
  {                                                           \
    int rc;                                                   \
    rc = (x);                                                 \
    if (!rc)                                                  \
    {                                                         \
      fprintf(stderr, "ERROR (%s,%d)\n", __FILE__, __LINE__); \
      return 1;                                               \
    }                                                         \
  } while (0)

#endif /* !SLH_TEST_SRC_TEST_COMMON_H */
