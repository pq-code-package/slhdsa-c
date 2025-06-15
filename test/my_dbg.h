/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === private tests and benchmarks */

#ifndef _MY_DBG_H_
#define _MY_DBG_H_
#include <stddef.h>
#include <stdint.h>

/* print checksum */
void dbg_chk(const char *label, const void *data, size_t data_sz);

/* print structured hex */
void dbg_dump(const char *label, const void *data, size_t data_sz);

/* print nist kat style hex */
void dbg_kat(const char *label, const void *data, size_t data_sz);

/* print nist kat style hex */
void dbg_hex(const char *label, const void *data, size_t data_sz);

#endif
